"""
SSH Decoy Server (Member 3)

How an attack is captured:
  1. TCP connection -> a session is opened in the shared SessionManager
     (refused quietly if the 100-session limit or the per-IP rate limit is hit)
  2. Every username/password tried is stored (password as a bcrypt hash)
  3. Weak passwords from SSH_ACCEPTED_CREDENTIALS "work", so the attacker
     reaches the fake shell; everything else is rejected like real sshd
  4. Every command - typed in the shell or sent as "ssh host 'cmd'" - is
     classified (MITRE ATT&CK) and stored with the fake output shown
  5. The session closes on exit/logout, disconnect, idle timeout or max duration

Nothing the attacker sends is ever executed (see shell.py).
"""
import logging
import os
import random
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import bcrypt
import paramiko

from app.core.config import Config
from app.core.session import RateLimited, SessionLimitReached, get_session_manager
from app.decoy_ssh.banners import DEFAULT_BANNER, FAKE_HOSTNAMES, FAKE_USERNAME, get_fake_motd
from app.decoy_ssh.shell import ShellSimulator
from app.enrichment.ip_lookup import enrich_and_store
from app.storage.database import get_database

log = logging.getLogger('honeypot.ssh')

BCRYPT_ROUNDS = 10
MAX_LINE_LENGTH = 1024          # longest command we buffer
AUTH_TIMEOUT_SECONDS = 30       # time allowed to log in and open a channel
MAX_AUTH_ATTEMPTS = 10          # then the connection is dropped (like MaxAuthTries)
RECV_POLL_SECONDS = 1.0         # how often the shell loop checks for timeouts

_host_key_lock = threading.Lock()
_host_key: Optional[paramiko.RSAKey] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_host_key(path: str = None) -> paramiko.RSAKey:
    """Load the server key, creating it once (at start-up, not during an attack)."""
    global _host_key
    with _host_key_lock:
        if _host_key is not None:
            return _host_key
        key_path = Path(path or Config.SSH_HOST_KEY_PATH)
        if key_path.exists():
            _host_key = paramiko.RSAKey.from_private_key_file(str(key_path))
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            log.info('Generating SSH host key at %s (first run only)', key_path)
            _host_key = paramiko.RSAKey.generate(2048)
            _host_key.write_private_key_file(str(key_path))
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        return _host_key


class SSHServer(paramiko.ServerInterface):
    """Decides what the attacker is allowed to do. Logs every login attempt."""

    def __init__(self, session_id: str, db, accepted_credentials=None):
        self.session_id = session_id
        self.db = db
        self.accepted = accepted_credentials if accepted_credentials is not None else Config.SSH_ACCEPTED_CREDENTIALS
        self.event = threading.Event()      # set when a shell or exec request arrives
        self.auth_attempts = 0
        self.username: Optional[str] = None
        self.exec_command: Optional[str] = None

    # -- authentication ----------------------------------------------------
    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_auth_password(self, username: str, password: str) -> int:
        self.auth_attempts += 1
        accepted = (username, password) in self.accepted
        try:
            self.db.log_auth_attempt({
                'session_id': self.session_id,
                'timestamp': _now(),
                'username': (username or '')[:256],
                'password_hash': bcrypt.hashpw((password or '').encode('utf-8', 'replace'),
                                               bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode('utf-8'),
                'auth_method': 'password',
                'success': accepted,
            })
        except Exception as exc:
            log.warning('could not log auth attempt: %s', exc)
        if accepted:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Key logins always fail, but we record that one was tried."""
        self.auth_attempts += 1
        try:
            self.db.log_auth_attempt({
                'session_id': self.session_id, 'timestamp': _now(), 'username': (username or '')[:256],
                'password_hash': None, 'auth_method': f'publickey:{key.get_name()}', 'success': False,
            })
        except Exception as exc:
            log.warning('could not log key attempt: %s', exc)
        return paramiko.AUTH_FAILED

    # -- channels ----------------------------------------------------------
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED   # no port forwarding

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

    def check_channel_env_request(self, channel, name, value):
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        """'ssh user@host "uname -a"' - very common with bots."""
        self.exec_command = command.decode('utf-8', 'replace') if isinstance(command, bytes) else str(command)
        self.event.set()
        return True


def _crlf(text: str) -> str:
    return text.replace('\r\n', '\n').replace('\n', '\r\n')


class _ShellSession:
    """Runs the fake shell for one connected channel."""

    def __init__(self, channel, session, db, manager, shell: ShellSimulator):
        self.channel = channel
        self.session = session
        self.db = db
        self.manager = manager
        self.shell = shell

    def expired(self) -> Optional[str]:
        current = self.manager.get_session(self.session.session_id)
        if current is None:
            return 'closed'
        self.manager.find_expired()          # marks this session if its time is up
        return current.close_reason

    def run_command(self, command: str, interaction_type: str = 'ssh_command') -> str:
        self.session.touch()
        output, classification, mitre = self.shell.process_command(command)
        try:
            self.db.log_interaction({
                'session_id': self.session.session_id,
                'timestamp': _now(),
                'interaction_type': interaction_type,
                'command': command[:MAX_LINE_LENGTH],
                'command_classification': classification,
                'fake_output': output,
            })
        except Exception as exc:
            log.warning('could not log command: %s', exc)
        log.info('[%s] %s $ %s  -> %s %s', self.session.source_ip, self.shell.hostname, command,
                 classification, mitre)
        return output

    def run_exec(self, command: str):
        output = self.run_command(command)
        if output:
            self.channel.sendall(_crlf(output) + '\r\n')
        self.channel.send_exit_status(0)

    def run_interactive(self):
        self.channel.sendall(_crlf(get_fake_motd(self.shell.hostname)) + '\r\n')
        self.channel.sendall(self.shell.get_prompt())
        self.channel.settimeout(RECV_POLL_SECONDS)

        buffer = ''
        escape = ''                     # collecting an ANSI escape sequence (arrow keys etc.)
        while True:
            reason = self.expired()
            if reason:
                note = 'timed out waiting for input: auto-logout' if reason == 'idle_timeout' else 'Connection closed.'
                self.channel.sendall(f'\r\n{note}\r\n')
                return
            try:
                data = self.channel.recv(1024)
            except socket.timeout:
                continue
            if not data:
                return
            for char in data.decode('utf-8', errors='ignore'):
                if escape:
                    escape += char
                    if char.isalpha() or char == '~' or len(escape) > 8:
                        escape = ''
                    continue
                if char == '\x1b':
                    escape = char
                elif char in ('\r', '\n'):
                    self.channel.sendall('\r\n')
                    command = buffer.strip()
                    buffer = ''
                    if command:
                        if command in ('exit', 'logout', 'quit'):
                            self.run_command(command)
                            self.channel.sendall('logout\r\n')
                            return
                        output = self.run_command(command)
                        if output:
                            self.channel.sendall(_crlf(output) + '\r\n')
                    self.channel.sendall(self.shell.get_prompt())
                elif char in ('\x7f', '\x08'):          # backspace
                    if buffer:
                        buffer = buffer[:-1]
                        self.channel.sendall('\b \b')
                elif char == '\x03':                     # Ctrl+C
                    buffer = ''
                    self.channel.sendall('^C\r\n' + self.shell.get_prompt())
                elif char == '\x04':                     # Ctrl+D
                    if not buffer:
                        self.channel.sendall('logout\r\n')
                        return
                elif char == '\x15':                     # Ctrl+U clears the line
                    self.channel.sendall('\b \b' * len(buffer))
                    buffer = ''
                elif char == '\x0c':                     # Ctrl+L
                    self.channel.sendall('\x1b[H\x1b[2J' + self.shell.get_prompt() + buffer)
                elif char == '\t' or ord(char) < 32:
                    continue                             # no tab completion
                elif len(buffer) < MAX_LINE_LENGTH:
                    buffer += char
                    self.channel.sendall(char)


def handle_ssh_client(client_socket: socket.socket, addr: tuple, db=None, session_manager=None,
                      host_key=None):
    """Handle one SSH connection from start to finish."""
    db = db or get_database()
    manager = session_manager or get_session_manager()
    client_ip, client_port = addr[0], addr[1]

    try:
        session = manager.create_session(source_ip=client_ip, source_port=client_port,
                                         dest_port=Config.SSH_PORT, protocol='ssh')
    except (SessionLimitReached, RateLimited) as exc:
        log.info('dropping SSH connection from %s: %s', client_ip, exc)
        client_socket.close()
        return

    transport = None
    channel = None
    try:
        db.create_session(session.to_dict())
        enrich_and_store(db, client_ip)

        transport = paramiko.Transport(client_socket)
        transport.local_version = DEFAULT_BANNER
        transport.add_server_key(host_key or load_host_key())
        server = SSHServer(session.session_id, db)
        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            log.info('SSH handshake with %s failed: %s', client_ip, exc)
            return

        # Record the attacker's SSH client (e.g. "SSH-2.0-libssh2_1.9.0")
        session.ssh_client_version = transport.remote_version
        db.update_session_client(session.session_id, ssh_client_version=transport.remote_version)

        # Wait for a successful login + channel, or give up after AUTH_TIMEOUT_SECONDS
        waited = 0.0
        while channel is None and transport.is_active() and waited < AUTH_TIMEOUT_SECONDS:
            channel = transport.accept(timeout=1)
            waited += 1
            if server.auth_attempts >= MAX_AUTH_ATTEMPTS and not server.username:
                log.info('%s: too many failed logins, disconnecting', client_ip)
                return
            if manager.get_session(session.session_id) is None:
                return
        if channel is None:
            log.info('%s never got a shell (%d login attempts)', client_ip, server.auth_attempts)
            return

        if not server.event.wait(10):
            return
        session.touch()

        hostname = random.choice(FAKE_HOSTNAMES)
        shell = ShellSimulator(hostname=hostname, username=server.username or FAKE_USERNAME,
                               max_output=Config.MAX_OUTPUT_BYTES)
        runner = _ShellSession(channel, session, db, manager, shell)
        if server.exec_command is not None:
            runner.run_exec(server.exec_command)
        else:
            runner.run_interactive()
            channel.send_exit_status(0)

    except Exception as exc:
        log.warning('error handling SSH client %s: %s', client_ip, exc)
    finally:
        for closer in (channel, transport):
            try:
                if closer is not None:
                    closer.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass
        ended = manager.end_session(session.session_id)
        try:
            db.end_session(session.session_id, _now(), (ended or session).duration_seconds())
        except Exception as exc:
            log.warning('could not close session %s: %s', session.session_id, exc)


def run_ssh_decoy(stop_event: Optional[threading.Event] = None):
    """Listen for SSH connections until stop_event is set (or forever)."""
    stop_event = stop_event or threading.Event()
    host_key = load_host_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == 'win32':
        # On Windows SO_REUSEADDR lets a second process bind the same port, so
        # two decoys would silently split incoming connections. Exclusive mode
        # makes the second bind fail with a clear "port in use" error.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((Config.SSH_HOST, Config.SSH_PORT))
    except OSError as exc:
        server_socket.close()
        raise OSError(f'SSH decoy cannot use port {Config.SSH_PORT}: {exc}') from exc

    server_socket.listen(100)
    server_socket.settimeout(1.0)
    log.info('SSH decoy listening on %s:%s (banner %s, %d weak passwords accepted)', Config.SSH_HOST,
             Config.SSH_PORT, DEFAULT_BANNER, len(Config.SSH_ACCEPTED_CREDENTIALS))
    try:
        while not stop_event.is_set():
            try:
                client_socket, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if stop_event.is_set():
                    break
                log.warning('error accepting SSH connection: %s', exc)
                continue
            log.info('SSH connection from %s:%s', addr[0], addr[1])
            threading.Thread(target=handle_ssh_client, args=(client_socket, addr),
                             kwargs={'host_key': host_key}, daemon=True, name=f'ssh-{addr[0]}').start()
    finally:
        server_socket.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    run_ssh_decoy()
