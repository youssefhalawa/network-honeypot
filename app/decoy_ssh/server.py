"""
SSH Decoy Server using Paramiko
Simulates an SSH service to capture credentials and commands
"""
import socket
import threading
import paramiko
import bcrypt
from datetime import datetime, timezone
from pathlib import Path
import random

from app.core.config import Config
from app.core.session import SessionManager
from app.storage.database import Database
from app.decoy_ssh.banners import DEFAULT_BANNER, get_fake_motd, get_fake_prompt, FAKE_HOSTNAMES, FAKE_USERNAME
from app.decoy_ssh.shell import ShellSimulator


class SSHServer(paramiko.ServerInterface):
    """
    Paramiko server interface implementation
    Handles SSH authentication and channel requests
    """

    def __init__(self, session_id: str, db: Database):
        self.event = threading.Event()
        self.session_id = session_id
        self.db = db
        self.auth_attempts = 0

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Handle password authentication attempts
        Always fails but logs credentials
        """
        self.auth_attempts += 1

        # Hash password with bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Log authentication attempt
        auth_data = {
            'session_id': self.session_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'username': username,
            'password_hash': password_hash,
            'auth_method': 'password'
        }
        self.db.log_auth_attempt(auth_data)

        # Always reject authentication
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Allow session channel requests"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Allow PTY requests"""
        return True

    def check_channel_shell_request(self, channel) -> bool:
        """Allow shell requests"""
        self.event.set()
        return True


def handle_ssh_client(client_socket: socket.socket, addr: tuple, db: Database, session_manager: SessionManager):
    """
    Handle individual SSH client connection

    Args:
        client_socket: Connected socket
        addr: Client address tuple (ip, port)
        db: Database instance
        session_manager: Session manager instance
    """
    client_ip, client_port = addr

    # Create session
    session = session_manager.create_session(
        source_ip=client_ip,
        source_port=client_port,
        dest_port=Config.SSH_PORT,
        protocol='ssh'
    )

    try:
        # Setup Paramiko transport
        transport = paramiko.Transport(client_socket)

        # Generate or load host key
        host_key_path = Path('data/ssh_host_rsa_key')
        if host_key_path.exists():
            host_key = paramiko.RSAKey.from_private_key_file(str(host_key_path))
        else:
            # Generate new key if not exists
            host_key_path.parent.mkdir(parents=True, exist_ok=True)
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(str(host_key_path))

        transport.add_server_key(host_key)

        # Set banner
        transport.local_version = DEFAULT_BANNER

        # Create server interface
        server = SSHServer(session.session_id, db)

        # Store session in database
        db.create_session(session.to_dict())

        # Start SSH server
        transport.start_server(server=server)

        # Wait for authentication (will always fail)
        channel = transport.accept(timeout=30)

        if channel is None:
            print(f"[SSH] No channel from {client_ip}")
            transport.close()
            return

        # Even though auth failed, simulate shell for logging
        # (Some honeypots accept and simulate shell regardless)
        hostname = random.choice(FAKE_HOSTNAMES)
        shell = ShellSimulator(hostname=hostname, username=FAKE_USERNAME)

        # Send fake MOTD
        motd = get_fake_motd(hostname)
        channel.send(motd + '\r\n')

        # Send prompt
        prompt = shell.get_prompt()
        channel.send(prompt)

        # Command buffer
        command_buffer = ''

        # Read commands
        while True:
            if channel.recv_ready():
                data = channel.recv(1024).decode('utf-8', errors='ignore')

                if not data:
                    break

                for char in data:
                    if char in ['\r', '\n']:
                        if command_buffer.strip():
                            # Process command
                            output, classification, mitre = shell.process_command(command_buffer)

                            # Log interaction
                            interaction_data = {
                                'session_id': session.session_id,
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                                'interaction_type': 'ssh_command',
                                'command': command_buffer,
                                'command_classification': classification,
                                'fake_output': output
                            }
                            db.log_interaction(interaction_data)

                            # Send output
                            channel.send('\r\n' + output + '\r\n')

                        # Reset buffer and send new prompt
                        command_buffer = ''
                        channel.send(prompt)

                    elif char == '\x7f':  # Backspace
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send('\b \b')

                    elif char == '\x03':  # Ctrl+C
                        command_buffer = ''
                        channel.send('^C\r\n' + prompt)

                    elif char == '\x04':  # Ctrl+D (EOF)
                        channel.send('logout\r\n')
                        break

                    else:
                        command_buffer += char
                        channel.send(char)

            if not channel.active:
                break

        channel.close()
        transport.close()

        # End session
        ended_at = datetime.now(timezone.utc).isoformat()
        duration = session.duration_seconds()
        db.end_session(session.session_id, ended_at, duration)

    except Exception as e:
        print(f"[SSH] Error handling {client_ip}: {e}")
    finally:
        session_manager.end_session(session.session_id)
        try:
            client_socket.close()
        except:
            pass


def run_ssh_decoy():
    """
    Start the SSH decoy server
    Listens for SSH connections and handles them in separate threads
    """
    db = Database(Config.DATABASE_PATH)
    session_manager = SessionManager()

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((Config.SSH_HOST, Config.SSH_PORT))
        server_socket.listen(100)

        print(f"[*] Starting SSH Decoy on {Config.SSH_HOST}:{Config.SSH_PORT}")
        print(f"[*] Database: {Config.DATABASE_PATH}")
        print(f"[*] Fake SSH shell ready - waiting for attackers...")

        while True:
            try:
                client_socket, addr = server_socket.accept()
                print(f"[SSH] Connection from {addr[0]}:{addr[1]}")

                # Handle in new thread
                client_thread = threading.Thread(
                    target=handle_ssh_client,
                    args=(client_socket, addr, db, session_manager),
                    daemon=True
                )
                client_thread.start()

            except KeyboardInterrupt:
                print("\n[!] Shutting down SSH decoy...")
                break
            except Exception as e:
                print(f"[SSH] Error accepting connection: {e}")
                continue

    except OSError as e:
        if "address already in use" in str(e).lower():
            print(f"[✗] Port {Config.SSH_PORT} is already in use")
            print(f"    Try a different port in .env or stop the conflicting service")
        else:
            raise
    finally:
        server_socket.close()


if __name__ == '__main__':
    run_ssh_decoy()
