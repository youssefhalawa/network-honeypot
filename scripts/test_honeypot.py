#!/usr/bin/env python3
"""
Test script to verify HTTP honeypot functionality
Simulates various attack patterns against the running honeypot
"""
import requests
import time
import sys
from datetime import datetime

# Target honeypot (adjust if needed)
TARGET = 'http://localhost:8080'

# Test credentials (common botnet/attacker patterns)
TEST_CREDENTIALS = [
    ('admin', 'admin'),
    ('root', 'password'),
    ('admin', '123456'),
    ('user', 'user'),
    ('test', 'test'),
]

# Test paths (vulnerability scans)
TEST_PATHS = [
    '/',
    '/admin',
    '/wp-admin',
    '/phpmyadmin',
    '/admin.php',
    "/../etc/passwd",
    "/index.php?id=1' OR '1'='1",
]


def print_banner():
    print("=" * 60)
    print("🧪 Honeypot Test Script - Phase 1 Verification")
    print("=" * 60)
    print(f"Target: {TARGET}")
    print(f"Time: {datetime.now().isoformat()}")
    print()


def test_get_requests():
    """Test various GET requests"""
    print("[*] Testing GET requests on different paths...")

    for path in TEST_PATHS:
        try:
            url = f"{TARGET}{path}"
            headers = {'User-Agent': 'TestBot/1.0 (Honeypot Verification)'}

            response = requests.get(url, headers=headers, timeout=5)
            print(f"  GET {path:30s} -> {response.status_code}")
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed to connect: {e}")
            return False

    print()
    return True


def test_login_attempts():
    """Test credential capture via login form"""
    print("[*] Testing credential capture (login attempts)...")

    for username, password in TEST_CREDENTIALS:
        try:
            url = f"{TARGET}/login"
            data = {'username': username, 'password': password}
            headers = {'User-Agent': 'BruteForceBot/2.1'}

            response = requests.post(url, data=data, headers=headers, timeout=5)
            print(f"  POST /login - {username:10s} / {password:15s} -> {response.status_code}")
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed: {e}")
            return False

    print()
    return True


def test_sqli_attempts():
    """Test SQL injection pattern logging"""
    print("[*] Testing SQL injection pattern logging...")

    sqli_payloads = [
        "?id=1' OR '1'='1",
        "?id=1 UNION SELECT NULL--",
        "?user=admin'--",
    ]

    for payload in sqli_payloads:
        try:
            url = f"{TARGET}/search{payload}"
            headers = {'User-Agent': 'sqlmap/1.5'}

            response = requests.get(url, headers=headers, timeout=5)
            print(f"  GET {payload:30s} -> {response.status_code}")
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed: {e}")
            return False

    print()
    return True


def verify_database():
    """Verify data was written to database"""
    print("[*] Verifying database entries...")
    print("  Run this command to check captured data:")
    print(f"    sqlite3 data/honeypot.db \"SELECT COUNT(*) FROM sessions;\"")
    print(f"    sqlite3 data/honeypot.db \"SELECT COUNT(*) FROM auth_attempts;\"")
    print(f"    sqlite3 data/honeypot.db \"SELECT COUNT(*) FROM interactions;\"")
    print()


def main():
    print_banner()

    # Check if honeypot is running
    try:
        response = requests.get(TARGET, timeout=3)
    except requests.exceptions.ConnectionError:
        print(f"[✗] Cannot connect to {TARGET}")
        print(f"    Make sure the honeypot is running:")
        print(f"    python -m app.main")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[✗] Connection error: {e}")
        sys.exit(1)

    print(f"[✓] Honeypot is responding at {TARGET}")
    print()

    # Run tests
    tests_passed = 0
    tests_total = 3

    if test_get_requests():
        tests_passed += 1

    if test_login_attempts():
        tests_passed += 1

    if test_sqli_attempts():
        tests_passed += 1

    # Summary
    print("=" * 60)
    print(f"Tests completed: {tests_passed}/{tests_total} passed")
    print("=" * 60)
    print()

    verify_database()

    if tests_passed == tests_total:
        print("[✓] Phase 1 verification complete!")
        print("    Check data/honeypot.db for captured telemetry")
        return 0
    else:
        print("[✗] Some tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
