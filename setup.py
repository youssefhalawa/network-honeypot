#!/usr/bin/env python3
"""
One-command setup and verification script for Network Honeypot
Checks prerequisites, creates configuration, and runs initial tests
"""
import sys
import os
import subprocess
from pathlib import Path


def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def check_python_version():
    """Verify Python version"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print(f"  ✗ Python {version.major}.{version.minor} detected")
        print(f"  ✓ Python 3.9+ required")
        return False
    print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
    return True


def install_dependencies():
    """Install Python dependencies"""
    print("\nInstalling dependencies...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            check=True,
            capture_output=True
        )
        print("  ✓ Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Failed to install dependencies: {e}")
        return False


def create_env_file():
    """Create .env file from template"""
    print("\nCreating configuration file...")
    env_example = Path(".env.example")
    env_file = Path(".env")

    if env_file.exists():
        print("  ℹ .env already exists, skipping")
        return True

    if not env_example.exists():
        print("  ✗ .env.example not found")
        return False

    try:
        env_file.write_text(env_example.read_text())
        print("  ✓ .env created from template")
        return True
    except Exception as e:
        print(f"  ✗ Failed to create .env: {e}")
        return False


def create_data_directory():
    """Create data directory"""
    print("\nCreating data directory...")
    data_dir = Path("data")
    try:
        data_dir.mkdir(exist_ok=True)
        print("  ✓ data/ directory ready")
        return True
    except Exception as e:
        print(f"  ✗ Failed to create data directory: {e}")
        return False


def test_imports():
    """Test critical imports"""
    print("\nTesting imports...")
    required_modules = [
        ('flask', 'Flask'),
        ('paramiko', 'Paramiko'),
        ('bcrypt', 'bcrypt'),
        ('dotenv', 'python-dotenv'),
    ]

    all_ok = True
    for module, name in required_modules:
        try:
            __import__(module)
            print(f"  ✓ {name} available")
        except ImportError:
            print(f"  ✗ {name} not found")
            all_ok = False

    return all_ok


def check_ports():
    """Check if default ports are available"""
    print("\nChecking port availability...")
    import socket

    ports = [
        (8080, "HTTP decoy"),
        (2222, "SSH decoy"),
        (5000, "Dashboard"),
    ]

    all_available = True
    for port, service in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()

        if result == 0:
            print(f"  ⚠ Port {port} ({service}) is in use")
            all_available = False
        else:
            print(f"  ✓ Port {port} ({service}) available")

    return all_available


def print_next_steps():
    """Print next steps for user"""
    print_header("Setup Complete!")
    print("""
Next Steps:

1. Review configuration:
   Edit .env file to customize ports and settings

2. Start the honeypot:
   python -m app.main

3. Run tests (in new terminal):
   python scripts/test_honeypot.py
   python scripts/simulate_attacks.py

4. Start dashboard (in new terminal):
   python -m app.dashboard.app
   Then open: http://localhost:5000

5. View captured data:
   sqlite3 data/honeypot.db "SELECT * FROM sessions LIMIT 5;"

Documentation:
- README.md              - Complete guide
- QUICKSTART.md          - 5-minute guide
- docs/ARCHITECTURE.md   - System design
- docs/TEAM_WALKTHROUGH.md - Code walkthrough

⚠️  Security Reminder:
Only deploy on networks you own or have authorization to monitor.
See README.md for deployment warnings and best practices.
""")


def main():
    """Main setup flow"""
    print_header("Network Honeypot - Setup Script")

    print("\n📋 This script will:")
    print("  • Verify Python version")
    print("  • Install dependencies")
    print("  • Create configuration files")
    print("  • Test imports")
    print("  • Check port availability")
    print()

    # Check Python version
    if not check_python_version():
        print("\n❌ Setup failed: Python version too old")
        sys.exit(1)

    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed: Could not install dependencies")
        sys.exit(1)

    # Create .env file
    if not create_env_file():
        print("\n❌ Setup failed: Could not create configuration")
        sys.exit(1)

    # Create data directory
    if not create_data_directory():
        print("\n❌ Setup failed: Could not create data directory")
        sys.exit(1)

    # Test imports
    if not test_imports():
        print("\n⚠️  Warning: Some dependencies missing, re-run:")
        print("   pip install -r requirements.txt")

    # Check ports
    ports_ok = check_ports()
    if not ports_ok:
        print("\n⚠️  Warning: Some ports in use. Edit .env to change ports.")

    # Success
    print_next_steps()
    return 0


if __name__ == '__main__':
    sys.exit(main())
