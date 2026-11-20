"""
Honeypot Main Entry Point
Orchestrates HTTP and SSH decoy servers concurrently
"""
import sys
import signal
import threading
from pathlib import Path

from app.core.config import Config
from app.decoy_http.server import run_http_decoy
from app.decoy_ssh.server import run_ssh_decoy


def signal_handler(sig, frame):
    """Handle graceful shutdown on SIGINT/SIGTERM"""
    print("\n[!] Shutting down honeypot gracefully...")
    sys.exit(0)


def main():
    """Main orchestrator - runs HTTP and SSH decoys concurrently"""
    print("=" * 60)
    print("🍯 Network Honeypot - SSH/HTTP Decoy System")
    print("=" * 60)
    print()

    # Validate configuration
    try:
        Config.validate()
        print("[✓] Configuration validated")
    except ValueError as e:
        print(f"[✗] Configuration error: {e}")
        sys.exit(1)

    # Ensure data directory exists
    data_dir = Path(Config.DATABASE_PATH).parent
    data_dir.mkdir(parents=True, exist_ok=True)
    print(f"[✓] Data directory: {data_dir}")

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print()
    print("=" * 60)
    print("ACTIVE DECOYS:")
    print("=" * 60)

    if Config.HTTP_DECOY_ENABLED:
        print(f"  • HTTP Decoy:  http://{Config.HTTP_HOST}:{Config.HTTP_PORT}")

    if Config.SSH_DECOY_ENABLED:
        print(f"  • SSH Decoy:   ssh://{Config.SSH_HOST}:{Config.SSH_PORT}")

    print()
    print("=" * 60)
    print("⚠️  DEPLOYMENT WARNING:")
    print("=" * 60)
    print("  • Only deploy on networks you own/have authorization for")
    print("  • Run in isolated environment (DMZ/VLAN)")
    print("  • Monitor logs regularly for novel attack patterns")
    print("  • Captured credentials are sensitive - handle securely")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()

    # Start decoys in separate threads
    threads = []

    if Config.HTTP_DECOY_ENABLED:
        http_thread = threading.Thread(target=run_http_decoy, daemon=True, name="HTTP-Decoy")
        http_thread.start()
        threads.append(http_thread)

    if Config.SSH_DECOY_ENABLED:
        ssh_thread = threading.Thread(target=run_ssh_decoy, daemon=True, name="SSH-Decoy")
        ssh_thread.start()
        threads.append(ssh_thread)

    if not threads:
        print("[!] No decoys enabled. Enable HTTP_DECOY_ENABLED or SSH_DECOY_ENABLED in .env")
        sys.exit(1)

    # Keep main thread alive
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        sys.exit(0)


if __name__ == '__main__':
    main()
