"""
Honeypot main entry point (Member 1)

    python -m app.main

Start-up:   validate settings -> set up logging -> check ports are free ->
            close sessions left open by a previous crash -> start the decoys
            (and the dashboard if DASHBOARD_ENABLED=true) in their own threads
Running:    a "reaper" thread closes sessions that hit the idle timeout or
            the maximum duration; the main thread watches that every service
            is still alive
Shutdown:   Ctrl+C / SIGTERM stops every server, then closes all open
            sessions in the database so nothing stays "Active" forever
"""
import logging
import logging.handlers
import os
import signal
import socket
import sys
import threading
from pathlib import Path

from app.core.config import Config

log = logging.getLogger('honeypot')

REAPER_INTERVAL_SECONDS = 5


# ---------------------------------------------------------------------------
# Start-up helpers
# ---------------------------------------------------------------------------
def setup_logging():
    """Console + rotating log file (LOG_FILE, 5 MB x 5 files)."""
    fmt = logging.Formatter('%(asctime)s %(levelname)-7s %(name)s: %(message)s')
    root = logging.getLogger()
    root.setLevel(Config.LOG_LEVEL)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        Path(Config.LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(Config.LOG_FILE, maxBytes=5 * 1024 * 1024,
                                                            backupCount=5, encoding='utf-8')
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError as exc:
        log.warning('cannot write log file %s: %s (console only)', Config.LOG_FILE, exc)

    logging.getLogger('werkzeug').setLevel(logging.WARNING)   # one line per request is too noisy
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)  # scanners cause harmless errors


def port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if sys.platform == 'win32':
            # On Windows SO_REUSEADDR lets another socket bind a port that is
            # already in use, so this probe would report a busy port as free
            # and a second honeypot would start silently. Exclusive mode makes
            # bind() fail when the port is really taken.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
            return True
        except OSError:
            return False


def check_ports() -> list:
    problems = []
    wanted = []
    if Config.HTTP_DECOY_ENABLED:
        wanted.append(('HTTP decoy', Config.HTTP_HOST, Config.HTTP_PORT, 'HTTP_PORT'))
    if Config.SSH_DECOY_ENABLED:
        wanted.append(('SSH decoy', Config.SSH_HOST, Config.SSH_PORT, 'SSH_PORT'))
    if Config.DASHBOARD_ENABLED:
        wanted.append(('Dashboard', Config.DASHBOARD_HOST, Config.DASHBOARD_PORT, 'DASHBOARD_PORT'))
    for name, host, port, setting in wanted:
        if not port_is_free(host, port):
            hint = ' (ports below 1024 need root or setcap)' if port < 1024 else ''
            if port == 5000 and sys.platform == 'darwin':
                hint = ' (on a Mac, AirPlay Receiver uses port 5000: set DASHBOARD_PORT=5050)'
            problems.append(f'{name}: port {port} is already in use or not allowed{hint}. '
                            f'Stop the other program or change {setting} in .env')
    return problems


def check_user():
    """The honeypot should not run as root (see README: deployment)."""
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        log.warning('Running as root is dangerous. Create a normal user (e.g. "%s") and run as that user.',
                    Config.RUN_AS_USER)


def load_services():
    """Import each enabled service only when needed, with clear errors."""
    services = []
    if Config.HTTP_DECOY_ENABLED:
        try:
            from app.decoy_http.server import run_http_decoy
            services.append(('HTTP-Decoy', run_http_decoy))
        except ImportError as exc:
            raise SystemExit(f'[x] HTTP decoy needs Flask: {exc}. Run: pip install -r requirements.txt')
    if Config.SSH_DECOY_ENABLED:
        try:
            from app.decoy_ssh.server import run_ssh_decoy
            services.append(('SSH-Decoy', run_ssh_decoy))
        except ImportError as exc:
            raise SystemExit(f'[x] SSH decoy needs paramiko: {exc}. Run: pip install -r requirements.txt '
                             '(or set SSH_DECOY_ENABLED=false)')
    if Config.DASHBOARD_ENABLED:
        from app.dashboard.app import run_dashboard
        services.append(('Dashboard', run_dashboard))
    return services


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------
class ServiceThread(threading.Thread):
    """Runs one server and remembers why it stopped, if it crashed."""

    def __init__(self, name, target, stop_event):
        super().__init__(name=name, daemon=True)
        self._target_fn = target
        self._stop_event = stop_event
        self.error = None

    def run(self):
        try:
            self._target_fn(stop_event=self._stop_event)
        except BaseException as exc:  # noqa: BLE001 - we report every failure
            self.error = exc


def reaper(stop_event: threading.Event, db, manager):
    """Close sessions that went idle or ran too long."""
    while not stop_event.wait(REAPER_INTERVAL_SECONDS):
        try:
            for session in manager.find_expired():
                log.info('session %s (%s %s) closed: %s', session.session_id[:8], session.protocol,
                         session.source_ip, session.close_reason)
                if session.protocol != 'ssh':
                    # SSH handlers notice the mark themselves and say "auto-logout" to the attacker
                    if manager.end_session(session.session_id):
                        db.end_session(session.session_id, db.utc_now(), session.duration_seconds())
        except Exception as exc:
            log.warning('reaper error: %s', exc)


def shutdown(db, manager, threads):
    log.info('Shutting down...')
    for thread in threads:
        thread.join(timeout=5)
    open_sessions = manager.end_all()
    for session in open_sessions:
        try:
            db.end_session(session.session_id, db.utc_now(), session.duration_seconds())
        except Exception as exc:
            log.warning('could not close session %s: %s', session.session_id, exc)
    leftover = db.close_open_sessions()
    stats = db.get_stats()
    log.info('Closed %d open session(s). Totals: %d sessions, %d login attempts, %d commands, %d HTTP requests.',
             len(open_sessions) + leftover, stats['total_sessions'], stats['credentials_captured'],
             stats['commands_captured'], stats['http_requests'])


def print_banner():
    line = '=' * 60
    print(line)
    print('  Network Honeypot - SSH/HTTP Decoy System')
    print(line)
    if Config.HTTP_DECOY_ENABLED:
        print(f'  - HTTP decoy:  http://{Config.HTTP_HOST}:{Config.HTTP_PORT}')
    if Config.SSH_DECOY_ENABLED:
        print(f'  - SSH decoy:   ssh -p {Config.SSH_PORT} root@{Config.SSH_HOST}')
    if Config.DASHBOARD_ENABLED:
        print(f'  - Dashboard:   http://{Config.DASHBOARD_HOST}:{Config.DASHBOARD_PORT}')
    print(f'  - Database:    {Config.DATABASE_PATH}')
    print(f'  - Limits:      {Config.MAX_CONCURRENT_SESSIONS} sessions, idle {Config.SESSION_IDLE_TIMEOUT_SECONDS}s, '
          f'max {Config.SESSION_MAX_DURATION_SECONDS}s')
    print(line)
    print('[!] Only deploy on networks you own or are authorized to monitor.')
    print('   Run it isolated (DMZ/VLAN) and block outgoing traffic (see README).')
    print('Press Ctrl+C to stop')
    print(line)


def main():
    # Redirected output on Windows defaults to the legacy code page (cp1252),
    # which cannot encode the banner emoji and would crash start-up. Force UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    try:
        Config.validate()
    except ValueError as exc:
        print(f'[x] {exc}')
        print('    Fix these settings in your .env file and start again.')
        sys.exit(1)

    setup_logging()
    print_banner()
    for note in Config.warnings():
        log.warning(note)
    check_user()

    problems = check_ports()
    if problems:
        for problem in problems:
            log.error(problem)
        sys.exit(1)

    services = load_services()

    from app.core.session import get_session_manager
    from app.storage.database import get_database
    db = get_database()
    manager = get_session_manager()
    stale = db.close_open_sessions()
    if stale:
        log.info('Closed %d session(s) left open by a previous run', stale)

    stop_event = threading.Event()

    def handle_signal(signum, _frame):
        log.info('Received %s', signal.Signals(signum).name)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    if hasattr(signal, 'SIGBREAK'):      # Windows Ctrl+Break (also used by service stop)
        signal.signal(signal.SIGBREAK, handle_signal)

    threads = [ServiceThread(name, target, stop_event) for name, target in services]
    for thread in threads:
        thread.start()
    reaper_thread = threading.Thread(target=reaper, args=(stop_event, db, manager), daemon=True, name='Reaper')
    reaper_thread.start()

    exit_code = 0
    while not stop_event.wait(1):
        dead = [t for t in threads if not t.is_alive()]
        if dead:
            for t in dead:
                log.error('%s stopped unexpectedly: %s', t.name, t.error or 'no error given')
            exit_code = 1
            stop_event.set()

    shutdown(db, manager, threads)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
