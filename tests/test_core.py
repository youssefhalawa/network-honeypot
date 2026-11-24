"""
Tests for Member 1: configuration, sessions, start-up and shutdown.
"""
import os
import signal
import socket
import subprocess
import sys
import threading
import time

import pytest

from conftest import ROOT, clear_database, query
from app.core.session import RateLimited, SessionLimitReached, SessionManager


def run_config_check(env_overrides):
    """Import the config in a fresh Python with these settings and run validate()."""
    env = {**os.environ, **env_overrides}
    code = 'from app.core.config import Config; Config.validate(); print("OK")'
    return subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env, capture_output=True, text=True)


# --- Configuration -----------------------------------------------------------

def test_default_config_is_valid():
    assert run_config_check({}).stdout.strip() == 'OK'


def test_bad_number_gives_clear_error_not_crash():
    result = run_config_check({'HTTP_PORT': 'abc'})
    assert result.returncode != 0
    assert "HTTP_PORT='abc' is not a whole number" in result.stderr
    assert 'Traceback' in result.stderr  # raised by validate(), i.e. after import succeeded
    assert 'invalid literal' not in result.stderr


@pytest.mark.parametrize('env, message', [
    ({'HTTP_PORT': '2222', 'SSH_PORT': '2222'}, 'cannot both be 2222'),
    ({'DASHBOARD_ENABLED': 'true', 'DASHBOARD_PORT': '8080'}, 'cannot both be 8080'),
    ({'SSH_PORT': '70000'}, 'between 1 and 65535'),
    ({'SESSION_IDLE_TIMEOUT_SECONDS': '0'}, 'must be greater than 0'),
    ({'SESSION_IDLE_TIMEOUT_SECONDS': '4000'}, 'cannot be longer'),
    ({'HTTP_DECOY_ENABLED': 'false', 'SSH_DECOY_ENABLED': 'false'}, 'At least one decoy'),
    ({'SSH_DECOY_ENABLED': 'maybe'}, 'should be true or false'),
    ({'LOG_LEVEL': 'LOUD'}, 'LOG_LEVEL'),
])
def test_invalid_settings_are_reported(env, message):
    result = run_config_check(env)
    assert result.returncode != 0 and message in result.stderr


def test_relative_database_path_is_inside_project():
    env = {**os.environ, 'DATABASE_PATH': 'data/x.db'}
    out = subprocess.run([sys.executable, '-c', 'from app.core.config import Config; print(Config.DATABASE_PATH)'],
                         cwd=ROOT, env=env, capture_output=True, text=True).stdout.strip()
    assert out == str(ROOT / 'data' / 'x.db')


def test_weak_credentials_are_parsed():
    env = {**os.environ, 'SSH_ACCEPTED_CREDENTIALS': 'root:root, admin:p:w'}
    out = subprocess.run([sys.executable, '-c',
                          'from app.core.config import Config; print(sorted(Config.SSH_ACCEPTED_CREDENTIALS))'],
                         cwd=ROOT, env=env, capture_output=True, text=True).stdout.strip()
    assert out == "[('admin', 'p:w'), ('root', 'root')]"


# --- Session manager ---------------------------------------------------------

def make(manager, ip='203.0.113.1', protocol='ssh'):
    return manager.create_session(source_ip=ip, source_port=1234, dest_port=2222, protocol=protocol)


def test_session_limit_is_enforced():
    manager = SessionManager(max_sessions=3)
    sessions = [make(manager, ip=f'203.0.113.{i}') for i in range(3)]
    with pytest.raises(SessionLimitReached):
        make(manager, ip='203.0.113.99')
    manager.end_session(sessions[0].session_id)
    make(manager, ip='203.0.113.99')   # room again
    assert manager.active_session_count() == 3


def test_rate_limit_per_ip():
    manager = SessionManager(rate_limit=2, rate_window=60)
    for _ in range(2):
        manager.end_session(make(manager).session_id)
    with pytest.raises(RateLimited):
        make(manager)
    make(manager, ip='198.51.100.7')   # other IPs are not affected


def test_idle_timeout_marks_session():
    manager = SessionManager(idle_timeout=0.2, max_duration=60)
    session = make(manager)
    assert manager.find_expired() == []
    time.sleep(0.3)
    expired = manager.find_expired()
    assert expired == [session] and session.close_reason == 'idle_timeout'


def test_activity_resets_idle_timer():
    manager = SessionManager(idle_timeout=0.3, max_duration=60)
    session = make(manager)
    for _ in range(4):
        time.sleep(0.15)
        session.touch()
    assert manager.find_expired() == []
    assert session.interaction_count == 4


def test_max_duration_even_when_active():
    manager = SessionManager(idle_timeout=10, max_duration=0.3)
    session = make(manager)
    for _ in range(4):
        time.sleep(0.1)
        session.touch()
    assert manager.find_expired() == [session] and session.close_reason == 'max_duration'


def test_end_session_returns_session_only_once():
    manager = SessionManager()
    session = make(manager)
    assert manager.end_session(session.session_id) is session
    assert manager.end_session(session.session_id) is None


def test_manager_is_thread_safe():
    manager = SessionManager(max_sessions=10_000, rate_limit=10_000)
    errors = []

    def worker(n):
        try:
            for i in range(200):
                s = make(manager, ip=f'10.{n}.{i % 250}.1')
                manager.find_expired()
                manager.end_session(s.session_id)
        except Exception as exc:  # pragma: no cover - only on failure
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and manager.active_session_count() == 0


def test_http_and_ssh_share_one_manager():
    from app.core.session import get_session_manager
    import app.decoy_http.server as http_server
    assert http_server.session_manager is get_session_manager()


# --- main.py -----------------------------------------------------------------

def test_busy_port_is_detected():
    from app.main import port_is_free
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        assert port_is_free('127.0.0.1', s.getsockname()[1]) is False


def test_reaper_closes_expired_http_sessions():
    from app.main import reaper
    from app.storage.database import get_database
    clear_database()
    db = get_database()
    manager = SessionManager(idle_timeout=0.1, max_duration=60)
    session = make(manager, protocol='http')
    db.create_session(session.to_dict())
    stop = threading.Event()
    import app.main as main_module
    old = main_module.REAPER_INTERVAL_SECONDS
    main_module.REAPER_INTERVAL_SECONDS = 0.1
    try:
        t = threading.Thread(target=reaper, args=(stop, db, manager))
        t.start()
        time.sleep(0.5)
        stop.set()
        t.join()
    finally:
        main_module.REAPER_INTERVAL_SECONDS = old
    assert manager.active_session_count() == 0
    assert query('SELECT ended_at FROM sessions')[0]['ended_at'] is not None


def test_honeypot_starts_and_stops_cleanly(tmp_path):
    """Run the real program, then Ctrl+C it: it must exit 0 and leave no open sessions."""
    from conftest import free_port
    env = {**os.environ, 'DATABASE_PATH': str(tmp_path / 'run.db'), 'HTTP_PORT': str(free_port()),
           'SSH_PORT': str(free_port()), 'LOG_FILE': str(tmp_path / 'run.log')}
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
    proc = subprocess.Popen([sys.executable, '-m', 'app.main'], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding='utf-8', errors='replace', creationflags=creationflags)
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                socket.create_connection(('127.0.0.1', int(env['HTTP_PORT'])), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        import urllib.request
        urllib.request.urlopen(f"http://127.0.0.1:{env['HTTP_PORT']}/").read()
        if sys.platform == 'win32':
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(2)  # SIGINT = Ctrl+C
        output, _ = proc.communicate(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 0, output
    assert 'Shutting down' in output and 'Totals: 1 sessions' in output
    import sqlite3
    assert sqlite3.connect(env['DATABASE_PATH']).execute(
        'SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL').fetchone()[0] == 0


def test_port_in_use_stops_with_clear_message(tmp_path):
    from conftest import free_port
    with socket.socket() as busy:
        busy.bind(('0.0.0.0', 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        env = {**os.environ, 'DATABASE_PATH': str(tmp_path / 'run.db'), 'HTTP_PORT': str(port),
               'SSH_PORT': str(free_port()), 'LOG_FILE': str(tmp_path / 'run.log')}
        result = subprocess.run([sys.executable, '-m', 'app.main'], cwd=ROOT, env=env, capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=30)
    assert result.returncode == 1
    assert f'port {port} is already in use' in result.stdout + result.stderr
