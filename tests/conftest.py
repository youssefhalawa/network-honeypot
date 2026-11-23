"""
Shared test setup (Member 7).
Every test uses a throwaway database and key in a temp folder, never data/.
Settings are put in the environment BEFORE any app module is imported.
"""
import os
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = Path(tempfile.mkdtemp(prefix='honeypot-tests-'))
os.environ.update({
    'DATABASE_PATH': str(TMP / 'test.db'),
    'SSH_HOST_KEY_PATH': str(TMP / 'ssh_host_rsa_key'),
    'LOG_FILE': str(TMP / 'honeypot.log'),
    'GEOIP_DB_PATH': str(TMP / 'missing-city.mmdb'),
    'GEOIP_ASN_DB_PATH': str(TMP / 'missing-asn.mmdb'),
    'RATE_LIMIT_PER_IP': '100000',
    'MAX_CONCURRENT_SESSIONS': '1000',
})

DB_PATH = os.environ['DATABASE_PATH']
TABLES = ('interactions', 'auth_attempts', 'sessions', 'ip_intel')


def clear_database():
    from app.storage.database import get_database
    get_database()  # make sure the schema exists
    with sqlite3.connect(DB_PATH) as conn:
        for table in TABLES:
            conn.execute(f'DELETE FROM {table}')


def query(sql, *args):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def clean_db():
    clear_database()
    from app.core.session import get_session_manager
    get_session_manager().end_all()
    yield
