"""
Tests for Member 4 (database) and Member 5 (IP enrichment).
"""
import threading
from datetime import datetime, timedelta, timezone

import pytest

from conftest import query
from app.enrichment import ip_lookup
from app.enrichment.ip_lookup import IPEnricher, enrich_and_store
from app.storage.database import get_database
from app.storage.models import AuthAttempt, SessionRecord


def new_session(db, sid, ip='203.0.113.5', protocol='ssh', started=None):
    db.create_session({'session_id': sid, 'source_ip': ip, 'source_port': 5000, 'dest_port': 2222,
                       'protocol': protocol, 'started_at': started or datetime.now(timezone.utc).isoformat()})


# --- Database ------------------------------------------------------------

def test_schema_has_four_tables_and_ten_indexes(clean_db):
    tables = {r['name'] for r in query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'sessions', 'auth_attempts', 'interactions', 'ip_intel'} <= tables
    indexes = query("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
    assert len(indexes) == 10


def test_wal_mode_is_on(clean_db):
    assert query('PRAGMA journal_mode')[0]['journal_mode'] == 'wal'


def test_concurrent_writes_do_not_lose_data(clean_db):
    db = get_database()
    new_session(db, 's1')
    errors = []

    def writer(n):
        try:
            for i in range(25):
                db.log_interaction({'session_id': 's1', 'timestamp': db.utc_now(), 'interaction_type': 'ssh_command',
                                    'command': f'cmd {n}-{i}'})
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert query('SELECT COUNT(*) AS n FROM interactions')[0]['n'] == 200
    assert query('SELECT total_interactions FROM sessions')[0]['total_interactions'] == 200


def test_close_open_sessions_after_crash(clean_db):
    db = get_database()
    new_session(db, 'left-open', started=(datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat())
    assert db.close_open_sessions() == 1
    row = query('SELECT ended_at, duration_seconds FROM sessions')[0]
    assert row['ended_at'] and 110 < row['duration_seconds'] < 130


def test_end_session_only_counts_once(clean_db):
    db = get_database()
    new_session(db, 'x')
    db.end_session('x', 'first', 1.0)
    db.end_session('x', 'second', 2.0)
    assert query('SELECT ended_at FROM sessions')[0]['ended_at'] == 'first'


def test_sort_column_cannot_inject_sql(clean_db):
    db = get_database()
    new_session(db, 'a')
    rows = db.get_sessions(sort='started_at; DROP TABLE sessions', order='sideways')
    assert len(rows) == 1 and query('SELECT COUNT(*) AS n FROM sessions')[0]['n'] == 1


def test_timeline_covers_requested_hours(clean_db):
    db = get_database()
    new_session(db, 'now')
    new_session(db, 'old', started=(datetime.now(timezone.utc) - timedelta(hours=30)).isoformat())
    timeline = db.get_timeline(24)
    assert len(timeline) == 24 and sum(t['count'] for t in timeline) == 1 and timeline[-1]['count'] == 1


def test_models_build_from_rows(clean_db):
    db = get_database()
    new_session(db, 'm')
    db.log_auth_attempt({'session_id': 'm', 'timestamp': db.utc_now(), 'username': 'root',
                         'password_hash': '$2b$...', 'auth_method': 'password', 'success': True})
    assert SessionRecord.from_row(query('SELECT * FROM sessions')[0]).protocol == 'ssh'
    assert AuthAttempt.from_row(query('SELECT * FROM auth_attempts')[0]).success == 1


# --- IP enrichment ---------------------------------------------------------

@pytest.mark.parametrize('ip, code', [
    ('127.0.0.1', 'RESERVED'), ('10.1.2.3', 'PRIVATE'), ('192.168.0.9', 'PRIVATE'), ('172.16.5.5', 'PRIVATE'),
    ('8.8.8.8', 'OFFLINE'), ('not-an-ip', 'OFFLINE'),
])
def test_enrich_without_geoip_database(ip, code):
    enricher = IPEnricher('/nonexistent/GeoLite2-City.mmdb')
    assert enricher.enrich(ip)['country_code'] == code


class FakeEnricher:
    calls = 0

    def enrich(self, ip):
        FakeEnricher.calls += 1
        return {'ip_address': ip, 'country_code': 'DE', 'country_name': 'Germany', 'city': 'Berlin',
                'latitude': 52.5, 'longitude': 13.4, 'asn': 3320, 'asn_org': 'Deutsche Telekom AG'}


def test_enrich_and_store_saves_and_caches(clean_db, monkeypatch):
    monkeypatch.setattr(ip_lookup, '_enricher', FakeEnricher())
    FakeEnricher.calls = 0
    db = get_database()
    for sid in ('a', 'b', 'c'):
        new_session(db, sid, ip='198.51.100.20')
        enrich_and_store(db, '198.51.100.20')
    row = query('SELECT * FROM ip_intel')[0]
    assert row['country_code'] == 'DE' and row['city'] == 'Berlin' and row['asn'] == 3320
    assert row['total_sessions'] == 3
    assert FakeEnricher.calls == 1, 'second and third lookups should come from the cache'
    origins = db.get_origins()
    assert origins[0]['country_code'] == 'DE' and origins[0]['session_count'] == 3
    assert db.get_geo_points()[0]['latitude'] == 52.5


def test_enrichment_errors_never_break_a_decoy(clean_db, monkeypatch):
    class Broken:
        def enrich(self, ip):
            raise RuntimeError('boom')
    monkeypatch.setattr(ip_lookup, '_enricher', Broken())
    assert enrich_and_store(get_database(), '198.51.100.99') is None
