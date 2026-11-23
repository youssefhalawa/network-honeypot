"""
Tests for the HTTP decoy (Member 2): app/decoy_http/server.py
Run from the project root:  python -m pytest tests/test_http_decoy.py -v
"""
import base64
import json
import sqlite3

import bcrypt
import pytest

from conftest import DB_PATH, clear_database, query
from app.decoy_http.server import app, session_manager


@pytest.fixture
def client():
    app.config['TESTING'] = True
    clear_database()
    return app.test_client()


def last_interaction():
    return query('SELECT * FROM interactions ORDER BY interaction_id DESC LIMIT 1')[0]


# --- The fake page ----------------------------------------------------------

def test_login_page_is_served(client):
    r = client.get('/')
    assert r.status_code == 200
    assert b'Acme Corp' in r.data and b'name="password"' in r.data


def test_server_header_pretends_to_be_apache(client):
    r = client.get('/')
    assert r.headers['Server'] == 'Apache/2.4.41 (Ubuntu)'
    assert 'Werkzeug' not in r.headers['Server']


# --- Credential capture -----------------------------------------------------

def test_login_always_fails_and_captures_credentials(client):
    r = client.post('/login', data={'username': 'admin', 'password': 'Secret123'})
    assert r.status_code == 200
    assert b'Invalid username or password' in r.data

    attempt = query('SELECT * FROM auth_attempts')[0]
    assert attempt['username'] == 'admin'
    assert attempt['success'] == 0
    assert attempt['auth_method'] == 'form'
    assert attempt['password_hash'] != 'Secret123'
    assert bcrypt.checkpw(b'Secret123', attempt['password_hash'].encode())


def test_plaintext_password_is_stored_nowhere(client):
    client.post('/login', data={'username': 'root', 'password': 'Sup3rS3cretPW'})
    conn = sqlite3.connect(DB_PATH)
    for table in ('sessions', 'auth_attempts', 'interactions'):
        for row in conn.execute(f'SELECT * FROM {table}'):
            assert 'Sup3rS3cretPW' not in json.dumps(row, default=str)
    conn.close()
    body = json.loads(last_interaction()['http_body'])
    assert body == {'username': 'root', 'password': '[REDACTED]'}


def test_basic_auth_credentials_are_captured_and_header_redacted(client):
    token = base64.b64encode(b'scanner:letmein').decode()
    client.get('/admin', headers={'Authorization': f'Basic {token}'})
    attempt = query('SELECT * FROM auth_attempts')[0]
    assert attempt['username'] == 'scanner' and attempt['auth_method'] == 'http_basic'
    assert token not in last_interaction()['http_headers']


def test_password_with_special_characters_does_not_crash(client):
    r = client.post('/login', data={'username': "a'; DROP TABLE x;--", 'password': 'pä$$wörd😀'})
    assert r.status_code == 200
    assert len(query('SELECT * FROM auth_attempts')) == 1


# --- Request logging and classification -------------------------------------

def test_every_request_is_logged(client):
    client.get('/?page=2', headers={'User-Agent': 'TestBot/1.0'})
    row = last_interaction()
    assert row['http_method'] == 'GET' and row['http_path'] == '/'
    assert json.loads(row['http_query_params']) == {'page': ['2']}
    assert json.loads(row['http_headers'])['User-Agent'] == 'TestBot/1.0'


@pytest.mark.parametrize('url, expected', [
    ("/?id=1' OR '1'='1", 'sqli'),
    ('/search?q=<script>alert(1)</script>', 'xss'),
    ('/wp-login.php', 'wordpress_scan'),
    ('/phpmyadmin/', 'phpmyadmin_scan'),
    ('/page?file=../../../etc/passwd', 'lfi'),
    ('/admin', 'admin_probe'),
    ('/robots.txt', 'recon_robots'),
    ('/random-page', 'scan'),
])
def test_attacks_are_classified(client, url, expected):
    client.get(url)
    assert last_interaction()['attack_signature'] == expected


def test_sqli_inside_login_form_is_classified(client):
    client.post('/login', data={'username': "admin' OR '1'='1", 'password': 'x'})
    assert last_interaction()['attack_signature'] == 'sqli'


def test_plain_login_is_labeled_credential_capture(client):
    client.post('/login', data={'username': 'bob', 'password': 'hunter2'})
    assert last_interaction()['attack_signature'] == 'credential_capture'


# --- Sessions ---------------------------------------------------------------

def test_ip_is_enriched_for_each_session(client):
    client.get('/')
    intel = query('SELECT * FROM ip_intel')
    assert len(intel) == 1 and intel[0]['country_code'] in ('RESERVED', 'PRIVATE', 'OFFLINE')


def test_sessions_are_closed_after_each_request(client):
    for _ in range(5):
        client.get('/')
    rows = query('SELECT * FROM sessions')
    assert len(rows) == 5
    assert all(r['ended_at'] is not None for r in rows)
    assert all(r['protocol'] == 'http' and r['total_interactions'] == 1 for r in rows)
    assert session_manager.active_session_count() == 0


def test_forged_x_forwarded_for_is_ignored(client):
    client.get('/', headers={'X-Forwarded-For': '8.8.8.8'})
    assert query('SELECT source_ip FROM sessions')[0]['source_ip'] != '8.8.8.8'


# --- Deceptive responses ----------------------------------------------------

def test_admin_returns_fake_apache_403(client):
    r = client.get('/admin/settings')
    assert r.status_code == 403 and b'Apache/2.4.41' in r.data


def test_unknown_path_returns_fake_apache_404(client):
    r = client.get('/backup.zip')
    assert r.status_code == 404 and b'Apache/2.4.41' in r.data


@pytest.mark.parametrize('method', ['PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def test_unusual_methods_get_apache_pages_and_are_logged(client, method):
    r = client.open('/login', method=method)
    assert b'Werkzeug' not in r.data and b'Apache/2.4.41' in r.data
    assert last_interaction()['http_method'] == method


def test_huge_body_is_rejected_and_logged(client):
    r = client.post('/login', data='A' * (2 * 1024 * 1024), content_type='text/plain')
    assert r.status_code == 413
    assert last_interaction()['attack_signature'] == 'oversized_request'


def test_logged_body_is_truncated(client):
    client.post('/api/upload', data='B' * 10000, content_type='text/plain')
    body = last_interaction()['http_body']
    assert len(body) < 5000 and body.endswith('[truncated]')


def test_username_is_html_escaped_on_error_page(client):
    r = client.post('/login', data={'username': '"><script>alert(1)</script>', 'password': 'x'})
    assert b'<script>alert(1)</script>' not in r.data


def test_no_code_execution_functions_in_decoy():
    import inspect
    import app.decoy_http.server as server
    source = inspect.getsource(server)
    for forbidden in ('subprocess', 'os.system', 'eval(', 'exec(', 'open('):
        assert forbidden not in source
