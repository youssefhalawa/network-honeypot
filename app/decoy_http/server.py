"""
HTTP Decoy Server - Fake "DEPI GPT" employee login portal (Member 2)

What it does:
  * Serves a convincing corporate login page on Config.HTTP_PORT (default 8080)
  * Captures every username/password sent to it (form POST or HTTP Basic auth)
    and stores ONLY a bcrypt hash of the password, never plaintext
  * Logs every request (method, path, query, body, headers) to the database
  * Tags each request with an attack signature using Member 5's classifier
  * Always answers like a real Apache server: login always fails, /admin is
    403, everything else is 404, and the Server header says Apache

Safety guarantees:
  * Nothing the attacker sends is ever executed or used to open files
  * Password fields and Authorization headers are redacted before logging
  * Request bodies are capped (MAX_REQUEST_BYTES) and logged bodies truncated
  * A database error never breaks the fake page (the attacker sees nothing odd)
"""
import json
import logging
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import bcrypt
from flask import Flask, request, render_template_string
from werkzeug.exceptions import HTTPException
from werkzeug.serving import WSGIRequestHandler

from app.core.classifiers import classify_http_request
from app.core.config import Config
from app.core.webserver import serve_until_stopped
from app.core.session import RateLimited, SessionLimitReached, get_session_manager
from app.enrichment.ip_lookup import enrich_and_store
from app.storage.database import get_database

log = logging.getLogger('honeypot.http')

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
MAX_REQUEST_BYTES = 1024 * 1024      # reject bodies over 1 MB (413)
MAX_LOGGED_BODY = 4096               # store at most 4 KB of any body
BCRYPT_ROUNDS = 10                   # cheaper than default 12: brute-force floods won't pin the CPU
FAKE_SERVER_HEADER = 'Apache/2.4.41 (Ubuntu)'

# Only trust X-Forwarded-For when the honeypot really sits behind your own
# reverse proxy (TRUST_PROXY_HEADERS=true). Otherwise attackers could forge any source IP.
TRUST_PROXY_HEADERS = Config.TRUST_PROXY_HEADERS

SENSITIVE_KEYS = ('pass', 'pwd', 'secret', 'token')
ALL_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------
db = get_database()                      # shared with the SSH decoy and the dashboard
session_manager = get_session_manager()  # shared limit + timeouts for HTTP and SSH

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_BYTES

# ---------------------------------------------------------------------------
# Fake pages
# ---------------------------------------------------------------------------
LOGIN_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Portal - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .login-container {
            background: white; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%; max-width: 400px; padding: 40px;
        }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #333; font-size: 28px; font-weight: 600; }
        .logo p { color: #666; font-size: 14px; margin-top: 5px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; font-size: 14px; font-weight: 500; margin-bottom: 8px; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 12px 15px; border: 1px solid #ddd; border-radius: 5px;
            font-size: 14px; transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #667eea; }
        .options { display: flex; justify-content: space-between; align-items: center;
                   font-size: 13px; color: #555; margin-bottom: 20px; }
        .options a { color: #667eea; text-decoration: none; }
        .btn-login {
            width: 100%; padding: 12px; background: #667eea; color: white; border: none;
            border-radius: 5px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.3s;
        }
        .btn-login:hover { background: #5568d3; }
        .error-message {
            background: #fee; border: 1px solid #fcc; color: #c33; padding: 12px;
            border-radius: 5px; margin-bottom: 20px; font-size: 14px;
        }
        .footer { text-align: center; margin-top: 25px; padding-top: 20px; border-top: 1px solid #eee; }
        .footer p { color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>DEPI GPT</h1>
            <p>Employee Portal</p>
        </div>

        {% if error %}
        <div class="error-message">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" value="{{ username or '' }}" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="options">
                <label style="display:inline;font-weight:400"><input type="checkbox" name="remember"> Remember me</label>
                <a href="/forgot-password">Forgot password?</a>
            </div>
            <button type="submit" class="btn-login">Sign In</button>
        </form>

        <div class="footer">
            <p>Powered by Enterprise SSO v2.4.1</p>
            <p>&copy; {{ year }} DEPI GPT. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
'''

APACHE_ERROR_PAGE = '''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>{{ code }} {{ title }}</title>
</head><body>
<h1>{{ title }}</h1>
<p>{{ message }}</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at {{ host }} Port {{ port }}</address>
</body></html>
'''

ERROR_TEXT = {
    401: ('Unauthorized', 'This server could not verify that you are authorized to access the document requested.'),
    403: ('Forbidden', "You don't have permission to access this resource."),
    404: ('Not Found', 'The requested URL was not found on this server.'),
    405: ('Method Not Allowed', 'The requested method is not allowed for this URL.'),
    413: ('Request Entity Too Large', 'The requested resource does not allow request data with this request, '
                                      'or the amount of data provided in the request exceeds the capacity limit.'),
    500: ('Internal Server Error', 'The server encountered an internal error or misconfiguration '
                                   'and was unable to complete your request.'),
}

# Bait: tells scanners where the "interesting" pages are
ROBOTS_TXT = 'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /config/\n'


def _render_login(error=None, username=None):
    return render_template_string(LOGIN_PAGE, error=error, username=username,
                                  year=datetime.now(timezone.utc).year)


def _render_error(code):
    title, message = ERROR_TEXT[code]
    host = request.host.split(':')[0] if request.host else 'localhost'
    return render_template_string(APACHE_ERROR_PAGE, code=code, title=title, message=message,
                                  host=host, port=Config.HTTP_PORT), code


# ---------------------------------------------------------------------------
# Capture helpers
# ---------------------------------------------------------------------------
def _now():
    return datetime.now(timezone.utc).isoformat()


def _warn(msg):
    log.warning(msg)


def get_client_ip():
    """Real client IP. Proxy headers are ignored unless TRUST_PROXY_HEADERS=true."""
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        if request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP').strip()
    return request.remote_addr or 'unknown'


def _is_sensitive(key):
    key = key.lower()
    return any(word in key for word in SENSITIVE_KEYS)


def _raw_body():
    """Raw body text for non-form requests."""
    try:
        return request.get_data(cache=True, as_text=True) or ''
    except Exception:
        return ''


def _body_for_classification():
    """Decoded body (form fields as 'key=value'), used only in memory. Never stored as-is."""
    if request.form:
        return ' '.join(f'{k}={v}' for k, v in request.form.items(multi=True))
    return unquote_plus(_raw_body())


def _safe_body():
    """Body text for the database: password-like fields redacted, size capped."""
    if request.form:
        fields = {k: ('[REDACTED]' if _is_sensitive(k) else v) for k, v in request.form.items()}
        text = json.dumps(fields)
    elif request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            data = {k: ('[REDACTED]' if _is_sensitive(str(k)) else v) for k, v in data.items()}
        text = json.dumps(data) if data is not None else _raw_body()
    else:
        text = _raw_body()
    if not text:
        return None
    return text[:MAX_LOGGED_BODY] + ('...[truncated]' if len(text) > MAX_LOGGED_BODY else '')


def _safe_headers():
    headers = dict(request.headers)
    for name in list(headers):
        if name.lower() in ('authorization', 'proxy-authorization'):
            headers[name] = '[REDACTED]'
    return json.dumps(headers)


def _hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8', 'replace'),
                         bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode('utf-8')


def _classify(default_label):
    """Ask Member 5's classifier; fall back to a route label when nothing matches."""
    try:
        query = unquote_plus(request.query_string.decode('utf-8', 'replace'))
        signature, _severity, _desc = classify_http_request(
            request.method, request.path, query, _body_for_classification())
    except Exception as exc:
        _warn(f'classifier error: {exc}')
        signature = 'benign'
    return default_label if signature == 'benign' else signature


def record_request(default_label='benign', credentials=None):
    """
    Log one HTTP request as one short session:
    create session -> log credentials (hashed) -> log interaction -> end session.
    Any database failure is printed and swallowed so the fake page still loads.
    """
    session = None
    try:
        try:
            session = session_manager.create_session(
                source_ip=get_client_ip(),
                source_port=int(request.environ.get('REMOTE_PORT') or 0),
                dest_port=Config.HTTP_PORT,
                protocol='http',
                user_agent=request.headers.get('User-Agent'),
            )
        except (SessionLimitReached, RateLimited) as exc:
            # Still answer normally (so nothing looks odd) but don't flood the database
            log.info('not logging request: %s', exc)
            return
        db.create_session(session.to_dict())
        enrich_and_store(db, session.source_ip)
        session.touch()

        for username, password, method in (credentials or []):
            db.log_auth_attempt({
                'session_id': session.session_id,
                'timestamp': _now(),
                'username': username[:256],
                'password_hash': _hash_password(password),
                'auth_method': method,
            })

        db.log_interaction({
            'session_id': session.session_id,
            'timestamp': _now(),
            'interaction_type': 'http_request',
            'http_method': request.method,
            'http_path': request.path,
            'http_query_params': json.dumps(request.args.to_dict(flat=False)) if request.args else None,
            'http_body': _safe_body(),
            'http_headers': _safe_headers(),
            'attack_signature': _classify(default_label),
        })
    except Exception as exc:
        _warn(f'failed to record request: {exc}')
    finally:
        if session is not None:
            try:
                db.end_session(session.session_id, _now(), session.duration_seconds())
            except Exception as exc:
                _warn(f'failed to close session: {exc}')
            session_manager.end_session(session.session_id)


def _basic_auth_credentials():
    """Credentials sent with HTTP Basic auth (common in scanners), if any."""
    auth = request.authorization
    if auth and auth.type == 'basic' and auth.username is not None:
        return [(auth.username, auth.password or '', 'http_basic')]
    return []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/', methods=['GET', 'HEAD', 'POST'], provide_automatic_options=False)
@app.route('/login', methods=['GET', 'HEAD'], provide_automatic_options=False)
def index():
    """Show the fake login page."""
    record_request('benign', _basic_auth_credentials())
    return _render_login()


@app.route('/login', methods=['POST'], provide_automatic_options=False)
def login():
    """Capture the submitted credentials, then always fail like a real portal."""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    credentials = [(username, password, 'form')] if (username or password) else []
    record_request('credential_capture', credentials + _basic_auth_credentials())
    return _render_login(error='Invalid username or password. Please try again.', username=username)


@app.route('/admin', methods=ALL_METHODS, provide_automatic_options=False)
@app.route('/admin/<path:subpath>', methods=ALL_METHODS, provide_automatic_options=False)
def admin(subpath=None):
    """Fake admin area: always 403 Forbidden."""
    record_request('admin_probe', _basic_auth_credentials())
    return _render_error(403)


@app.route('/robots.txt', methods=['GET', 'HEAD'], provide_automatic_options=False)
def robots():
    record_request('recon_robots')
    return ROBOTS_TXT, 200, {'Content-Type': 'text/plain'}


@app.route('/<path:path>', methods=ALL_METHODS, provide_automatic_options=False)
def catch_all(path):
    """Every other URL: log it (scanners, LFI, WordPress probes...) and return 404."""
    record_request('scan', _basic_auth_credentials())
    return _render_error(404)


# ---------------------------------------------------------------------------
# Error handlers: always look like Apache, never like Flask
# ---------------------------------------------------------------------------
@app.errorhandler(HTTPException)
def handle_http_error(error):
    code = error.code if error.code in ERROR_TEXT else 404
    if code == 413:
        # Body is too large to read; log the request line and headers only.
        try:
            session = session_manager.create_session(
                source_ip=get_client_ip(), source_port=int(request.environ.get('REMOTE_PORT') or 0),
                dest_port=Config.HTTP_PORT, protocol='http', user_agent=request.headers.get('User-Agent'))
            db.create_session(session.to_dict())
            enrich_and_store(db, session.source_ip)
            db.log_interaction({
                'session_id': session.session_id, 'timestamp': _now(), 'interaction_type': 'http_request',
                'http_method': request.method, 'http_path': request.path,
                'http_body': f'[body rejected: over {MAX_REQUEST_BYTES} bytes]',
                'http_headers': _safe_headers(), 'attack_signature': 'oversized_request'})
            db.end_session(session.session_id, _now(), 0.0)
            session_manager.end_session(session.session_id)
        except (SessionLimitReached, RateLimited):
            pass
        except Exception as exc:
            _warn(f'failed to record 413: {exc}')
    else:
        record_request('scan')
    return _render_error(code)


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    _warn(f'unexpected error: {error!r}')
    return _render_error(500)


@app.after_request
def apache_headers(response):
    response.headers['Server'] = FAKE_SERVER_HEADER
    response.headers.pop('X-Powered-By', None)
    return response


# ---------------------------------------------------------------------------
# Server start-up
# ---------------------------------------------------------------------------
class ApacheRequestHandler(WSGIRequestHandler):
    """
    Python's base handler always adds 'Server: Werkzeug/x Python/y'. We skip it so the
    only Server header is the Apache one set in apache_headers() (a duplicate header
    would itself give the honeypot away).
    """
    server_version = 'Apache/2.4.41'
    sys_version = '(Ubuntu)'

    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())


def run_http_decoy(stop_event=None):
    """Start the HTTP decoy server (called by app/main.py in its own thread)."""
    log.info('HTTP decoy listening on %s:%s (fake DEPI GPT login portal)', Config.HTTP_HOST, Config.HTTP_PORT)
    serve_until_stopped(app, Config.HTTP_HOST, Config.HTTP_PORT, stop_event, ApacheRequestHandler)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    run_http_decoy()
