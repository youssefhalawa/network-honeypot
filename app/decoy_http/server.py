"""
HTTP Decoy Server - Fake login portal
Captures credentials and HTTP attack payloads
"""
from flask import Flask, request, render_template_string, jsonify
import bcrypt
import json
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Config
from app.core.session import SessionManager
from app.storage.database import Database

# Initialize components
db = Database(Config.DATABASE_PATH)
session_manager = SessionManager()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'honeypot-secret-key-change-in-production'

# Fake login page HTML template
LOGIN_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Portal - Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
            padding: 40px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #333;
            font-size: 28px;
            font-weight: 600;
        }
        .logo p {
            color: #666;
            font-size: 14px;
            margin-top: 5px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #333;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn-login:hover {
            background: #5568d3;
        }
        .error-message {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        .footer p {
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🏢 Acme Corp</h1>
            <p>Employee Portal</p>
        </div>

        {% if error %}
        <div class="error-message">
            ⚠️ {{ error }}
        </div>
        {% endif %}

        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit" class="btn-login">Sign In</button>
        </form>

        <div class="footer">
            <p>Powered by Enterprise SSO v2.4.1</p>
            <p>&copy; 2024 Acme Corporation. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
'''


def get_client_ip():
    """Extract real client IP (handles proxies)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def log_http_interaction(session_id: str, attack_signature: str = 'benign'):
    """Log HTTP request details to database"""
    interaction_data = {
        'session_id': session_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'interaction_type': 'http_request',
        'http_method': request.method,
        'http_path': request.path,
        'http_query_params': json.dumps(dict(request.args)) if request.args else None,
        'http_body': request.get_data(as_text=True) if request.data else None,
        'http_headers': json.dumps(dict(request.headers)),
        'attack_signature': attack_signature
    }
    return db.log_interaction(interaction_data)


@app.route('/')
def index():
    """Display fake login page"""
    # Create session for this request
    client_ip = get_client_ip()
    session = session_manager.create_session(
        source_ip=client_ip,
        source_port=request.environ.get('REMOTE_PORT', 0),
        dest_port=Config.HTTP_PORT,
        protocol='http',
        user_agent=request.headers.get('User-Agent')
    )

    # Store session in database
    db.create_session(session.to_dict())

    # Log this GET request
    log_http_interaction(session.session_id, 'benign')

    return render_template_string(LOGIN_PAGE, error=None)


@app.route('/login', methods=['POST'])
def login():
    """Handle login form submission and capture credentials"""
    client_ip = get_client_ip()

    # Create new session for this login attempt
    session = session_manager.create_session(
        source_ip=client_ip,
        source_port=request.environ.get('REMOTE_PORT', 0),
        dest_port=Config.HTTP_PORT,
        protocol='http',
        user_agent=request.headers.get('User-Agent')
    )

    # Store session
    db.create_session(session.to_dict())

    # Extract credentials
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Hash password with bcrypt (NEVER store plaintext)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Log authentication attempt
    auth_data = {
        'session_id': session.session_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'username': username,
        'password_hash': password_hash,
        'auth_method': 'form'
    }
    db.log_auth_attempt(auth_data)

    # Log the POST request
    log_http_interaction(session.session_id, 'credential_capture')

    # Always reject with fake error message
    return render_template_string(
        LOGIN_PAGE,
        error='Invalid username or password. Please try again.'
    )


@app.route('/admin')
@app.route('/admin/')
def admin():
    """Fake admin panel endpoint"""
    client_ip = get_client_ip()
    session = session_manager.create_session(
        source_ip=client_ip,
        source_port=request.environ.get('REMOTE_PORT', 0),
        dest_port=Config.HTTP_PORT,
        protocol='http',
        user_agent=request.headers.get('User-Agent')
    )

    db.create_session(session.to_dict())
    log_http_interaction(session.session_id, 'admin_probe')

    # Return fake 403 Forbidden
    return render_template_string('''
        <html>
        <head><title>403 Forbidden</title></head>
        <body>
        <h1>Forbidden</h1>
        <p>You don't have permission to access this resource.</p>
        <hr>
        <small>Apache/2.4.41 (Ubuntu) Server at internal.acme.corp Port 80</small>
        </body>
        </html>
    '''), 403


@app.errorhandler(404)
def not_found(error):
    """Log 404 attempts (path traversal, vulnerability scans)"""
    client_ip = get_client_ip()
    session = session_manager.create_session(
        source_ip=client_ip,
        source_port=request.environ.get('REMOTE_PORT', 0),
        dest_port=Config.HTTP_PORT,
        protocol='http',
        user_agent=request.headers.get('User-Agent')
    )

    db.create_session(session.to_dict())

    # Classify attack type based on path
    attack_sig = 'scan'
    path = request.path.lower()
    if '..' in path or 'etc/passwd' in path:
        attack_sig = 'lfi'
    elif 'wp-' in path or 'wordpress' in path:
        attack_sig = 'wordpress_scan'
    elif 'phpmy' in path or '.php' in path:
        attack_sig = 'php_scan'
    elif "'" in path or 'union' in path or 'select' in path:
        attack_sig = 'sqli'

    log_http_interaction(session.session_id, attack_sig)

    return render_template_string('''
        <html>
        <head><title>404 Not Found</title></head>
        <body>
        <h1>Not Found</h1>
        <p>The requested URL was not found on this server.</p>
        <hr>
        <small>Apache/2.4.41 (Ubuntu) Server at internal.acme.corp Port 80</small>
        </body>
        </html>
    '''), 404


def run_http_decoy():
    """Start the HTTP decoy server"""
    print(f"[*] Starting HTTP Decoy on {Config.HTTP_HOST}:{Config.HTTP_PORT}")
    print(f"[*] Database: {Config.DATABASE_PATH}")
    print(f"[*] Fake login portal ready - waiting for attackers...")

    app.run(
        host=Config.HTTP_HOST,
        port=Config.HTTP_PORT,
        debug=False,
        threaded=True
    )


if __name__ == '__main__':
    run_http_decoy()
