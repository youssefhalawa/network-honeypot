"""
Analytics Dashboard Application
Web-based interface for viewing honeypot telemetry and statistics
"""
from flask import Flask, render_template, jsonify, request
from datetime import datetime, timezone, timedelta
import json

from app.core.config import Config
from app.storage.database import Database

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dashboard-secret-key-change-in-production'

# Initialize database
db = Database(Config.DATABASE_PATH)


@app.route('/')
def index():
    """Dashboard home page with overview statistics"""
    stats = db.get_stats()

    return render_template('dashboard.html', stats=stats)


@app.route('/api/stats')
def api_stats():
    """JSON API endpoint for statistics"""
    stats = db.get_stats()
    return jsonify(stats)


@app.route('/api/sessions')
def api_sessions():
    """JSON API endpoint for session list with pagination"""
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))

    sessions = db.get_sessions(limit=limit, offset=offset)
    return jsonify({
        'sessions': sessions,
        'limit': limit,
        'offset': offset
    })


@app.route('/api/session/<session_id>')
def api_session_detail(session_id):
    """JSON API endpoint for session details"""
    session = db.get_session_details(session_id)

    if session is None:
        return jsonify({'error': 'Session not found'}), 404

    return jsonify(session)


@app.route('/api/timeline')
def api_timeline():
    """JSON API endpoint for attack timeline data"""
    # Get last 24 hours of activity
    hours = int(request.args.get('hours', 24))

    # This is a simplified version - you can enhance with actual time-series queries
    sessions = db.get_sessions(limit=1000)

    # Group by hour
    timeline_data = {}
    for session in sessions:
        if not session.get('started_at'):
            continue

        try:
            dt = datetime.fromisoformat(session['started_at'])
            hour_key = dt.strftime('%Y-%m-%d %H:00')

            if hour_key not in timeline_data:
                timeline_data[hour_key] = 0
            timeline_data[hour_key] += 1
        except:
            continue

    # Convert to sorted list
    timeline = [
        {'timestamp': k, 'count': v}
        for k, v in sorted(timeline_data.items())
    ]

    return jsonify(timeline[-hours:])


@app.route('/api/attack_types')
def api_attack_types():
    """JSON API endpoint for attack type distribution"""
    # Query interaction classifications
    with db._lock:
        conn = db._get_connection()
        cursor = conn.cursor()

        # SSH command classifications
        cursor.execute('''
            SELECT command_classification, COUNT(*) as count
            FROM interactions
            WHERE interaction_type = 'ssh_command' AND command_classification IS NOT NULL
            GROUP BY command_classification
            ORDER BY count DESC
        ''')
        ssh_data = [dict(row) for row in cursor.fetchall()]

        # HTTP attack signatures
        cursor.execute('''
            SELECT attack_signature, COUNT(*) as count
            FROM interactions
            WHERE interaction_type = 'http_request' AND attack_signature IS NOT NULL
            GROUP BY attack_signature
            ORDER BY count DESC
        ''')
        http_data = [dict(row) for row in cursor.fetchall()]

        conn.close()

    return jsonify({
        'ssh_commands': ssh_data,
        'http_attacks': http_data
    })


@app.route('/api/geo_map')
def api_geo_map():
    """JSON API endpoint for geographic map data"""
    with db._lock:
        conn = db._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                i.country_code,
                i.country_name,
                i.latitude,
                i.longitude,
                COUNT(s.session_id) as session_count
            FROM ip_intel i
            JOIN sessions s ON s.source_ip = i.ip_address
            WHERE i.latitude IS NOT NULL AND i.longitude IS NOT NULL
            GROUP BY i.country_code, i.country_name, i.latitude, i.longitude
            ORDER BY session_count DESC
        ''')

        geo_data = [dict(row) for row in cursor.fetchall()]
        conn.close()

    return jsonify(geo_data)


@app.route('/sessions')
def sessions_page():
    """Session list page"""
    sessions = db.get_sessions(limit=100)
    return render_template('sessions.html', sessions=sessions)


@app.route('/session/<session_id>')
def session_detail_page(session_id):
    """Session detail page"""
    session = db.get_session_details(session_id)

    if session is None:
        return "Session not found", 404

    return render_template('session_detail.html', session=session)


def run_dashboard():
    """Start the dashboard web server"""
    print(f"[*] Starting Analytics Dashboard on {Config.DASHBOARD_HOST}:{Config.DASHBOARD_PORT}")
    print(f"[*] Open: http://{Config.DASHBOARD_HOST}:{Config.DASHBOARD_PORT}")

    app.run(
        host=Config.DASHBOARD_HOST,
        port=Config.DASHBOARD_PORT,
        debug=False,
        threaded=True
    )


if __name__ == '__main__':
    run_dashboard()
