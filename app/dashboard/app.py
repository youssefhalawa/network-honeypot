"""
Analytics Dashboard (Member 6)

    python -m app.dashboard.app      (or DASHBOARD_ENABLED=true with app.main)
    open http://127.0.0.1:5000

Pages:  /                overview: live numbers, charts, origins, timeline
        /sessions        all sessions, 50 per page, sortable, HTTP/SSH filter
        /session/<id>    one session: logins, commands (terminal view), requests
API:    /api/stats  /api/sessions  /api/session/<id>  /api/timeline  /api/attack_types
        /api/origins  /api/geo_map
Export: /export/jsonl  /export/csv/<table>  /export/misp

The dashboard has no login, so by default it only listens on 127.0.0.1.
"""
import json
import logging
import math
from datetime import datetime, timezone

from flask import Flask, Response, abort, jsonify, render_template, request, url_for

from app.core.classifiers import get_http_mitre, get_risk_score, get_ssh_mitre
from app.core.config import Config
from app.core.webserver import serve_until_stopped
from app.storage.database import SESSION_SORT_COLUMNS, get_database
from app.storage.exporters import TABLES, to_csv, to_jsonl, to_misp

log = logging.getLogger('honeypot.dashboard')

app = Flask(__name__)
PAGE_SIZE = 50


def get_db():
    return get_database()


def int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
    """Read an integer query parameter safely (bad input -> default, clamped to a range)."""
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


@app.template_filter('short_time')
def short_time(value):
    if not value:
        return '-'
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return value


@app.template_filter('duration')
def duration(value):
    if value is None:
        return '-'
    seconds = float(value)
    if seconds < 60:
        return f'{seconds:.1f}s'
    return f'{int(seconds // 60)}m {int(seconds % 60)}s'


@app.template_filter('pretty_json')
def pretty_json(value):
    try:
        return json.dumps(json.loads(value), indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return value or ''


@app.context_processor
def helpers():
    return {'risk': get_risk_score, 'ssh_mitre': get_ssh_mitre, 'http_mitre': get_http_mitre}


def with_percent(rows, key='count'):
    """Add a 'pct' (0-100) to each row for CSS bar widths."""
    top = max((r[key] for r in rows), default=0) or 1
    return [{**r, 'pct': round(100 * r[key] / top, 1)} for r in rows]


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    db = get_db()
    stats = db.get_stats()
    attack_types = db.get_attack_types()
    timeline = db.get_timeline(24)
    return render_template(
        'dashboard.html', stats=stats,
        top_ips=with_percent(stats['top_ips'], 'session_count'),
        top_usernames=with_percent(stats['top_usernames'], 'attempt_count'),
        top_commands=with_percent(stats['top_commands']),
        ssh_types=with_percent(attack_types['ssh_commands']),
        http_types=with_percent(attack_types['http_attacks']),
        origins=with_percent(db.get_origins()[:15], 'session_count'),
        timeline=with_percent(timeline), timeline_total=sum(t['count'] for t in timeline),
    )


@app.route('/sessions')
def sessions_page():
    db = get_db()
    protocol = request.args.get('protocol') if request.args.get('protocol') in ('http', 'ssh') else None
    sort = request.args.get('sort') if request.args.get('sort') in SESSION_SORT_COLUMNS else 'started_at'
    order = 'asc' if request.args.get('order') == 'asc' else 'desc'
    total = db.count_sessions(protocol)
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = int_arg('page', 1, 1, pages)
    sessions = db.get_sessions(limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE, sort=sort, order=order,
                               protocol=protocol)

    def link(**changes):
        params = {'page': page, 'sort': sort, 'order': order, 'protocol': protocol or ''}
        params.update(changes)
        return url_for('sessions_page', **{k: v for k, v in params.items() if v not in ('', None)})

    return render_template('sessions.html', sessions=sessions, page=page, pages=pages, total=total,
                           sort=sort, order=order, protocol=protocol, link=link)


@app.route('/session/<session_id>')
def session_detail_page(session_id):
    session = get_db().get_session_details(session_id)
    if session is None:
        abort(404)
    return render_template('session_detail.html', session=session)


@app.errorhandler(404)
def not_found(_error):
    return render_template('base.html', not_found=True), 404


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------
@app.route('/api/stats')
def api_stats():
    stats = get_db().get_stats()
    stats['generated_at'] = datetime.now(timezone.utc).isoformat()
    return jsonify(stats)


@app.route('/api/sessions')
def api_sessions():
    limit = int_arg('limit', 50, 1, 500)
    offset = int_arg('offset', 0, 0, 10_000_000)
    protocol = request.args.get('protocol') if request.args.get('protocol') in ('http', 'ssh') else None
    db = get_db()
    return jsonify({
        'sessions': db.get_sessions(limit=limit, offset=offset, sort=request.args.get('sort', 'started_at'),
                                    order=request.args.get('order', 'desc'), protocol=protocol),
        'total': db.count_sessions(protocol), 'limit': limit, 'offset': offset,
    })


@app.route('/api/session/<session_id>')
def api_session_detail(session_id):
    session = get_db().get_session_details(session_id)
    if session is None:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(session)


@app.route('/api/timeline')
def api_timeline():
    return jsonify(get_db().get_timeline(int_arg('hours', 24, 1, 168)))


@app.route('/api/attack_types')
def api_attack_types():
    return jsonify(get_db().get_attack_types())


@app.route('/api/origins')
def api_origins():
    return jsonify(get_db().get_origins())


@app.route('/api/geo_map')
def api_geo_map():
    return jsonify(get_db().get_geo_points())


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------
def _download(body: str, filename: str, mimetype: str) -> Response:
    return Response(body, mimetype=mimetype, headers={'Content-Disposition': f'attachment; filename={filename}'})


def _stamp():
    return datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')


@app.route('/export/jsonl')
def export_jsonl():
    return _download(to_jsonl(get_db()), f'honeypot_events_{_stamp()}.jsonl', 'application/x-ndjson')


@app.route('/export/csv/<table>')
def export_csv(table):
    if table not in TABLES:
        abort(404)
    return _download(to_csv(get_db(), table), f'{table}_{_stamp()}.csv', 'text/csv')


@app.route('/export/misp')
def export_misp():
    return _download(json.dumps(to_misp(get_db()), indent=2, ensure_ascii=False),
                     f'misp_event_{_stamp()}.json', 'application/json')


# ---------------------------------------------------------------------------
def run_dashboard(stop_event=None):
    """Start the dashboard web server (stoppable when started from app/main.py)."""
    log.info('Dashboard on http://%s:%s', Config.DASHBOARD_HOST, Config.DASHBOARD_PORT)
    serve_until_stopped(app, Config.DASHBOARD_HOST, Config.DASHBOARD_PORT, stop_event)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    for note in Config.warnings():
        log.warning(note)
    try:
        run_dashboard()
    except OSError as exc:
        hint = (' On a Mac, port 5000 is used by AirPlay Receiver: set DASHBOARD_PORT=5050 in .env '
                '(or turn off AirPlay Receiver in System Settings).' if Config.DASHBOARD_PORT == 5000 else '')
        raise SystemExit(f'[x] Dashboard cannot use port {Config.DASHBOARD_PORT}: {exc}.{hint}')
