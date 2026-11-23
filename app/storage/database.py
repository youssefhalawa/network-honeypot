"""
SQLite storage layer (Member 4)

* WAL mode so the dashboard can read while the decoys write
* One lock per database file (shared by every Database object for that file),
  so HTTP, SSH and the dashboard never write at the same moment
* Connections are always closed, even when a query fails
* Passwords are never stored in plain text: callers pass a bcrypt hash
"""
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

_FILE_LOCKS: Dict[str, threading.RLock] = {}
_FILE_LOCKS_GUARD = threading.Lock()

# Columns the sessions page may be sorted by (anything else is ignored)
SESSION_SORT_COLUMNS = {
    'started_at', 'source_ip', 'protocol', 'duration_seconds', 'total_interactions', 'dest_port',
}


def _lock_for(path: str) -> threading.RLock:
    key = str(Path(path).resolve())
    with _FILE_LOCKS_GUARD:
        if key not in _FILE_LOCKS:
            _FILE_LOCKS[key] = threading.RLock()
        return _FILE_LOCKS[key]


class Database:
    """Thread-safe SQLite database wrapper"""

    def __init__(self, db_path: str = 'data/honeypot.db'):
        self.db_path = str(db_path)
        self._lock = _lock_for(self.db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------
    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connect(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        """Open a connection under the shared lock; commit on success, always close."""
        with self._lock:
            conn = self._get_connection()
            try:
                yield conn
                if write:
                    conn.commit()
            except Exception:
                if write:
                    conn.rollback()
                raise
            finally:
                conn.close()

    def _init_schema(self):
        with self._connect(write=True) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    dest_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    duration_seconds REAL,
                    user_agent TEXT,
                    ssh_client_version TEXT,
                    total_interactions INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(source_ip);
                CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
                CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol);

                CREATE TABLE IF NOT EXISTS auth_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_hash TEXT,
                    auth_method TEXT,
                    success INTEGER DEFAULT 0,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_attempts(session_id);
                CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username);

                CREATE TABLE IF NOT EXISTS interactions (
                    interaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    interaction_type TEXT NOT NULL,
                    command TEXT,
                    command_classification TEXT,
                    fake_output TEXT,
                    http_method TEXT,
                    http_path TEXT,
                    http_query_params TEXT,
                    http_body TEXT,
                    http_headers TEXT,
                    attack_signature TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id);
                CREATE INDEX IF NOT EXISTS idx_interactions_type ON interactions(interaction_type);
                CREATE INDEX IF NOT EXISTS idx_interactions_classification ON interactions(command_classification);
                CREATE INDEX IF NOT EXISTS idx_interactions_timestamp ON interactions(timestamp);

                CREATE TABLE IF NOT EXISTS ip_intel (
                    ip_address TEXT PRIMARY KEY,
                    last_updated TEXT NOT NULL,
                    country_code TEXT,
                    country_name TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    asn INTEGER,
                    asn_org TEXT,
                    is_tor INTEGER DEFAULT 0,
                    is_vpn INTEGER DEFAULT 0,
                    abuse_confidence_score INTEGER,
                    total_sessions INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_ip_country ON ip_intel(country_code);
            ''')

    @staticmethod
    def utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def create_session(self, session_data: Dict[str, Any]) -> str:
        with self._connect(write=True) as conn:
            conn.execute('''
                INSERT INTO sessions (session_id, source_ip, source_port, dest_port, protocol,
                                      started_at, user_agent, ssh_client_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_data['session_id'], session_data['source_ip'], session_data['source_port'],
                session_data['dest_port'], session_data['protocol'], session_data['started_at'],
                session_data.get('user_agent'), session_data.get('ssh_client_version'),
            ))
        return session_data['session_id']

    def update_session_client(self, session_id: str, ssh_client_version: Optional[str] = None,
                              user_agent: Optional[str] = None):
        """Fill in client details learned after the session started (e.g. SSH version)."""
        with self._connect(write=True) as conn:
            conn.execute('''
                UPDATE sessions SET ssh_client_version = COALESCE(?, ssh_client_version),
                                    user_agent = COALESCE(?, user_agent)
                WHERE session_id = ?
            ''', (ssh_client_version, user_agent, session_id))

    def end_session(self, session_id: str, ended_at: str, duration_seconds: float):
        """Mark a session as ended (only the first call counts)."""
        with self._connect(write=True) as conn:
            conn.execute('''
                UPDATE sessions SET ended_at = ?, duration_seconds = ?
                WHERE session_id = ? AND ended_at IS NULL
            ''', (ended_at, duration_seconds, session_id))

    def close_open_sessions(self) -> int:
        """Close sessions left open by a crash or power cut. Run at start-up and shutdown."""
        now = self.utc_now()
        with self._connect(write=True) as conn:
            cur = conn.execute('''
                UPDATE sessions
                SET ended_at = ?,
                    duration_seconds = MAX(0, (julianday(?) - julianday(started_at)) * 86400.0)
                WHERE ended_at IS NULL
            ''', (now, now))
            return cur.rowcount

    def log_auth_attempt(self, auth_data: Dict[str, Any]) -> int:
        """auth_data['password_hash'] must already be a bcrypt hash."""
        with self._connect(write=True) as conn:
            cur = conn.execute('''
                INSERT INTO auth_attempts (session_id, timestamp, username, password_hash, auth_method, success)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                auth_data['session_id'], auth_data['timestamp'], auth_data['username'],
                auth_data['password_hash'], auth_data['auth_method'], 1 if auth_data.get('success') else 0,
            ))
            return cur.lastrowid

    def log_interaction(self, interaction_data: Dict[str, Any]) -> int:
        with self._connect(write=True) as conn:
            cur = conn.execute('''
                INSERT INTO interactions (
                    session_id, timestamp, interaction_type,
                    command, command_classification, fake_output,
                    http_method, http_path, http_query_params, http_body, http_headers,
                    attack_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                interaction_data['session_id'], interaction_data['timestamp'], interaction_data['interaction_type'],
                interaction_data.get('command'), interaction_data.get('command_classification'),
                interaction_data.get('fake_output'), interaction_data.get('http_method'),
                interaction_data.get('http_path'), interaction_data.get('http_query_params'),
                interaction_data.get('http_body'), interaction_data.get('http_headers'),
                interaction_data.get('attack_signature'),
            ))
            interaction_id = cur.lastrowid
            conn.execute('UPDATE sessions SET total_interactions = total_interactions + 1 WHERE session_id = ?',
                         (interaction_data['session_id'],))
            return interaction_id

    def upsert_ip_intel(self, intel: Dict[str, Any]):
        """Insert or refresh enrichment data for an IP and count one more session."""
        now = self.utc_now()
        with self._connect(write=True) as conn:
            conn.execute('''
                INSERT INTO ip_intel (ip_address, last_updated, country_code, country_name, city,
                                      latitude, longitude, asn, asn_org, is_tor, is_vpn,
                                      total_sessions, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_updated = excluded.last_updated,
                    country_code = excluded.country_code,
                    country_name = excluded.country_name,
                    city = excluded.city,
                    latitude = excluded.latitude,
                    longitude = excluded.longitude,
                    asn = excluded.asn,
                    asn_org = excluded.asn_org,
                    is_tor = excluded.is_tor,
                    is_vpn = excluded.is_vpn,
                    total_sessions = ip_intel.total_sessions + 1,
                    last_seen = excluded.last_seen
            ''', (
                intel['ip_address'], intel.get('last_updated') or now, intel.get('country_code'),
                intel.get('country_name'), intel.get('city'), intel.get('latitude'), intel.get('longitude'),
                intel.get('asn'), intel.get('asn_org'), int(bool(intel.get('is_tor'))),
                int(bool(intel.get('is_vpn'))), now, now,
            ))

    def record_ip_seen(self, ip: str):
        """Count a session for an IP whose enrichment is still fresh (no new lookup)."""
        now = self.utc_now()
        with self._connect(write=True) as conn:
            conn.execute('UPDATE ip_intel SET total_sessions = total_sessions + 1, last_seen = ? WHERE ip_address = ?',
                         (now, ip))

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def get_ip_intel(self, ip: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM ip_intel WHERE ip_address = ?', (ip,)).fetchone()
            return dict(row) if row else None

    def ip_intel_is_fresh(self, ip: str, max_age_hours: int) -> bool:
        row = self.get_ip_intel(ip)
        if not row:
            return False
        try:
            updated = datetime.fromisoformat(row['last_updated'])
        except (TypeError, ValueError):
            return False
        return datetime.now(timezone.utc) - updated < timedelta(hours=max_age_hours)

    def count_sessions(self, protocol: Optional[str] = None) -> int:
        with self._connect() as conn:
            if protocol:
                return conn.execute('SELECT COUNT(*) FROM sessions WHERE protocol = ?', (protocol,)).fetchone()[0]
            return conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]

    def get_sessions(self, limit: int = 100, offset: int = 0, sort: str = 'started_at',
                     order: str = 'desc', protocol: Optional[str] = None) -> List[Dict]:
        """Sessions with pagination, sorting and an optional protocol filter.
        Each row also carries the country from ip_intel when known."""
        sort = sort if sort in SESSION_SORT_COLUMNS else 'started_at'
        order = 'ASC' if str(order).lower() == 'asc' else 'DESC'
        where, params = '', []
        if protocol in ('http', 'ssh'):
            where, params = 'WHERE s.protocol = ?', [protocol]
        with self._connect() as conn:
            rows = conn.execute(f'''
                SELECT s.*, i.country_code, i.country_name, i.city
                FROM sessions s LEFT JOIN ip_intel i ON i.ip_address = s.source_ip
                {where}
                ORDER BY s.{sort} {order}, s.started_at DESC
                LIMIT ? OFFSET ?
            ''', (*params, int(limit), int(offset))).fetchall()
            return [dict(r) for r in rows]

    def get_session_details(self, session_id: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute('''
                SELECT s.*, i.country_code, i.country_name, i.city, i.asn, i.asn_org
                FROM sessions s LEFT JOIN ip_intel i ON i.ip_address = s.source_ip
                WHERE s.session_id = ?
            ''', (session_id,)).fetchone()
            if not row:
                return None
            details = dict(row)
            details['auth_attempts'] = [dict(r) for r in conn.execute(
                'SELECT * FROM auth_attempts WHERE session_id = ? ORDER BY timestamp, attempt_id', (session_id,))]
            details['interactions'] = [dict(r) for r in conn.execute(
                'SELECT * FROM interactions WHERE session_id = ? ORDER BY timestamp, interaction_id', (session_id,))]
            return details

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate numbers for the dashboard overview."""
        with self._connect() as conn:
            one = lambda sql, *a: conn.execute(sql, a).fetchone()[0]  # noqa: E731
            stats = {
                'total_sessions': one('SELECT COUNT(*) FROM sessions'),
                'http_sessions': one("SELECT COUNT(*) FROM sessions WHERE protocol = 'http'"),
                'ssh_sessions': one("SELECT COUNT(*) FROM sessions WHERE protocol = 'ssh'"),
                'unique_ips': one('SELECT COUNT(DISTINCT source_ip) FROM sessions'),
                'credentials_captured': one('SELECT COUNT(*) FROM auth_attempts'),
                'successful_logins': one('SELECT COUNT(*) FROM auth_attempts WHERE success = 1'),
                'commands_captured': one("SELECT COUNT(*) FROM interactions WHERE interaction_type = 'ssh_command'"),
                'http_requests': one("SELECT COUNT(*) FROM interactions WHERE interaction_type = 'http_request'"),
                'active_sessions': one('SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL'),
                'countries': one("SELECT COUNT(DISTINCT country_code) FROM ip_intel "
                                 "WHERE country_code NOT IN ('PRIVATE','RESERVED','OFFLINE','UNKNOWN','ERROR')"),
            }
            stats['top_ips'] = [dict(r) for r in conn.execute('''
                SELECT s.source_ip, COUNT(*) AS session_count, MAX(i.country_code) AS country_code
                FROM sessions s LEFT JOIN ip_intel i ON i.ip_address = s.source_ip
                GROUP BY s.source_ip ORDER BY session_count DESC LIMIT 10''')]
            stats['top_usernames'] = [dict(r) for r in conn.execute('''
                SELECT username, COUNT(*) AS attempt_count FROM auth_attempts
                GROUP BY username ORDER BY attempt_count DESC LIMIT 10''')]
            stats['top_commands'] = [dict(r) for r in conn.execute('''
                SELECT command, COUNT(*) AS count FROM interactions
                WHERE interaction_type = 'ssh_command' AND command IS NOT NULL
                  AND command NOT IN ('exit', 'logout', 'quit')
                GROUP BY command ORDER BY count DESC LIMIT 10''')]
            return stats

    def get_attack_types(self) -> Dict[str, List[Dict]]:
        with self._connect() as conn:
            ssh = [dict(r) for r in conn.execute('''
                SELECT command_classification AS label, COUNT(*) AS count FROM interactions
                WHERE interaction_type = 'ssh_command' AND command_classification IS NOT NULL
                GROUP BY command_classification ORDER BY count DESC''')]
            http = [dict(r) for r in conn.execute('''
                SELECT attack_signature AS label, COUNT(*) AS count FROM interactions
                WHERE interaction_type = 'http_request' AND attack_signature IS NOT NULL
                GROUP BY attack_signature ORDER BY count DESC''')]
            return {'ssh_commands': ssh, 'http_attacks': http}

    def get_timeline(self, hours: int = 24) -> List[Dict]:
        """Sessions per hour for the last `hours` hours (empty hours included as 0)."""
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        with self._connect() as conn:
            rows = conn.execute('''
                SELECT started_at FROM sessions WHERE started_at >= ?
            ''', (start.isoformat(),)).fetchall()
        buckets = {(start + timedelta(hours=h)).strftime('%Y-%m-%d %H:00'): 0 for h in range(hours)}
        for (started_at,) in rows:
            try:
                key = datetime.fromisoformat(started_at).astimezone(timezone.utc).strftime('%Y-%m-%d %H:00')
            except (TypeError, ValueError):
                continue
            if key in buckets:
                buckets[key] += 1
        return [{'timestamp': k, 'count': v} for k, v in buckets.items()]

    def get_origins(self) -> List[Dict]:
        """Sessions grouped by country (the 'source origin mapping')."""
        with self._connect() as conn:
            return [dict(r) for r in conn.execute('''
                SELECT COALESCE(i.country_code, 'PENDING') AS country_code,
                       COALESCE(i.country_name, 'Not looked up yet') AS country_name,
                       COUNT(s.session_id) AS session_count,
                       COUNT(DISTINCT s.source_ip) AS ip_count
                FROM sessions s LEFT JOIN ip_intel i ON i.ip_address = s.source_ip
                GROUP BY 1, 2 ORDER BY session_count DESC''')]

    def get_geo_points(self) -> List[Dict]:
        """Locations with coordinates, for a map."""
        with self._connect() as conn:
            return [dict(r) for r in conn.execute('''
                SELECT i.country_code, i.country_name, i.city, i.latitude, i.longitude,
                       COUNT(s.session_id) AS session_count
                FROM ip_intel i JOIN sessions s ON s.source_ip = i.ip_address
                WHERE i.latitude IS NOT NULL AND i.longitude IS NOT NULL
                GROUP BY i.country_code, i.country_name, i.city, i.latitude, i.longitude
                ORDER BY session_count DESC''')]

    def iter_table(self, table: str) -> Iterator[Dict]:
        """Yield every row of one table (used by scripts/export_logs.py)."""
        if table not in ('sessions', 'auth_attempts', 'interactions', 'ip_intel'):
            raise ValueError(f'unknown table {table}')
        with self._connect() as conn:
            for row in conn.execute(f'SELECT * FROM {table}'):
                yield dict(row)


# ---------------------------------------------------------------------------
# Shared instance
# ---------------------------------------------------------------------------
_shared_db: Optional[Database] = None
_shared_db_lock = threading.Lock()


def get_database() -> Database:
    """The one Database object used by the decoys and the dashboard."""
    global _shared_db
    with _shared_db_lock:
        if _shared_db is None:
            from app.core.config import Config
            _shared_db = Database(Config.DATABASE_PATH)
        return _shared_db
