"""
SQLite database operations with thread-safe access
"""
import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

class Database:
    """Thread-safe SQLite database wrapper"""

    def __init__(self, db_path: str = 'data/honeypot.db'):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_directory()
        self._init_schema()

    def _ensure_directory(self):
        """Create data directory if it doesn't exist"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with WAL mode enabled"""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.row_factory = sqlite3.Row  # Return rows as dict-like objects
        return conn

    def _init_schema(self):
        """Initialize database schema if tables don't exist"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Sessions table
            cursor.execute('''
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
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol)')

            # Auth attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_hash TEXT,
                    auth_method TEXT,
                    success INTEGER DEFAULT 0,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_attempts(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username)')

            # Interactions table
            cursor.execute('''
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
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_interactions_type ON interactions(interaction_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_interactions_classification ON interactions(command_classification)')

            # IP intel table
            cursor.execute('''
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
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_country ON ip_intel(country_code)')

            conn.commit()
            conn.close()

    def create_session(self, session_data: Dict[str, Any]) -> str:
        """Create a new session record"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO sessions (
                    session_id, source_ip, source_port, dest_port, protocol,
                    started_at, user_agent, ssh_client_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_data['session_id'],
                session_data['source_ip'],
                session_data['source_port'],
                session_data['dest_port'],
                session_data['protocol'],
                session_data['started_at'],
                session_data.get('user_agent'),
                session_data.get('ssh_client_version')
            ))

            conn.commit()
            conn.close()
            return session_data['session_id']

    def end_session(self, session_id: str, ended_at: str, duration_seconds: float):
        """Mark a session as ended"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE sessions
                SET ended_at = ?, duration_seconds = ?
                WHERE session_id = ?
            ''', (ended_at, duration_seconds, session_id))

            conn.commit()
            conn.close()

    def log_auth_attempt(self, auth_data: Dict[str, Any]) -> int:
        """Log an authentication attempt"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO auth_attempts (
                    session_id, timestamp, username, password_hash, auth_method, success
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                auth_data['session_id'],
                auth_data['timestamp'],
                auth_data['username'],
                auth_data['password_hash'],
                auth_data['auth_method'],
                0  # Always fail in honeypot
            ))

            attempt_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return attempt_id

    def log_interaction(self, interaction_data: Dict[str, Any]) -> int:
        """Log an HTTP request or SSH command"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO interactions (
                    session_id, timestamp, interaction_type,
                    command, command_classification, fake_output,
                    http_method, http_path, http_query_params, http_body, http_headers,
                    attack_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                interaction_data['session_id'],
                interaction_data['timestamp'],
                interaction_data['interaction_type'],
                interaction_data.get('command'),
                interaction_data.get('command_classification'),
                interaction_data.get('fake_output'),
                interaction_data.get('http_method'),
                interaction_data.get('http_path'),
                interaction_data.get('http_query_params'),
                interaction_data.get('http_body'),
                interaction_data.get('http_headers'),
                interaction_data.get('attack_signature')
            ))

            # Update total_interactions count
            cursor.execute('''
                UPDATE sessions
                SET total_interactions = total_interactions + 1
                WHERE session_id = ?
            ''', (interaction_data['session_id'],))

            interaction_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return interaction_id

    def get_sessions(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Retrieve sessions with pagination"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM sessions
                ORDER BY started_at DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))

            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]

    def get_session_details(self, session_id: str) -> Optional[Dict]:
        """Get full details for a session including auth attempts and interactions"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Get session
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            session = cursor.fetchone()

            if not session:
                conn.close()
                return None

            session_dict = dict(session)

            # Get auth attempts
            cursor.execute('''
                SELECT * FROM auth_attempts WHERE session_id = ? ORDER BY timestamp
            ''', (session_id,))
            session_dict['auth_attempts'] = [dict(row) for row in cursor.fetchall()]

            # Get interactions
            cursor.execute('''
                SELECT * FROM interactions WHERE session_id = ? ORDER BY timestamp
            ''', (session_id,))
            session_dict['interactions'] = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return session_dict

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics for dashboard"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            stats = {}

            # Total sessions
            cursor.execute('SELECT COUNT(*) as count FROM sessions')
            stats['total_sessions'] = cursor.fetchone()['count']

            # Unique IPs
            cursor.execute('SELECT COUNT(DISTINCT source_ip) as count FROM sessions')
            stats['unique_ips'] = cursor.fetchone()['count']

            # Total credentials captured
            cursor.execute('SELECT COUNT(*) as count FROM auth_attempts')
            stats['credentials_captured'] = cursor.fetchone()['count']

            # Active sessions
            cursor.execute('SELECT COUNT(*) as count FROM sessions WHERE ended_at IS NULL')
            stats['active_sessions'] = cursor.fetchone()['count']

            # Top source IPs
            cursor.execute('''
                SELECT source_ip, COUNT(*) as session_count
                FROM sessions
                GROUP BY source_ip
                ORDER BY session_count DESC
                LIMIT 10
            ''')
            stats['top_ips'] = [dict(row) for row in cursor.fetchall()]

            # Top usernames
            cursor.execute('''
                SELECT username, COUNT(*) as attempt_count
                FROM auth_attempts
                GROUP BY username
                ORDER BY attempt_count DESC
                LIMIT 10
            ''')
            stats['top_usernames'] = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return stats

    @staticmethod
    def utc_now() -> str:
        """Return current UTC timestamp in ISO 8601 format"""
        return datetime.now(timezone.utc).isoformat()
