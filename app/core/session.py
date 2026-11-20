"""
Session state management
Tracks active connections and metadata
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Session:
    """Represents an active honeypot session"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_ip: str = ''
    source_port: int = 0
    dest_port: int = 0
    protocol: str = ''  # 'http' or 'ssh'
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    user_agent: Optional[str] = None
    ssh_client_version: Optional[str] = None
    interaction_count: int = 0

    def to_dict(self) -> Dict:
        """Convert session to dictionary for database storage"""
        return {
            'session_id': self.session_id,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'started_at': self.started_at,
            'user_agent': self.user_agent,
            'ssh_client_version': self.ssh_client_version
        }

    def duration_seconds(self) -> float:
        """Calculate session duration from start until now"""
        started = datetime.fromisoformat(self.started_at)
        now = datetime.now(timezone.utc)
        return (now - started).total_seconds()


class SessionManager:
    """Manages active honeypot sessions"""

    def __init__(self):
        self._sessions: Dict[str, Session] = {}

    def create_session(
        self,
        source_ip: str,
        source_port: int,
        dest_port: int,
        protocol: str,
        user_agent: Optional[str] = None,
        ssh_client_version: Optional[str] = None
    ) -> Session:
        """Create and register a new session"""
        session = Session(
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            user_agent=user_agent,
            ssh_client_version=ssh_client_version
        )
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Retrieve a session by ID"""
        return self._sessions.get(session_id)

    def end_session(self, session_id: str):
        """Remove session from active tracking"""
        self._sessions.pop(session_id, None)

    def active_session_count(self) -> int:
        """Return count of currently active sessions"""
        return len(self._sessions)

    def cleanup_old_sessions(self, max_age_seconds: int = 1800):
        """Remove sessions older than specified age"""
        now = datetime.now(timezone.utc)
        to_remove = []

        for session_id, session in self._sessions.items():
            started = datetime.fromisoformat(session.started_at)
            age = (now - started).total_seconds()
            if age > max_age_seconds:
                to_remove.append(session_id)

        for session_id in to_remove:
            self.end_session(session_id)

        return len(to_remove)
