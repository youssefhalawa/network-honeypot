"""
Session state management (Member 1)

One shared SessionManager (get_session_manager()) is used by BOTH decoys, so:
  * the MAX_CONCURRENT_SESSIONS limit covers HTTP + SSH together
  * idle and maximum-duration timeouts are enforced in one place
  * all access is protected by a lock (decoys run many threads at once)
"""
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionLimitReached(Exception):
    """Raised when MAX_CONCURRENT_SESSIONS sessions are already open."""


class RateLimited(Exception):
    """Raised when one IP opens too many sessions in the rate-limit window."""


@dataclass
class Session:
    """Represents an active honeypot session"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_ip: str = ''
    source_port: int = 0
    dest_port: int = 0
    protocol: str = ''  # 'http' or 'ssh'
    started_at: str = field(default_factory=utc_now_iso)
    user_agent: Optional[str] = None
    ssh_client_version: Optional[str] = None
    interaction_count: int = 0
    # monotonic clock values: not affected by system clock changes
    _started_mono: float = field(default_factory=time.monotonic, repr=False)
    _last_activity_mono: float = field(default_factory=time.monotonic, repr=False)
    # set when the reaper decides this session must close
    close_reason: Optional[str] = None

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
            'ssh_client_version': self.ssh_client_version,
        }

    def touch(self):
        """Record activity (resets the idle timer)."""
        self._last_activity_mono = time.monotonic()
        self.interaction_count += 1

    def duration_seconds(self) -> float:
        return round(time.monotonic() - self._started_mono, 3)

    def idle_seconds(self) -> float:
        return time.monotonic() - self._last_activity_mono

    @property
    def should_close(self) -> bool:
        return self.close_reason is not None


class SessionManager:
    """Thread-safe registry of active sessions with limits and timeouts."""

    def __init__(self, max_sessions: int = 100, idle_timeout: int = 300, max_duration: int = 1800,
                 rate_limit: int = 30, rate_window: int = 60):
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self._sessions: Dict[str, Session] = {}
        self._recent_by_ip: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.RLock()

    # -- create / get / end -------------------------------------------------
    def create_session(self, source_ip: str, source_port: int, dest_port: int, protocol: str,
                       user_agent: Optional[str] = None, ssh_client_version: Optional[str] = None) -> Session:
        """Register a new session. Raises SessionLimitReached or RateLimited."""
        with self._lock:
            if len(self._sessions) >= self.max_sessions:
                raise SessionLimitReached(f"{self.max_sessions} sessions already open")

            now = time.monotonic()
            recent = self._recent_by_ip[source_ip]
            while recent and now - recent[0] > self.rate_window:
                recent.popleft()
            if len(recent) >= self.rate_limit:
                raise RateLimited(f"{source_ip} opened {len(recent)} sessions in {self.rate_window}s")
            recent.append(now)

            session = Session(source_ip=source_ip, source_port=int(source_port or 0), dest_port=dest_port,
                              protocol=protocol, user_agent=user_agent, ssh_client_version=ssh_client_version)
            self._sessions[session.session_id] = session
            return session

    def get_session(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def touch(self, session_id: str):
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.touch()

    def end_session(self, session_id: str) -> Optional[Session]:
        """Remove a session; returns it (or None if already ended) so callers
        can record the duration exactly once."""
        with self._lock:
            return self._sessions.pop(session_id, None)

    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def active_sessions(self) -> List[Session]:
        with self._lock:
            return list(self._sessions.values())

    # -- timeouts -----------------------------------------------------------
    def find_expired(self) -> List[Session]:
        """Mark and return sessions that went idle too long or ran too long.
        They stay registered until their decoy closes them (or end_all)."""
        expired = []
        with self._lock:
            for session in self._sessions.values():
                if session.close_reason:
                    continue
                if session.duration_seconds() > self.max_duration:
                    session.close_reason = 'max_duration'
                elif session.idle_seconds() > self.idle_timeout:
                    session.close_reason = 'idle_timeout'
                if session.close_reason:
                    expired.append(session)
            # forget rate-limit history of IPs that went quiet
            now = time.monotonic()
            for ip in [ip for ip, q in self._recent_by_ip.items() if not q or now - q[-1] > self.rate_window]:
                del self._recent_by_ip[ip]
        return expired

    def cleanup_old_sessions(self, max_age_seconds: Optional[int] = None) -> int:
        """Backwards-compatible helper: drop sessions older than max_age_seconds."""
        limit = self.max_duration if max_age_seconds is None else max_age_seconds
        with self._lock:
            old = [sid for sid, s in self._sessions.items() if s.duration_seconds() > limit]
            for sid in old:
                self._sessions.pop(sid, None)
        return len(old)

    def end_all(self) -> List[Session]:
        """Remove and return every open session (used at shutdown)."""
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            return sessions


# ---------------------------------------------------------------------------
# The single shared instance used by every part of the honeypot
# ---------------------------------------------------------------------------
_shared_manager: Optional[SessionManager] = None
_shared_lock = threading.Lock()


def get_session_manager() -> SessionManager:
    global _shared_manager
    with _shared_lock:
        if _shared_manager is None:
            from app.core.config import Config
            _shared_manager = SessionManager(
                max_sessions=Config.MAX_CONCURRENT_SESSIONS,
                idle_timeout=Config.SESSION_IDLE_TIMEOUT_SECONDS,
                max_duration=Config.SESSION_MAX_DURATION_SECONDS,
                rate_limit=Config.RATE_LIMIT_PER_IP,
                rate_window=Config.RATE_LIMIT_WINDOW_SECONDS,
            )
        return _shared_manager
