"""
Typed record definitions for the four database tables (Member 4).
They document the schema in Python and can be built from query rows:
    AuthAttempt.from_row(row_dict)
"""
from dataclasses import dataclass, fields
from typing import Any, Dict, Optional


class _Row:
    @classmethod
    def from_row(cls, row: Dict[str, Any]):
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in dict(row).items() if k in names})


@dataclass
class SessionRecord(_Row):
    session_id: str
    source_ip: str
    source_port: int
    dest_port: int
    protocol: str                      # 'http' | 'ssh'
    started_at: str                    # ISO 8601 UTC
    ended_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    user_agent: Optional[str] = None
    ssh_client_version: Optional[str] = None
    total_interactions: int = 0


@dataclass
class AuthAttempt(_Row):
    session_id: str
    timestamp: str
    username: str
    password_hash: Optional[str]       # bcrypt hash, never plain text
    auth_method: Optional[str]         # 'password' | 'form' | 'http_basic'
    success: int = 0                   # 1 when a weak SSH password let the attacker in
    attempt_id: Optional[int] = None


@dataclass
class Interaction(_Row):
    session_id: str
    timestamp: str
    interaction_type: str              # 'ssh_command' | 'ssh_exec' | 'http_request'
    command: Optional[str] = None
    command_classification: Optional[str] = None
    fake_output: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_query_params: Optional[str] = None   # JSON
    http_body: Optional[str] = None
    http_headers: Optional[str] = None        # JSON
    attack_signature: Optional[str] = None
    interaction_id: Optional[int] = None


@dataclass
class IPIntel(_Row):
    ip_address: str
    last_updated: str
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_tor: int = 0
    is_vpn: int = 0
    abuse_confidence_score: Optional[int] = None
    total_sessions: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
