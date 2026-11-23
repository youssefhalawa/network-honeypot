"""
Honeypot configuration management (Member 1)

Loads settings from environment variables and the project's .env file.
Bad values never crash the import: they fall back to the default and are
reported by Config.validate(), which main.py runs before anything starts.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# Project root (the folder that contains app/, scripts/, .env)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / '.env')

# Problems found while reading settings; reported by Config.validate()
_PARSE_ERRORS = []


def _get_str(name, default):
    value = os.getenv(name)
    return default if value is None or value.strip() == '' else value.strip()


def _get_int(name, default):
    raw = os.getenv(name)
    if raw is None or raw.strip() == '':
        return default
    try:
        return int(raw.strip())
    except ValueError:
        _PARSE_ERRORS.append(f"{name}={raw!r} is not a whole number (using default {default})")
        return default


def _get_bool(name, default):
    raw = os.getenv(name)
    if raw is None or raw.strip() == '':
        return default
    value = raw.strip().lower()
    if value in ('1', 'true', 'yes', 'on'):
        return True
    if value in ('0', 'false', 'no', 'off'):
        return False
    _PARSE_ERRORS.append(f"{name}={raw!r} should be true or false (using default {default})")
    return default


def _get_path(name, default):
    """Relative paths are resolved from the project root, not the current folder,
    so the honeypot and the dashboard always use the same database."""
    path = Path(_get_str(name, default)).expanduser()
    return str(path if path.is_absolute() else BASE_DIR / path)


def _get_credentials(name, default):
    """Parse 'user:pass,user:pass' into a set of (user, pass) tuples."""
    pairs = set()
    for item in _get_str(name, default).split(','):
        item = item.strip()
        if not item:
            continue
        if ':' not in item:
            _PARSE_ERRORS.append(f"{name}: '{item}' should look like user:password")
            continue
        user, password = item.split(':', 1)
        pairs.add((user.strip(), password.strip()))
    return pairs


DEFAULT_WEAK_CREDENTIALS = (
    'root:root,root:toor,root:123456,root:password,root:admin,'
    'admin:admin,admin:password,admin:123456,ubuntu:ubuntu,'
    'user:user,test:test,guest:guest,pi:raspberry,oracle:oracle'
)


class Config:
    """Centralized configuration"""

    BASE_DIR = str(BASE_DIR)

    # HTTP Decoy
    HTTP_DECOY_ENABLED = _get_bool('HTTP_DECOY_ENABLED', True)
    HTTP_PORT = _get_int('HTTP_PORT', 8080)
    HTTP_HOST = _get_str('HTTP_HOST', '0.0.0.0')
    TRUST_PROXY_HEADERS = _get_bool('TRUST_PROXY_HEADERS', False)

    # SSH Decoy
    SSH_DECOY_ENABLED = _get_bool('SSH_DECOY_ENABLED', True)
    SSH_PORT = _get_int('SSH_PORT', 2222)
    SSH_HOST = _get_str('SSH_HOST', '0.0.0.0')
    SSH_HOST_KEY_PATH = _get_path('SSH_HOST_KEY_PATH', 'data/ssh_host_rsa_key')
    # Weak passwords that "work", so attackers reach the fake shell.
    # Every attempt (accepted or not) is logged.
    SSH_ACCEPTED_CREDENTIALS = _get_credentials('SSH_ACCEPTED_CREDENTIALS', DEFAULT_WEAK_CREDENTIALS)

    # Database
    DATABASE_PATH = _get_path('DATABASE_PATH', 'data/honeypot.db')

    # Session Limits
    MAX_CONCURRENT_SESSIONS = _get_int('MAX_CONCURRENT_SESSIONS', 100)
    SESSION_IDLE_TIMEOUT_SECONDS = _get_int('SESSION_IDLE_TIMEOUT_SECONDS', 300)
    SESSION_MAX_DURATION_SECONDS = _get_int('SESSION_MAX_DURATION_SECONDS', 1800)
    MAX_OUTPUT_BYTES = _get_int('MAX_OUTPUT_BYTES', 4096)

    # Rate Limiting (connections per IP per window; extra connections are dropped)
    RATE_LIMIT_PER_IP = _get_int('RATE_LIMIT_PER_IP', 120)
    RATE_LIMIT_WINDOW_SECONDS = _get_int('RATE_LIMIT_WINDOW_SECONDS', 60)

    # IP Enrichment
    GEOIP_DB_PATH = _get_path('GEOIP_DB_PATH', 'data/GeoLite2-City.mmdb')
    GEOIP_ASN_DB_PATH = _get_path('GEOIP_ASN_DB_PATH', 'data/GeoLite2-ASN.mmdb')
    IP_INTEL_CACHE_HOURS = _get_int('IP_INTEL_CACHE_HOURS', 24)

    # Dashboard
    DASHBOARD_ENABLED = _get_bool('DASHBOARD_ENABLED', False)
    DASHBOARD_PORT = _get_int('DASHBOARD_PORT', 5000)
    DASHBOARD_HOST = _get_str('DASHBOARD_HOST', '127.0.0.1')

    # Logging
    LOG_LEVEL = _get_str('LOG_LEVEL', 'INFO').upper()
    LOG_FILE = _get_path('LOG_FILE', 'data/logs/honeypot.log')

    # Deployment
    RUN_AS_USER = _get_str('RUN_AS_USER', 'honeypot')

    @classmethod
    def validate(cls):
        """Check every setting. Raises ValueError listing ALL problems at once."""
        errors = list(_PARSE_ERRORS)

        ports = {'HTTP_PORT': cls.HTTP_PORT, 'SSH_PORT': cls.SSH_PORT, 'DASHBOARD_PORT': cls.DASHBOARD_PORT}
        for name, port in ports.items():
            if not 1 <= port <= 65535:
                errors.append(f"{name}={port} must be between 1 and 65535")

        in_use = []
        if cls.HTTP_DECOY_ENABLED:
            in_use.append(('HTTP_PORT', cls.HTTP_PORT))
        if cls.SSH_DECOY_ENABLED:
            in_use.append(('SSH_PORT', cls.SSH_PORT))
        if cls.DASHBOARD_ENABLED:
            in_use.append(('DASHBOARD_PORT', cls.DASHBOARD_PORT))
        for i, (name_a, port_a) in enumerate(in_use):
            for name_b, port_b in in_use[i + 1:]:
                if port_a == port_b:
                    errors.append(f"{name_a} and {name_b} cannot both be {port_a}")

        if not cls.HTTP_DECOY_ENABLED and not cls.SSH_DECOY_ENABLED:
            errors.append("At least one decoy (HTTP or SSH) must be enabled")

        positive = {
            'MAX_CONCURRENT_SESSIONS': cls.MAX_CONCURRENT_SESSIONS,
            'SESSION_IDLE_TIMEOUT_SECONDS': cls.SESSION_IDLE_TIMEOUT_SECONDS,
            'SESSION_MAX_DURATION_SECONDS': cls.SESSION_MAX_DURATION_SECONDS,
            'MAX_OUTPUT_BYTES': cls.MAX_OUTPUT_BYTES,
            'RATE_LIMIT_PER_IP': cls.RATE_LIMIT_PER_IP,
            'RATE_LIMIT_WINDOW_SECONDS': cls.RATE_LIMIT_WINDOW_SECONDS,
        }
        for name, value in positive.items():
            if value <= 0:
                errors.append(f"{name}={value} must be greater than 0")

        if cls.SESSION_IDLE_TIMEOUT_SECONDS > cls.SESSION_MAX_DURATION_SECONDS:
            errors.append("SESSION_IDLE_TIMEOUT_SECONDS cannot be longer than SESSION_MAX_DURATION_SECONDS")

        if cls.LOG_LEVEL not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
            errors.append(f"LOG_LEVEL={cls.LOG_LEVEL} must be DEBUG, INFO, WARNING, ERROR or CRITICAL")

        if cls.SSH_DECOY_ENABLED and not cls.SSH_ACCEPTED_CREDENTIALS:
            errors.append("SSH_ACCEPTED_CREDENTIALS is empty: attackers could never reach the fake shell")

        if errors:
            raise ValueError("Configuration errors:\n  - " + "\n  - ".join(errors))
        return True

    @classmethod
    def warnings(cls):
        """Non-fatal advice shown at start-up."""
        notes = []
        if cls.DASHBOARD_ENABLED and cls.DASHBOARD_HOST not in ('127.0.0.1', 'localhost', '::1'):
            notes.append(f"Dashboard is reachable from the network ({cls.DASHBOARD_HOST}). "
                         "It has no login - keep it on 127.0.0.1 unless it is firewalled.")
        return notes
