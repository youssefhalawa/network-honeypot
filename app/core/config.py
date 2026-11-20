"""
Honeypot configuration management
Loads settings from environment variables and .env file
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if it exists
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / '.env')

class Config:
    """Centralized configuration"""

    # HTTP Decoy
    HTTP_DECOY_ENABLED = os.getenv('HTTP_DECOY_ENABLED', 'true').lower() == 'true'
    HTTP_PORT = int(os.getenv('HTTP_PORT', 8080))
    HTTP_HOST = os.getenv('HTTP_HOST', '0.0.0.0')

    # SSH Decoy
    SSH_DECOY_ENABLED = os.getenv('SSH_DECOY_ENABLED', 'false').lower() == 'true'
    SSH_PORT = int(os.getenv('SSH_PORT', 2222))
    SSH_HOST = os.getenv('SSH_HOST', '0.0.0.0')

    # Database
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'data/honeypot.db')

    # Session Limits
    MAX_CONCURRENT_SESSIONS = int(os.getenv('MAX_CONCURRENT_SESSIONS', 100))
    SESSION_IDLE_TIMEOUT_SECONDS = int(os.getenv('SESSION_IDLE_TIMEOUT_SECONDS', 300))
    SESSION_MAX_DURATION_SECONDS = int(os.getenv('SESSION_MAX_DURATION_SECONDS', 1800))

    # Rate Limiting
    RATE_LIMIT_PER_IP = int(os.getenv('RATE_LIMIT_PER_IP', 10))
    RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', 60))

    # IP Enrichment
    GEOIP_DB_PATH = os.getenv('GEOIP_DB_PATH', 'data/GeoLite2-City.mmdb')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY', '')

    # Dashboard
    DASHBOARD_ENABLED = os.getenv('DASHBOARD_ENABLED', 'false').lower() == 'true'
    DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', 5000))
    DASHBOARD_HOST = os.getenv('DASHBOARD_HOST', '127.0.0.1')

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'data/logs/honeypot.log')

    # Deployment
    RUN_AS_USER = os.getenv('RUN_AS_USER', 'honeypot')
    TIMEZONE = os.getenv('TIMEZONE', 'UTC')

    @classmethod
    def validate(cls):
        """Validate critical configuration"""
        errors = []

        if cls.HTTP_PORT < 1 or cls.HTTP_PORT > 65535:
            errors.append(f"Invalid HTTP_PORT: {cls.HTTP_PORT}")

        if cls.SSH_PORT < 1 or cls.SSH_PORT > 65535:
            errors.append(f"Invalid SSH_PORT: {cls.SSH_PORT}")

        if cls.HTTP_PORT == cls.SSH_PORT:
            errors.append("HTTP_PORT and SSH_PORT cannot be the same")

        if not cls.HTTP_DECOY_ENABLED and not cls.SSH_DECOY_ENABLED:
            errors.append("At least one decoy (HTTP or SSH) must be enabled")

        if errors:
            raise ValueError("Configuration errors:\n" + "\n".join(errors))

        return True
