"""
IP Intelligence and Enrichment (Member 5)

* GeoIP lookup with MaxMind GeoLite2 City (+ optional ASN database)
* Private / reserved addresses are labelled without a lookup
* Works offline: if the .mmdb files are missing, IPs are stored as 'OFFLINE'
* enrich_and_store(ip) is what the decoys call for every new session.
  Results are cached in the ip_intel table for IP_INTEL_CACHE_HOURS.
"""
import ipaddress
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:  # library not installed
    GEOIP_AVAILABLE = False

log = logging.getLogger('honeypot.enrichment')


class IPEnricher:
    """Enriches IP addresses with location and network information."""

    def __init__(self, mmdb_path: str = 'data/GeoLite2-City.mmdb', asn_mmdb_path: Optional[str] = None):
        self.mmdb_path = mmdb_path
        self.reader = None
        self.asn_reader = None
        self.geoip_available = False

        if not GEOIP_AVAILABLE:
            log.warning('geoip2 library not installed - IP enrichment runs in offline mode')
            return

        if Path(mmdb_path).exists():
            try:
                self.reader = geoip2.database.Reader(mmdb_path)
                self.geoip_available = True
                log.info('GeoIP database loaded: %s', mmdb_path)
            except Exception as exc:
                log.warning('Failed to load GeoIP database %s: %s', mmdb_path, exc)
        else:
            log.warning('GeoIP database not found at %s - run scripts/setup_geoip.sh (offline mode for now)',
                        mmdb_path)

        if asn_mmdb_path and Path(asn_mmdb_path).exists():
            try:
                self.asn_reader = geoip2.database.Reader(asn_mmdb_path)
            except Exception as exc:
                log.warning('Failed to load ASN database %s: %s', asn_mmdb_path, exc)

    def enrich(self, ip: str) -> Dict:
        result = {
            'ip_address': ip,
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'is_private': self._is_private(ip),
            'is_reserved': self._is_reserved(ip),
            'country_code': None, 'country_name': None, 'city': None,
            'latitude': None, 'longitude': None, 'asn': None, 'asn_org': None,
            'is_tor': False, 'is_vpn': False,
        }

        # Reserved first: loopback (127.0.0.1) is also "private" in Python's ipaddress
        if result['is_reserved']:
            result.update(country_code='RESERVED', country_name='Reserved / Loopback')
            return result
        if result['is_private']:
            result.update(country_code='PRIVATE', country_name='Private Network (RFC1918)')
            return result

        if self.geoip_available and self.reader:
            try:
                response = self.reader.city(ip)
                result.update(
                    country_code=response.country.iso_code or 'UNKNOWN',
                    country_name=response.country.name or 'Unknown',
                    city=response.city.name,
                    latitude=response.location.latitude,
                    longitude=response.location.longitude,
                )
            except geoip2.errors.AddressNotFoundError:
                result.update(country_code='UNKNOWN', country_name='Unknown')
            except Exception as exc:
                log.warning('GeoIP lookup error for %s: %s', ip, exc)
                result.update(country_code='ERROR', country_name='Lookup Error')
        else:
            result.update(country_code='OFFLINE', country_name='GeoIP Unavailable')

        if self.asn_reader:
            try:
                asn = self.asn_reader.asn(ip)
                result.update(asn=asn.autonomous_system_number, asn_org=asn.autonomous_system_organization)
            except Exception:
                pass

        return result

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _is_reserved(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved \
                or addr.is_unspecified
        except ValueError:
            return False

    def close(self):
        for reader in (self.reader, self.asn_reader):
            if reader:
                reader.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ---------------------------------------------------------------------------
# Shared enricher + the function the decoys call
# ---------------------------------------------------------------------------
_enricher: Optional[IPEnricher] = None
_enricher_lock = threading.Lock()


def get_enricher() -> IPEnricher:
    global _enricher
    with _enricher_lock:
        if _enricher is None:
            from app.core.config import Config
            _enricher = IPEnricher(Config.GEOIP_DB_PATH, Config.GEOIP_ASN_DB_PATH)
        return _enricher


def enrich_and_store(db, ip: str, cache_hours: Optional[int] = None) -> Optional[Dict]:
    """Look up `ip` (unless cached recently) and save it in ip_intel.
    Never raises: enrichment problems must not break a decoy."""
    try:
        if cache_hours is None:
            from app.core.config import Config
            cache_hours = Config.IP_INTEL_CACHE_HOURS
        if db.ip_intel_is_fresh(ip, cache_hours):
            db.record_ip_seen(ip)
            return db.get_ip_intel(ip)
        intel = get_enricher().enrich(ip)
        db.upsert_ip_intel(intel)
        return intel
    except Exception as exc:
        log.warning('IP enrichment failed for %s: %s', ip, exc)
        return None
