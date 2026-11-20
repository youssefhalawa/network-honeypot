"""
IP Intelligence and Enrichment Module
Provides GeoIP lookup and threat intelligence with offline fallback
"""
import ipaddress
from typing import Dict, Optional
from pathlib import Path
from datetime import datetime, timezone

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


class IPEnricher:
    """
    Enriches IP addresses with geographical and network information
    Handles private/reserved IPs gracefully with offline fallback
    """

    def __init__(self, mmdb_path: str = 'data/GeoLite2-City.mmdb'):
        self.mmdb_path = mmdb_path
        self.reader = None
        self.geoip_available = False

        if GEOIP_AVAILABLE and Path(mmdb_path).exists():
            try:
                self.reader = geoip2.database.Reader(mmdb_path)
                self.geoip_available = True
                print(f"[✓] GeoIP database loaded: {mmdb_path}")
            except Exception as e:
                print(f"[!] Failed to load GeoIP database: {e}")
        else:
            if not GEOIP_AVAILABLE:
                print("[!] geoip2 library not installed - enrichment disabled")
            else:
                print(f"[!] GeoIP database not found at {mmdb_path}")
                print("[!] Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")

    def enrich(self, ip: str) -> Dict:
        """
        Enrich IP address with all available intelligence

        Args:
            ip: IP address string

        Returns:
            Dictionary with enrichment data
        """
        result = {
            'ip_address': ip,
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'is_private': self._is_private(ip),
            'is_reserved': self._is_reserved(ip),
            'country_code': None,
            'country_name': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'asn': None,
            'asn_org': None,
        }

        # Handle private/reserved IPs
        if result['is_private']:
            result['country_code'] = 'PRIVATE'
            result['country_name'] = 'Private Network (RFC1918)'
            return result

        if result['is_reserved']:
            result['country_code'] = 'RESERVED'
            result['country_name'] = 'Reserved IP Space'
            return result

        # Try GeoIP lookup for public IPs
        if self.geoip_available and self.reader:
            try:
                response = self.reader.city(ip)

                result.update({
                    'country_code': response.country.iso_code,
                    'country_name': response.country.name,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                })

                # Try to get ASN info if available
                if hasattr(response, 'traits') and hasattr(response.traits, 'autonomous_system_number'):
                    result['asn'] = response.traits.autonomous_system_number
                    result['asn_org'] = response.traits.autonomous_system_organization

            except geoip2.errors.AddressNotFoundError:
                result['country_code'] = 'UNKNOWN'
                result['country_name'] = 'Unknown'
            except Exception as e:
                print(f"[!] GeoIP lookup error for {ip}: {e}")
                result['country_code'] = 'ERROR'
                result['country_name'] = 'Lookup Error'
        else:
            # Offline mode - no enrichment available
            result['country_code'] = 'OFFLINE'
            result['country_name'] = 'GeoIP Unavailable'

        return result

    @staticmethod
    def _is_private(ip: str) -> bool:
        """
        Check if IP is RFC1918 private address

        Args:
            ip: IP address string

        Returns:
            True if private, False otherwise
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _is_reserved(ip: str) -> bool:
        """
        Check if IP is reserved (loopback, link-local, multicast, etc.)

        Args:
            ip: IP address string

        Returns:
            True if reserved, False otherwise
        """
        try:
            addr = ipaddress.ip_address(ip)
            return (addr.is_loopback or
                    addr.is_link_local or
                    addr.is_multicast or
                    addr.is_reserved)
        except ValueError:
            return False

    @staticmethod
    def is_tor_exit(ip: str) -> bool:
        """
        Check if IP is known Tor exit node
        This is a placeholder - implement with Tor exit list API

        Args:
            ip: IP address string

        Returns:
            True if Tor exit node, False otherwise
        """
        # TODO: Implement Tor exit node check
        # Could use https://check.torproject.org/torbulkexitlist
        return False

    @staticmethod
    def is_vpn(ip: str) -> bool:
        """
        Check if IP is known VPN/proxy
        This is a placeholder - implement with VPN detection service

        Args:
            ip: IP address string

        Returns:
            True if VPN/proxy, False otherwise
        """
        # TODO: Implement VPN detection
        # Could use commercial services or maintain VPN IP list
        return False

    def close(self):
        """Close GeoIP database reader"""
        if self.reader:
            self.reader.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
