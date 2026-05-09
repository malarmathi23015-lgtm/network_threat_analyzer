"""
============================================================
detector/ip_reputation.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Checks IP addresses against threat intelligence databases
    to identify known malicious actors.

BEGINNER NOTE:
    IP reputation is like a credit score for IP addresses.
    Threat intelligence services track which IPs have been
    reported for:
    - Sending spam
    - Running port scans
    - Hosting malware
    - SSH brute forcing
    - Botnet activity

    We use AbuseIPDB (free API, no credit card needed).
    Get your free API key at: https://www.abuseipdb.com/register

    To avoid hitting API limits, results are cached in the
    database for 1 hour before being refreshed.
============================================================
"""

import time
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Optional

import requests

from core.logger import setup_logger
from core.config_manager import config
from database.db_manager import DatabaseManager

logger = setup_logger("IPReputation")

# Known private/reserved IP ranges that we should NOT check
# These are internal IPs that will never be in threat databases
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),       # Private LAN
    ipaddress.ip_network("172.16.0.0/12"),    # Private LAN
    ipaddress.ip_network("192.168.0.0/16"),   # Private LAN
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]


def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address is in a private/reserved range.

    We skip reputation lookups for private IPs because they
    won't be in any public threat intelligence database.

    Args:
        ip_str (str): IP address string e.g. '192.168.1.5'

    Returns:
        bool: True if IP is private/reserved
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_RANGES)
    except ValueError:
        return True  # Invalid IP = treat as private/skip


class IPReputationChecker:
    """
    Checks IP reputation using the AbuseIPDB API.

    Features:
    - Automatic caching to avoid API rate limits
    - Private IP filtering (no API calls for local IPs)
    - Graceful fallback when API is unavailable
    - Configurable via config.ini

    Usage:
        checker = IPReputationChecker(db)
        result = checker.check_ip("8.8.8.8")
        if result and result['is_malicious']:
            print(f"Malicious IP detected! Score: {result['score']}")
    """

    # AbuseIPDB API endpoint
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, db: DatabaseManager):
        """
        Initialize the reputation checker.

        Args:
            db (DatabaseManager): Database for caching results
        """
        self.db = db
        self.enabled = config.get_bool("IP_REPUTATION", "enabled", fallback=False)
        self.api_key = config.get_env("ABUSEIPDB_API_KEY") or config.get(
            "IP_REPUTATION", "abuseipdb_api_key", fallback=""
        )
        self.cache_ttl = config.get_int("IP_REPUTATION", "cache_ttl", fallback=3600)

        # In-memory cache for ultra-fast lookups (IP -> result dict)
        # This prevents repeated DB queries for frequently-seen IPs
        self._memory_cache: Dict[str, Dict] = {}

        # Rate limiting: track API calls per minute
        self._api_calls: list = []
        self._max_calls_per_minute = 60  # AbuseIPDB free tier limit

        if self.enabled:
            if not self.api_key or self.api_key == "YOUR_API_KEY_HERE":
                logger.warning("IP reputation enabled but no API key configured!")
                logger.warning("Set ABUSEIPDB_API_KEY in .env or config.ini")
                self.enabled = False
            else:
                logger.info("IP reputation checking ENABLED (AbuseIPDB)")
        else:
            logger.info("IP reputation checking DISABLED (enable in config.ini)")

    def check_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Check the reputation of an IP address.

        Lookup order:
        1. Memory cache (instant)
        2. Database cache (fast)
        3. AbuseIPDB API (external, rate-limited)

        Args:
            ip_address (str): IP to check e.g. '1.2.3.4'

        Returns:
            Dict with reputation data, or None if check failed/disabled:
            {
                'ip': '1.2.3.4',
                'score': 85,           # Abuse score 0-100
                'is_malicious': True,  # True if score > threshold
                'country': 'CN',       # Country code
                'source': 'abuseipdb'  # Where data came from
            }
        """
        if not self.enabled:
            return None

        # Skip private/internal IPs
        if is_private_ip(ip_address):
            return None

        # 1. Check memory cache first (fastest)
        if ip_address in self._memory_cache:
            cached = self._memory_cache[ip_address]
            logger.debug(f"IP {ip_address} found in memory cache")
            return cached

        # 2. Check database cache
        db_result = self.db.get_ip_reputation(ip_address)
        if db_result:
            # Check if cache is still fresh
            cached_time = datetime.fromisoformat(db_result["last_checked"])
            age_seconds = (datetime.now() - cached_time).total_seconds()

            if age_seconds < self.cache_ttl:
                result = {
                    "ip": ip_address,
                    "score": db_result["score"],
                    "is_malicious": bool(db_result["is_malicious"]),
                    "country": db_result["country"],
                    "source": "cache"
                }
                self._memory_cache[ip_address] = result
                logger.debug(f"IP {ip_address} found in DB cache (age: {age_seconds:.0f}s)")
                return result

        # 3. Query the AbuseIPDB API
        api_result = self._query_abuseipdb(ip_address)

        if api_result:
            # Save to database cache
            self.db.upsert_ip_reputation(
                ip_address=ip_address,
                score=api_result["score"],
                country=api_result.get("country"),
                is_malicious=api_result["is_malicious"],
                source="abuseipdb"
            )

            # Save to memory cache
            self._memory_cache[ip_address] = api_result

            if api_result["is_malicious"]:
                logger.warning(
                    f"MALICIOUS IP DETECTED: {ip_address} "
                    f"(score={api_result['score']}, country={api_result.get('country')})"
                )

        return api_result

    def _query_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        """
        Make an HTTP request to the AbuseIPDB API.

        API Documentation: https://docs.abuseipdb.com/#check-endpoint

        Args:
            ip_address (str): IP to check

        Returns:
            Dict with API response data, or None if request failed
        """
        # Rate limit check
        if not self._check_rate_limit():
            logger.warning("AbuseIPDB rate limit reached, skipping lookup")
            return None

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,       # Consider reports from last 90 days
                "verbose": False
            }

            logger.debug(f"Querying AbuseIPDB for: {ip_address}")
            response = requests.get(
                self.ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=5  # Don't wait more than 5 seconds
            )

            if response.status_code == 200:
                data = response.json().get("data", {})

                score = data.get("abuseConfidenceScore", 0)
                country = data.get("countryCode", "Unknown")

                # Consider score > 50 as malicious (configurable)
                is_malicious = score > 50

                return {
                    "ip": ip_address,
                    "score": score,
                    "is_malicious": is_malicious,
                    "country": country,
                    "source": "abuseipdb",
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt", None)
                }

            elif response.status_code == 422:
                logger.debug(f"Invalid IP format for API: {ip_address}")
            elif response.status_code == 429:
                logger.warning("AbuseIPDB API rate limit exceeded")
            else:
                logger.warning(f"AbuseIPDB API error: HTTP {response.status_code}")

        except requests.exceptions.Timeout:
            logger.debug(f"AbuseIPDB timeout for {ip_address}")
        except requests.exceptions.ConnectionError:
            logger.debug("No internet connection for IP reputation check")
        except Exception as e:
            logger.error(f"IP reputation lookup error: {e}")

        return None

    def _check_rate_limit(self) -> bool:
        """
        Ensure we don't exceed the API rate limit.

        AbuseIPDB free tier allows 1000 checks/day = ~60/min.
        We enforce this per minute to be safe.

        Returns:
            bool: True if we can make another API call
        """
        now = time.time()

        # Remove entries older than 1 minute from the call list
        self._api_calls = [t for t in self._api_calls if now - t < 60]

        if len(self._api_calls) >= self._max_calls_per_minute:
            return False  # Rate limit exceeded

        self._api_calls.append(now)
        return True

    def get_cached_malicious_ips(self) -> list:
        """
        Return all IPs currently known to be malicious from cache.

        Returns:
            List of malicious IP strings
        """
        return [
            ip for ip, data in self._memory_cache.items()
            if data.get("is_malicious", False)
        ]

    def bulk_check(self, ip_list: list) -> Dict[str, Optional[Dict]]:
        """
        Check reputation for multiple IPs.

        Args:
            ip_list (list): List of IP address strings

        Returns:
            Dict mapping IP -> reputation result (or None)
        """
        results = {}
        for ip in ip_list:
            results[ip] = self.check_ip(ip)
            # Small delay between checks to be API-friendly
            time.sleep(0.1)
        return results
