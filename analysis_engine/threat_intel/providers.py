"""
Threat intelligence providers for IOC enrichment.

Supports multiple threat intelligence sources with rate limiting,
caching, and error handling.
"""
import logging
import asyncio
import aiohttp
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
import time

from analysis_engine.threat_intel.cache import CacheManager

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, max_calls: int, period: float):
        """
        Initialize rate limiter.

        Args:
            max_calls: Maximum number of calls allowed in the period
            period: Time period in seconds
        """
        self.max_calls = max_calls
        self.period = period
        self.calls = []

    async def acquire(self):
        """Wait if necessary to respect rate limits."""
        now = time.time()

        # Remove old calls outside the window
        self.calls = [call_time for call_time in self.calls if now - call_time < self.period]

        if len(self.calls) >= self.max_calls:
            # Need to wait
            sleep_time = self.period - (now - self.calls[0]) + 0.1
            if sleep_time > 0:
                logger.debug(f"Rate limit reached, sleeping for {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)

        self.calls.append(time.time())


class ThreatIntelProvider(ABC):
    """
    Abstract base class for threat intelligence providers.

    All threat intel providers should inherit from this class and
    implement the abstract methods.
    """

    def __init__(
        self,
        api_key: str,
        cache_manager: Optional[CacheManager] = None,
        cache_ttl: int = 3600
    ):
        """
        Initialize the provider.

        Args:
            api_key: API key for the provider
            cache_manager: Optional cache manager instance
            cache_ttl: Cache TTL in seconds (default: 1 hour)
        """
        self.api_key = api_key
        self.cache_manager = cache_manager
        self.cache_ttl = cache_ttl
        self.provider_name = self.__class__.__name__

        logger.info(f"{self.provider_name} initialized")

    @abstractmethod
    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation.

        Args:
            ip_address: IP address to check

        Returns:
            Dictionary with reputation data
        """
        pass

    @abstractmethod
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation.

        Args:
            domain: Domain to check

        Returns:
            Dictionary with reputation data
        """
        pass

    @abstractmethod
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash reputation.

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            Dictionary with reputation data
        """
        pass

    def _get_cache_key(self, ioc_type: str, ioc_value: str) -> str:
        """Generate cache key."""
        return f"{self.provider_name}:{ioc_type}:{ioc_value}"

    async def _get_cached_or_fetch(
        self,
        ioc_type: str,
        ioc_value: str,
        fetch_func
    ) -> Dict[str, Any]:
        """
        Get from cache or fetch from API.

        Args:
            ioc_type: Type of IOC (ip, domain, hash)
            ioc_value: IOC value
            fetch_func: Async function to call if not in cache

        Returns:
            Enrichment data
        """
        # Check cache first
        if self.cache_manager:
            cache_key = self._get_cache_key(ioc_type, ioc_value)
            cached = self.cache_manager.get(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit for {ioc_type}:{ioc_value}")
                return cached

        # Fetch from API
        try:
            result = await fetch_func()

            # Store in cache
            if self.cache_manager:
                self.cache_manager.set(cache_key, result, self.cache_ttl)

            return result

        except Exception as e:
            logger.error(f"Error fetching {ioc_type}:{ioc_value} from {self.provider_name}: {e}")
            return {
                "error": str(e),
                "provider": self.provider_name,
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "timestamp": datetime.utcnow().isoformat()
            }


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    AbuseIPDB threat intelligence provider.

    Provides IP reputation checking using the AbuseIPDB API.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, cache_manager: Optional[CacheManager] = None, cache_ttl: int = 3600):
        """Initialize AbuseIPDB provider."""
        super().__init__(api_key, cache_manager, cache_ttl)
        self.rate_limiter = RateLimiter(max_calls=10, period=60)  # 10 calls per minute for free tier

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation on AbuseIPDB.

        Args:
            ip_address: IP address to check

        Returns:
            Dictionary with reputation data
        """
        async def fetch():
            await self.rate_limiter.acquire()

            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }

            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": ""
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/check",
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_ip_response(data)
                    elif response.status == 429:
                        raise Exception("Rate limit exceeded")
                    elif response.status == 401:
                        raise Exception("Invalid API key")
                    else:
                        error_text = await response.text()
                        raise Exception(f"API error: {response.status} - {error_text}")

        return await self._get_cached_or_fetch("ip", ip_address, fetch)

    def _parse_ip_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AbuseIPDB API response."""
        ip_data = data.get("data", {})

        return {
            "provider": "AbuseIPDB",
            "ip_address": ip_data.get("ipAddress"),
            "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
            "is_public": ip_data.get("isPublic", True),
            "is_whitelisted": ip_data.get("isWhitelisted", False),
            "country_code": ip_data.get("countryCode"),
            "usage_type": ip_data.get("usageType"),
            "isp": ip_data.get("isp"),
            "domain": ip_data.get("domain"),
            "total_reports": ip_data.get("totalReports", 0),
            "num_distinct_users": ip_data.get("numDistinctUsers", 0),
            "last_reported_at": ip_data.get("lastReportedAt"),
            "is_malicious": ip_data.get("abuseConfidenceScore", 0) > 50,
            "threat_level": self._get_threat_level(ip_data.get("abuseConfidenceScore", 0)),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _get_threat_level(self, score: int) -> str:
        """Convert abuse confidence score to threat level."""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """AbuseIPDB doesn't support domain checking."""
        return {
            "provider": "AbuseIPDB",
            "error": "Domain checking not supported by AbuseIPDB",
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat()
        }

    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """AbuseIPDB doesn't support file hash checking."""
        return {
            "provider": "AbuseIPDB",
            "error": "File hash checking not supported by AbuseIPDB",
            "file_hash": file_hash,
            "timestamp": datetime.utcnow().isoformat()
        }


class VirusTotalProvider(ThreatIntelProvider):
    """
    VirusTotal threat intelligence provider.

    Provides domain and file hash reputation checking using the VirusTotal API.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, cache_manager: Optional[CacheManager] = None, cache_ttl: int = 3600):
        """Initialize VirusTotal provider."""
        super().__init__(api_key, cache_manager, cache_ttl)
        self.rate_limiter = RateLimiter(max_calls=4, period=60)  # 4 requests per minute for free tier

    async def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """Make a request to VirusTotal API."""
        await self.rate_limiter.acquire()

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/{endpoint}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    raise Exception("Rate limit exceeded")
                elif response.status == 401:
                    raise Exception("Invalid API key")
                elif response.status == 404:
                    raise Exception("Resource not found")
                else:
                    error_text = await response.text()
                    raise Exception(f"API error: {response.status} - {error_text}")

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation on VirusTotal.

        Args:
            ip_address: IP address to check

        Returns:
            Dictionary with reputation data
        """
        async def fetch():
            data = await self._make_request(f"ip_addresses/{ip_address}")
            return self._parse_ip_response(data)

        return await self._get_cached_or_fetch("ip", ip_address, fetch)

    def _parse_ip_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal IP response."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})

        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        total_engines = sum(last_analysis_stats.values())

        return {
            "provider": "VirusTotal",
            "ip_address": data.get("data", {}).get("id"),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "harmless_count": last_analysis_stats.get("harmless", 0),
            "undetected_count": last_analysis_stats.get("undetected", 0),
            "total_engines": total_engines,
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "is_malicious": malicious_count > 0 or suspicious_count > 2,
            "threat_level": self._get_threat_level(malicious_count, suspicious_count),
            "reputation": attributes.get("reputation", 0),
            "timestamp": datetime.utcnow().isoformat()
        }

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation on VirusTotal.

        Args:
            domain: Domain to check

        Returns:
            Dictionary with reputation data
        """
        async def fetch():
            data = await self._make_request(f"domains/{domain}")
            return self._parse_domain_response(data)

        return await self._get_cached_or_fetch("domain", domain, fetch)

    def _parse_domain_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal domain response."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})

        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        total_engines = sum(last_analysis_stats.values())

        return {
            "provider": "VirusTotal",
            "domain": data.get("data", {}).get("id"),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "harmless_count": last_analysis_stats.get("harmless", 0),
            "undetected_count": last_analysis_stats.get("undetected", 0),
            "total_engines": total_engines,
            "categories": attributes.get("categories", {}),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "is_malicious": malicious_count > 0 or suspicious_count > 2,
            "threat_level": self._get_threat_level(malicious_count, suspicious_count),
            "reputation": attributes.get("reputation", 0),
            "timestamp": datetime.utcnow().isoformat()
        }

    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash reputation on VirusTotal.

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            Dictionary with reputation data
        """
        async def fetch():
            data = await self._make_request(f"files/{file_hash}")
            return self._parse_file_response(data)

        return await self._get_cached_or_fetch("hash", file_hash, fetch)

    def _parse_file_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal file response."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})

        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        total_engines = sum(last_analysis_stats.values())

        return {
            "provider": "VirusTotal",
            "file_hash": data.get("data", {}).get("id"),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "harmless_count": last_analysis_stats.get("harmless", 0),
            "undetected_count": last_analysis_stats.get("undetected", 0),
            "total_engines": total_engines,
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "is_malicious": malicious_count > 0 or suspicious_count > 2,
            "threat_level": self._get_threat_level(malicious_count, suspicious_count),
            "reputation": attributes.get("reputation", 0),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _get_threat_level(self, malicious_count: int, suspicious_count: int) -> str:
        """Convert detection counts to threat level."""
        if malicious_count >= 5:
            return "critical"
        elif malicious_count >= 3 or suspicious_count >= 5:
            return "high"
        elif malicious_count >= 1 or suspicious_count >= 2:
            return "medium"
        else:
            return "low"


class MockThreatIntelProvider(ThreatIntelProvider):
    """
    Mock provider for testing without real API keys.

    Returns simulated threat intelligence data based on IOC patterns.
    """

    def __init__(self, cache_manager: Optional[CacheManager] = None, cache_ttl: int = 3600):
        """Initialize mock provider."""
        super().__init__(api_key="mock_key", cache_manager=cache_manager, cache_ttl=cache_ttl)

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """Return mock IP reputation data."""
        # Simulate malicious IPs based on patterns
        is_malicious = ip_address.startswith("192.168.") or "malicious" in ip_address

        return {
            "provider": "MockProvider",
            "ip_address": ip_address,
            "abuse_confidence_score": 85 if is_malicious else 5,
            "is_malicious": is_malicious,
            "threat_level": "high" if is_malicious else "low",
            "total_reports": 42 if is_malicious else 0,
            "country_code": "US",
            "isp": "Mock ISP",
            "timestamp": datetime.utcnow().isoformat()
        }

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Return mock domain reputation data."""
        is_malicious = "malicious" in domain or "evil" in domain

        return {
            "provider": "MockProvider",
            "domain": domain,
            "malicious_count": 10 if is_malicious else 0,
            "suspicious_count": 5 if is_malicious else 0,
            "is_malicious": is_malicious,
            "threat_level": "critical" if is_malicious else "low",
            "total_engines": 50,
            "timestamp": datetime.utcnow().isoformat()
        }

    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Return mock file hash reputation data."""
        is_malicious = len(file_hash) > 32  # Arbitrary logic for testing

        return {
            "provider": "MockProvider",
            "file_hash": file_hash,
            "malicious_count": 15 if is_malicious else 0,
            "is_malicious": is_malicious,
            "threat_level": "critical" if is_malicious else "low",
            "total_engines": 60,
            "timestamp": datetime.utcnow().isoformat()
        }
