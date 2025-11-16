"""
Simple file-based cache with TTL support for threat intelligence data.
"""
import json
import time
import logging
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timedelta
import hashlib

logger = logging.getLogger(__name__)


class CacheManager:
    """
    File-based cache manager with TTL support.

    Provides a simple caching mechanism for threat intelligence data
    to reduce API calls and improve performance.
    """

    def __init__(self, cache_dir: str = "./data/threat_intel_cache", default_ttl: int = 3600):
        """
        Initialize the cache manager.

        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default time-to-live in seconds (default: 1 hour)
        """
        self.cache_dir = Path(cache_dir)
        self.default_ttl = default_ttl

        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"CacheManager initialized with cache_dir={cache_dir}, default_ttl={default_ttl}s")

    def _get_cache_key(self, key: str) -> str:
        """
        Generate a safe filename from a cache key.

        Args:
            key: Original cache key

        Returns:
            Safe filename (SHA256 hash of key)
        """
        return hashlib.sha256(key.encode()).hexdigest()

    def _get_cache_path(self, key: str) -> Path:
        """
        Get the file path for a cache key.

        Args:
            key: Cache key

        Returns:
            Path to cache file
        """
        cache_key = self._get_cache_key(key)
        return self.cache_dir / f"{cache_key}.json"

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve a value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value if found and not expired, None otherwise
        """
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            logger.debug(f"Cache miss: {key}")
            return None

        try:
            with open(cache_path, 'r') as f:
                cache_entry = json.load(f)

            # Check expiration
            expires_at = cache_entry.get("expires_at")
            if expires_at and time.time() > expires_at:
                logger.debug(f"Cache expired: {key}")
                # Clean up expired entry
                cache_path.unlink()
                return None

            logger.debug(f"Cache hit: {key}")
            return cache_entry.get("value")

        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Error reading cache for {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Store a value in cache.

        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
            ttl: Time-to-live in seconds (uses default_ttl if not specified)
        """
        cache_path = self._get_cache_path(key)
        ttl = ttl if ttl is not None else self.default_ttl

        cache_entry = {
            "key": key,
            "value": value,
            "created_at": time.time(),
            "expires_at": time.time() + ttl if ttl > 0 else None,
            "ttl": ttl
        }

        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_entry, f, indent=2)

            logger.debug(f"Cache stored: {key} (TTL: {ttl}s)")

        except (IOError, TypeError) as e:
            logger.error(f"Error writing cache for {key}: {e}")

    def invalidate(self, key: str) -> bool:
        """
        Invalidate a cache entry.

        Args:
            key: Cache key to invalidate

        Returns:
            True if entry was found and deleted, False otherwise
        """
        cache_path = self._get_cache_path(key)

        if cache_path.exists():
            cache_path.unlink()
            logger.debug(f"Cache invalidated: {key}")
            return True

        return False

    def clear(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries cleared
        """
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1

        logger.info(f"Cache cleared: {count} entries deleted")
        return count

    def cleanup_expired(self) -> int:
        """
        Remove all expired cache entries.

        Returns:
            Number of expired entries removed
        """
        count = 0
        current_time = time.time()

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cache_entry = json.load(f)

                expires_at = cache_entry.get("expires_at")
                if expires_at and current_time > expires_at:
                    cache_file.unlink()
                    count += 1

            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Error checking cache file {cache_file}: {e}")

        if count > 0:
            logger.info(f"Cleaned up {count} expired cache entries")

        return count

    def get_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        total_entries = 0
        expired_entries = 0
        total_size_bytes = 0
        current_time = time.time()

        for cache_file in self.cache_dir.glob("*.json"):
            total_entries += 1
            total_size_bytes += cache_file.stat().st_size

            try:
                with open(cache_file, 'r') as f:
                    cache_entry = json.load(f)

                expires_at = cache_entry.get("expires_at")
                if expires_at and current_time > expires_at:
                    expired_entries += 1

            except (json.JSONDecodeError, IOError):
                pass

        return {
            "total_entries": total_entries,
            "active_entries": total_entries - expired_entries,
            "expired_entries": expired_entries,
            "total_size_bytes": total_size_bytes,
            "total_size_mb": round(total_size_bytes / (1024 * 1024), 2),
            "cache_dir": str(self.cache_dir),
            "default_ttl": self.default_ttl
        }
