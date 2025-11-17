"""
Redis caching layer for performance optimization.

Provides:
- Analysis result caching
- Scenario metadata caching
- Detection rule caching
- IOC enrichment caching
- Cache invalidation strategies
"""
import redis
import json
import hashlib
import logging
from typing import Any, Optional, Dict, List
from datetime import timedelta
from functools import wraps
import pickle

logger = logging.getLogger(__name__)


class CacheConfig:
    """Cache configuration."""

    def __init__(
        self,
        enabled: bool = True,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        redis_password: Optional[str] = None,
        default_ttl: int = 3600,  # 1 hour
        max_connections: int = 50
    ):
        """
        Initialize cache configuration.

        Args:
            enabled: Whether caching is enabled
            redis_host: Redis server host
            redis_port: Redis server port
            redis_db: Redis database number
            redis_password: Optional Redis password
            default_ttl: Default TTL in seconds
            max_connections: Max connection pool size
        """
        self.enabled = enabled
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.redis_password = redis_password
        self.default_ttl = default_ttl
        self.max_connections = max_connections


class RedisCache:
    """
    Redis-based caching layer with automatic serialization.

    Features:
    - Automatic JSON/pickle serialization
    - TTL support
    - Key namespacing
    - Cache statistics
    - Batch operations
    """

    def __init__(self, config: CacheConfig):
        """
        Initialize Redis cache.

        Args:
            config: Cache configuration
        """
        self.config = config
        self.enabled = config.enabled
        self.client: Optional[redis.Redis] = None
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "errors": 0
        }

        if self.enabled:
            try:
                self.client = redis.Redis(
                    host=config.redis_host,
                    port=config.redis_port,
                    db=config.redis_db,
                    password=config.redis_password,
                    decode_responses=False,  # We handle encoding
                    max_connections=config.max_connections,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                # Test connection
                self.client.ping()
                logger.info(
                    f"Redis cache initialized: {config.redis_host}:{config.redis_port}/{config.redis_db}"
                )
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self.enabled = False
                self.client = None

    def _make_key(self, namespace: str, key: str) -> str:
        """
        Generate namespaced cache key.

        Args:
            namespace: Key namespace
            key: Cache key

        Returns:
            Namespaced key
        """
        return f"aiths:{namespace}:{key}"

    def _serialize(self, value: Any) -> bytes:
        """
        Serialize value for caching.

        Args:
            value: Value to serialize

        Returns:
            Serialized bytes
        """
        try:
            # Try JSON first (faster, human-readable in Redis)
            return json.dumps(value).encode('utf-8')
        except (TypeError, ValueError):
            # Fall back to pickle for complex objects
            return pickle.dumps(value)

    def _deserialize(self, data: bytes) -> Any:
        """
        Deserialize cached value.

        Args:
            data: Serialized data

        Returns:
            Deserialized value
        """
        try:
            # Try JSON first
            return json.loads(data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fall back to pickle
            return pickle.loads(data)

    def get(self, namespace: str, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            namespace: Key namespace
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        if not self.enabled or not self.client:
            return None

        try:
            cache_key = self._make_key(namespace, key)
            data = self.client.get(cache_key)

            if data is None:
                self.stats["misses"] += 1
                return None

            self.stats["hits"] += 1
            return self._deserialize(data)

        except Exception as e:
            logger.error(f"Cache get error: {e}")
            self.stats["errors"] += 1
            return None

    def set(
        self,
        namespace: str,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """
        Set value in cache.

        Args:
            namespace: Key namespace
            key: Cache key
            value: Value to cache
            ttl: Optional TTL in seconds

        Returns:
            True if successful, False otherwise
        """
        if not self.enabled or not self.client:
            return False

        try:
            cache_key = self._make_key(namespace, key)
            data = self._serialize(value)
            ttl = ttl or self.config.default_ttl

            self.client.setex(cache_key, ttl, data)
            self.stats["sets"] += 1
            return True

        except Exception as e:
            logger.error(f"Cache set error: {e}")
            self.stats["errors"] += 1
            return False

    def delete(self, namespace: str, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            namespace: Key namespace
            key: Cache key

        Returns:
            True if deleted, False otherwise
        """
        if not self.enabled or not self.client:
            return False

        try:
            cache_key = self._make_key(namespace, key)
            result = self.client.delete(cache_key)
            self.stats["deletes"] += 1
            return result > 0

        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            self.stats["errors"] += 1
            return False

    def invalidate_namespace(self, namespace: str) -> int:
        """
        Invalidate all keys in a namespace.

        Args:
            namespace: Namespace to invalidate

        Returns:
            Number of keys deleted
        """
        if not self.enabled or not self.client:
            return 0

        try:
            pattern = self._make_key(namespace, "*")
            keys = self.client.keys(pattern)
            if keys:
                deleted = self.client.delete(*keys)
                self.stats["deletes"] += deleted
                return deleted
            return 0

        except Exception as e:
            logger.error(f"Cache invalidate error: {e}")
            self.stats["errors"] += 1
            return 0

    def get_many(self, namespace: str, keys: List[str]) -> Dict[str, Any]:
        """
        Get multiple values from cache.

        Args:
            namespace: Key namespace
            keys: List of cache keys

        Returns:
            Dictionary of key -> value (only found keys)
        """
        if not self.enabled or not self.client:
            return {}

        try:
            cache_keys = [self._make_key(namespace, k) for k in keys]
            values = self.client.mget(cache_keys)

            result = {}
            for key, data in zip(keys, values):
                if data is not None:
                    result[key] = self._deserialize(data)
                    self.stats["hits"] += 1
                else:
                    self.stats["misses"] += 1

            return result

        except Exception as e:
            logger.error(f"Cache get_many error: {e}")
            self.stats["errors"] += 1
            return {}

    def set_many(
        self,
        namespace: str,
        items: Dict[str, Any],
        ttl: Optional[int] = None
    ) -> int:
        """
        Set multiple values in cache.

        Args:
            namespace: Key namespace
            items: Dictionary of key -> value
            ttl: Optional TTL in seconds

        Returns:
            Number of items successfully set
        """
        if not self.enabled or not self.client:
            return 0

        try:
            ttl = ttl or self.config.default_ttl
            pipeline = self.client.pipeline()

            for key, value in items.items():
                cache_key = self._make_key(namespace, key)
                data = self._serialize(value)
                pipeline.setex(cache_key, ttl, data)

            pipeline.execute()
            self.stats["sets"] += len(items)
            return len(items)

        except Exception as e:
            logger.error(f"Cache set_many error: {e}")
            self.stats["errors"] += 1
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Statistics dictionary
        """
        total_operations = self.stats["hits"] + self.stats["misses"]
        hit_rate = (
            self.stats["hits"] / total_operations * 100
            if total_operations > 0
            else 0
        )

        return {
            "enabled": self.enabled,
            "connected": self.client is not None and self.enabled,
            "stats": {
                **self.stats,
                "total_operations": total_operations,
                "hit_rate_percent": round(hit_rate, 2)
            }
        }

    def clear_all(self) -> bool:
        """
        Clear all cache (use with caution).

        Returns:
            True if successful
        """
        if not self.enabled or not self.client:
            return False

        try:
            self.client.flushdb()
            logger.warning("Cache cleared completely")
            return True
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False


# Global cache instance
_cache: Optional[RedisCache] = None


def init_cache(config: CacheConfig) -> RedisCache:
    """
    Initialize global cache instance.

    Args:
        config: Cache configuration

    Returns:
        Cache instance
    """
    global _cache
    _cache = RedisCache(config)
    return _cache


def get_cache() -> Optional[RedisCache]:
    """
    Get global cache instance.

    Returns:
        Cache instance or None if not initialized
    """
    return _cache


def cached(namespace: str, key_func=None, ttl: Optional[int] = None):
    """
    Decorator for caching function results.

    Args:
        namespace: Cache namespace
        key_func: Optional function to generate cache key from args
        ttl: Optional TTL in seconds

    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache()
            if not cache or not cache.enabled:
                return func(*args, **kwargs)

            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default: hash of function name and args
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                key_str = ":".join(key_parts)
                cache_key = hashlib.md5(key_str.encode()).hexdigest()

            # Try to get from cache
            cached_value = cache.get(namespace, cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit: {namespace}:{cache_key}")
                return cached_value

            # Execute function
            result = func(*args, **kwargs)

            # Cache result
            cache.set(namespace, cache_key, result, ttl)
            logger.debug(f"Cache set: {namespace}:{cache_key}")

            return result

        return wrapper
    return decorator


# Predefined cache namespaces
class CacheNamespace:
    """Cache namespace constants."""
    ANALYSIS = "analysis"
    SCENARIO = "scenario"
    DETECTION_RULES = "detection_rules"
    IOC_ENRICHMENT = "ioc_enrichment"
    THREAT_INTEL = "threat_intel"
    SESSION = "session"
    METRICS = "metrics"
