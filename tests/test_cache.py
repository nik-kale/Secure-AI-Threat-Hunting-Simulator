"""
Tests for the Redis cache serialisation layer (no Redis server needed).
"""

import json
import pickle

import pytest

from analysis_engine.cache import CacheConfig, RedisCache


class _Exploit:
    """Unpickling this object creates a marker file."""

    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (open, (self.path, "w"))


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, data):
        self.store[key] = data


@pytest.fixture
def cache():
    cache = RedisCache(CacheConfig(enabled=False))
    cache.enabled = True
    cache.client = _FakeRedis()
    return cache


def test_json_round_trip(cache):
    assert cache.set("ns", "k", {"a": [1, 2]}) is True
    assert cache.get("ns", "k") == {"a": [1, 2]}
    assert json.loads(cache.client.store["aiths:ns:k"]) == {"a": [1, 2]}


def test_pickled_data_in_redis_is_not_unpickled(cache, tmp_path):
    marker = tmp_path / "pwned"
    cache.client.store["aiths:ns:k"] = pickle.dumps(_Exploit(str(marker)))

    assert cache.get("ns", "k") is None
    assert not marker.exists()


def test_non_json_values_are_not_cached(cache):
    assert cache.set("ns", "k", object()) is False
    assert "aiths:ns:k" not in cache.client.store
