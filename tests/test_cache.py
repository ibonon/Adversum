# tests/test_cache.py
"""
Tests for api/cache.py — LRU cache with TTL, ETag, invalidation, and stats.
"""
from __future__ import annotations
import sys
import os
from pathlib import Path

# Ensure project root is on sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import asyncio
import time
from unittest.mock import patch

import pytest
import pytest_asyncio

from api.cache import LRUCache, CacheEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_cache(maxsize: int = 4, ttl: float = 30.0) -> LRUCache:
    """Return a brand-new LRUCache to avoid state sharing between tests."""
    return LRUCache(maxsize=maxsize, ttl=ttl)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_miss_returns_none():
    """A key never set must return None (cache miss)."""
    cache = _fresh_cache()
    result = await cache.get("nonexistent_key")
    assert result is None
    assert cache.misses == 1
    assert cache.hits == 0


@pytest.mark.asyncio
async def test_cache_set_and_get():
    """After set(), get() must return the same value with a valid ETag."""
    cache = _fresh_cache()
    payload = {"total_audits": 42, "avg_robustness": 0.87}
    etag = await cache.set("dashboard:stats", payload)

    # ETag must be a non-empty hex string (16 chars)
    assert isinstance(etag, str)
    assert len(etag) == 16

    entry = await cache.get("dashboard:stats")
    assert entry is not None
    assert entry.value == payload
    assert entry.etag == etag
    assert cache.hits == 1
    assert cache.misses == 0


@pytest.mark.asyncio
async def test_cache_ttl_expiry():
    """An entry must be evicted after its TTL has elapsed (monotonic mocked)."""
    cache = _fresh_cache(ttl=5.0)
    await cache.set("expiring_key", {"data": "hello"})

    # Fast-forward time by 10 seconds — entry is now stale
    with patch("api.cache.time.monotonic", return_value=time.monotonic() + 10):
        result = await cache.get("expiring_key")

    assert result is None, "Expired entry should return None"
    assert cache.misses >= 1


@pytest.mark.asyncio
async def test_cache_lru_eviction():
    """When maxsize is reached, the least-recently-used entry is evicted."""
    cache = _fresh_cache(maxsize=3, ttl=60.0)

    # Fill to capacity
    await cache.set("a", 1)
    await cache.set("b", 2)
    await cache.set("c", 3)

    # Touch "a" to make it recently used — "b" becomes LRU
    await cache.get("a")

    # Adding "d" should evict "b" (LRU)
    await cache.set("d", 4)

    assert await cache.get("b") is None, "'b' should have been evicted as LRU"
    assert await cache.get("a") is not None, "'a' should still be present"
    assert await cache.get("c") is not None, "'c' should still be present"
    assert await cache.get("d") is not None, "'d' should be present"


@pytest.mark.asyncio
async def test_cache_invalidate():
    """invalidate() must remove the key; invalidate_prefix() must remove matching keys."""
    cache = _fresh_cache()
    await cache.set("dashboard:stats", {"x": 1})
    await cache.set("dashboard:users", {"y": 2})
    await cache.set("other:key", {"z": 3})

    # Single key invalidation
    await cache.invalidate("dashboard:stats")
    assert await cache.get("dashboard:stats") is None

    # Prefix invalidation
    removed = await cache.invalidate_prefix("dashboard:")
    assert removed == 1  # only "dashboard:users" remains
    assert await cache.get("dashboard:users") is None

    # Unrelated key must still be present
    assert await cache.get("other:key") is not None


@pytest.mark.asyncio
async def test_cache_stats_hit_rate():
    """stats must accurately report size, hits, misses, and hit_rate."""
    cache = _fresh_cache()

    # Initially empty — no requests
    s = cache.stats
    assert s["size"] == 0
    assert s["hits"] == 0
    assert s["misses"] == 0
    assert s["hit_rate"] == 0.0

    await cache.set("k1", "v1")
    await cache.set("k2", "v2")

    await cache.get("k1")   # hit
    await cache.get("k2")   # hit
    await cache.get("k3")   # miss

    s = cache.stats
    assert s["size"] == 2
    assert s["hits"] == 2
    assert s["misses"] == 1
    assert s["hit_rate"] == pytest.approx(2 / 3, abs=0.001)
    assert s["maxsize"] == 4
