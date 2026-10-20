# api/cache.py
"""
Adversum API Cache — LRU in-memory cache with TTL and ETag support.
Thread-safe. Automatically evicts expired entries on access.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Optional
from dataclasses import dataclass


@dataclass
class CacheEntry:
    value: Any
    etag: str
    expires_at: float


class LRUCache:
    def __init__(self, maxsize: int = 512, ttl: float = 30.0):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0

    def _make_etag(self, data: Any) -> str:
        return hashlib.md5(
            json.dumps(data, default=str, sort_keys=True).encode()
        ).hexdigest()[:16]

    async def get(self, key: str) -> Optional[CacheEntry]:
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.misses += 1
                return None
            if time.monotonic() > entry.expires_at:
                del self._cache[key]
                self.misses += 1
                return None
            self._cache.move_to_end(key)
            self.hits += 1
            return entry

    async def set(self, key: str, value: Any) -> str:
        etag = self._make_etag(value)
        entry = CacheEntry(
            value=value, etag=etag, expires_at=time.monotonic() + self._ttl
        )
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self._maxsize:
                self._cache.popitem(last=False)
            self._cache[key] = entry
        return etag

    async def invalidate(self, key: str) -> None:
        async with self._lock:
            self._cache.pop(key, None)

    async def invalidate_prefix(self, prefix: str) -> int:
        async with self._lock:
            keys_to_del = [k for k in self._cache if k.startswith(prefix)]
            for k in keys_to_del:
                del self._cache[k]
            return len(keys_to_del)

    @property
    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "size": len(self._cache),
            "maxsize": self._maxsize,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
        }


# Singleton — shared across all requests
api_cache = LRUCache(maxsize=512, ttl=30.0)
