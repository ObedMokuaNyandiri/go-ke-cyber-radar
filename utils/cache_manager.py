"""
.GO.KE Cyber-Surface Radar — Cache Manager
============================================
Simple file-based caching to avoid redundant API calls and respect rate limits.
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional


CACHE_DIR = Path(__file__).parent.parent / ".cache"
DEFAULT_TTL = 3600  # 1 hour default cache TTL


class CacheManager:
    """File-based cache with TTL support."""

    def __init__(self, cache_dir: Optional[Path] = None, default_ttl: int = DEFAULT_TTL):
        self.cache_dir = cache_dir or CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl

    def _key_to_path(self, key: str) -> Path:
        """Convert a cache key to a file path."""
        hashed = hashlib.sha256(key.encode()).hexdigest()[:16]
        safe_key = "".join(c if c.isalnum() else "_" for c in key[:40])
        return self.cache_dir / f"{safe_key}_{hashed}.json"

    def get(self, key: str) -> Optional[Any]:
        """Retrieve a cached value if it exists and hasn't expired."""
        path = self._key_to_path(key)
        if not path.exists():
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                cached = json.load(f)

            if time.time() > cached.get("expires_at", 0):
                # Cache expired, remove file
                path.unlink(missing_ok=True)
                return None

            return cached.get("data")
        except (json.JSONDecodeError, OSError):
            path.unlink(missing_ok=True)
            return None

    def set(self, key: str, data: Any, ttl: Optional[int] = None) -> None:
        """Store a value in the cache with an expiration time."""
        ttl = ttl if ttl is not None else self.default_ttl
        path = self._key_to_path(key)

        cache_entry = {
            "key": key,
            "data": data,
            "created_at": time.time(),
            "expires_at": time.time() + ttl,
        }

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f)
        except OSError:
            pass  # Silently fail on cache write errors

    def delete(self, key: str) -> bool:
        """Remove a cached value."""
        path = self._key_to_path(key)
        if path.exists():
            path.unlink(missing_ok=True)
            return True
        return False

    def clear(self) -> int:
        """Clear all cached values. Returns count of removed entries."""
        count = 0
        for path in self.cache_dir.glob("*.json"):
            path.unlink(missing_ok=True)
            count += 1
        return count

    def stats(self) -> dict:
        """Get cache statistics."""
        total = 0
        expired = 0
        size_bytes = 0
        now = time.time()

        for path in self.cache_dir.glob("*.json"):
            total += 1
            size_bytes += path.stat().st_size
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                if now > cached.get("expires_at", 0):
                    expired += 1
            except (json.JSONDecodeError, OSError):
                expired += 1

        return {
            "total_entries": total,
            "expired_entries": expired,
            "valid_entries": total - expired,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
        }


# Global cache instance
cache = CacheManager()
