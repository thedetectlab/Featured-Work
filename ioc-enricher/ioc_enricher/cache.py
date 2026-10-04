"""
A plain JSON file cache for source query results, keyed by (source, ioc)
and stamped with the time it was written. Threat-intel API free tiers are
small — AbuseIPDB's is 1,000/day, VirusTotal's is 4/minute — so re-querying
the same IOC across repeated runs burns quota for nothing. Default TTL is
6 hours: long enough to make re-running a report on the same IOC list
free, short enough that a reputation change still shows up same-day.
"""

import json
import time
from pathlib import Path

DEFAULT_CACHE_PATH = Path.home() / ".cache" / "ioc-enricher" / "cache.json"
DEFAULT_TTL_SECONDS = 6 * 60 * 60  # 6 hours


class Cache:
    def __init__(self, path=None, ttl_seconds=DEFAULT_TTL_SECONDS):
        self.path = Path(path) if path else DEFAULT_CACHE_PATH
        self.ttl_seconds = ttl_seconds
        self._data = self._load()

    def _load(self):
        if not self.path.exists():
            return {}
        try:
            with open(self.path) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}  # corrupt or unreadable cache — treat as empty rather than crash

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as fh:
            json.dump(self._data, fh, indent=2)

    @staticmethod
    def _key(source, ioc_value):
        return f"{source}:{ioc_value}"

    def get(self, source, ioc_value):
        """Returns the cached dict for (source, ioc_value), or None if missing/expired."""
        entry = self._data.get(self._key(source, ioc_value))
        if entry is None:
            return None
        if time.time() - entry["cached_at"] > self.ttl_seconds:
            return None
        return entry["result"]

    def set(self, source, ioc_value, result_dict):
        self._data[self._key(source, ioc_value)] = {
            "cached_at": time.time(),
            "result": result_dict,
        }
        self._save()

    def clear(self):
        self._data = {}
        if self.path.exists():
            self.path.unlink()
