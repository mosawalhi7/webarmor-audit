"""
Caching engine for WebArmor-Audit.
"""

import json
import os
import threading
import time
from typing import Any, Dict, Optional


CACHE_FILENAME = ".webarmor_cache.json"
_cache_lock = threading.Lock()


def _get_cache_path() -> str:
    """Return the absolute path of the cache file in the current directory."""
    return os.path.abspath(CACHE_FILENAME)


def _load_cache() -> Dict[str, Any]:
    """Load the JSON cache file from disk."""
    path = _get_cache_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(data: Dict[str, Any]) -> None:
    """Save the JSON cache file to disk."""
    path = _get_cache_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def get_cached_report(url: str, ttl_seconds: int = 300) -> Optional[Dict[str, Any]]:
    """
    Retrieve cached report dict if it exists and has not expired.
    """
    with _cache_lock:
        cache = _load_cache()
        entry = cache.get(url)
        if not entry:
            return None

        cached_time = entry.get("timestamp", 0.0)
        current_time = time.time()

        if current_time - cached_time > ttl_seconds:
            return None

        return entry.get("report")


def save_to_cache(url: str, report_dict: Dict[str, Any]) -> None:
    """
    Save the report dict to cache with the current timestamp.
    """
    with _cache_lock:
        cache = _load_cache()
        current_time = time.time()

        # Clean old entries (older than 24 hours) to avoid bloating the file
        cleaned_cache = {}
        for k, v in cache.items():
            if current_time - v.get("timestamp", 0.0) < 86400:
                cleaned_cache[k] = v

        cleaned_cache[url] = {
            "timestamp": current_time,
            "report": report_dict
        }

        _save_cache(cleaned_cache)
