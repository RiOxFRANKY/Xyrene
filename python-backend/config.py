"""
Configuration management for the IDS Python backend.
Thread-safe singleton loading from config/config.json with sensible defaults.
"""

import os
import json
import threading
from typing import Any, Dict, Optional, Set


_DEFAULT_CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 8000,
    },
    "model": {
        "path": "models/xgboost_ids_model.json",
        "feature_names_path": "models/feature_names.json",
    },
    "thresholds": {
        "suspicious": 0.50,
        "malicious": 0.60,
        "critical": 0.90,
    },
    "policy": {
        "malicious_threshold": 3,
        "malicious_window_sec": 60,
        "suspicious_threshold": 5,
        "suspicious_window_sec": 120,
        "block_duration_sec": 300,
    },
    "logging": {
        "log_dir": "logs",
        "max_bytes": 10485760,
        "backup_count": 5,
    },
    "alerts": {
        "enabled": False,
        "webhook_url": "",
        "rate_limit_seconds": 10.0,
    },
    "whitelist_path": "config/whitelist.txt",
}


class IDSConfig:
    """
    Thread-safe singleton configuration.
    Loads from config/config.json and merges with defaults.
    """

    _instance: Optional["IDSConfig"] = None
    _lock = threading.Lock()

    def __init__(self, config_path: str = None):
        self._data: Dict[str, Any] = {}
        self._load(config_path)

    @classmethod
    def load(cls, config_path: str = None) -> "IDSConfig":
        with cls._lock:
            cls._instance = cls(config_path)
        return cls._instance

    @classmethod
    def get(cls) -> "IDSConfig":
        if cls._instance is None:
            cls.load()
        return cls._instance

    def _load(self, config_path: str = None) -> None:
        """Load config from file, falling back to defaults for missing keys."""
        self._data = _deep_copy_dict(_DEFAULT_CONFIG)

        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "config", "config.json"
            )

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                user_config = json.load(f)
            _deep_merge(self._data, user_config)

    def __getitem__(self, key: str) -> Any:
        """Access nested keys with dot notation: config['server.port']"""
        return self._get_nested(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self._get_nested(key)
        except KeyError:
            return default

    def _get_nested(self, key: str) -> Any:
        parts = key.split(".")
        node = self._data
        for part in parts:
            if isinstance(node, dict):
                node = node[part]
            else:
                raise KeyError(key)
        return node

    def load_whitelist(self) -> Set[str]:
        """Load whitelisted IPs from the whitelist file."""
        path = self._data.get("whitelist_path", "config/whitelist.txt")
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(os.path.dirname(__file__)), path)

        ips = set()
        if os.path.exists(path):
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.add(line)
        return ips

    @property
    def raw(self) -> Dict[str, Any]:
        return dict(self._data)


def _deep_copy_dict(d: dict) -> dict:
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _deep_copy_dict(v)
        elif isinstance(v, list):
            result[k] = list(v)
        else:
            result[k] = v
    return result


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
