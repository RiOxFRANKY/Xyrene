"""
IDS Logging layer.
IIDSLogger ABC + FileLogger that writes JSON Lines.
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from logging.handlers import RotatingFileHandler
from models.packet_data import PacketRequest, VerdictResult


class IIDSLogger(ABC):
    """Abstract interface for IDS event logging."""

    @abstractmethod
    def log_verdict(self, request: PacketRequest, result: VerdictResult) -> None:
        """Log a classification verdict."""
        ...

    @abstractmethod
    def log_block(self, ip: str, zone: str, reason: str) -> None:
        """Log an IP blocking event."""
        ...

    @abstractmethod
    def log_alert(self, ip: str, alert_type: str, details: str) -> None:
        """Log an alert dispatch event."""
        ...


class FileLogger(IIDSLogger):
    """
    Production-grade file logger using JSON Lines format.
    Supports log rotation (5 files × 10MB).
    Never logs raw payload to avoid PII leaks.
    """

    def __init__(self, log_dir: str = "logs", max_bytes: int = 10_485_760, backup_count: int = 5):
        os.makedirs(log_dir, exist_ok=True)

        self._verdict_logger = self._make_logger(
            "ids.verdicts", os.path.join(log_dir, "verdicts.log"), max_bytes, backup_count
        )
        self._block_logger = self._make_logger(
            "ids.blocks", os.path.join(log_dir, "blocks.log"), max_bytes, backup_count
        )
        self._alert_logger = self._make_logger(
            "ids.alerts", os.path.join(log_dir, "alerts.log"), max_bytes, backup_count
        )

    @staticmethod
    def _make_logger(
        name: str, filepath: str, max_bytes: int, backup_count: int
    ) -> logging.Logger:
        logger = logging.getLogger(name)
        # Prevent duplicate handlers on re-init
        if logger.handlers:
            return logger
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            filepath, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.propagate = False
        return logger

    def log_verdict(self, request: PacketRequest, result: VerdictResult) -> None:
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "type": "VERDICT",
            "packet_id": result.packet_id,
            "src_ip": request.src_ip,
            "dst_ip": request.dst_ip,
            "protocol": request.protocol,
            "length": request.length,
            "verdict": result.verdict.value,
            "confidence": round(result.confidence, 6),
            "action": result.action.value,
            "blocked": result.blocked,
        }
        self._verdict_logger.info(json.dumps(entry, separators=(",", ":")))

    def log_block(self, ip: str, zone: str, reason: str) -> None:
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "type": "BLOCK",
            "src_ip": ip,
            "zone": zone,
            "reason": reason,
        }
        self._block_logger.info(json.dumps(entry, separators=(",", ":")))

    def log_alert(self, ip: str, alert_type: str, details: str) -> None:
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "type": "ALERT",
            "src_ip": ip,
            "alert_type": alert_type,
            "details": details,
        }
        self._alert_logger.info(json.dumps(entry, separators=(",", ":")))
