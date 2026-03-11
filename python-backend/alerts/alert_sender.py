"""
Alert sending system.
IAlertSender ABC with webhook and console implementations.
"""

import json
import time
import logging
import threading
from abc import ABC, abstractmethod
from typing import List, Optional
from models.packet_data import VerdictResult


logger = logging.getLogger("ids.alerts")


class IAlertSender(ABC):
    """Abstract Base Class for alert delivery."""

    @abstractmethod
    def send(self, result: VerdictResult, reason: str) -> bool:
        """
        Send an alert about a verdict.
        Returns True on successful delivery.
        """
        ...


class ConsoleAlertSender(IAlertSender):
    """Prints alerts to stdout — useful for development."""

    def send(self, result: VerdictResult, reason: str) -> bool:
        print(
            f"[ALERT] {result.verdict.value} | "
            f"IP: {result.src_ip} | "
            f"Conf: {result.confidence:.4f} | "
            f"Action: {result.action.value} | "
            f"Reason: {reason}"
        )
        return True


class WebhookAlertSender(IAlertSender):
    """Sends alerts via HTTP webhook (fire-and-forget, non-blocking)."""

    def __init__(self, webhook_url: str, timeout: float = 5.0):
        self._url = webhook_url
        self._timeout = timeout

    def send(self, result: VerdictResult, reason: str) -> bool:
        try:
            import urllib.request

            payload = json.dumps({
                "text": (
                    f"🚨 IDS Alert: {result.verdict.value}\n"
                    f"Source IP: {result.src_ip}\n"
                    f"Confidence: {result.confidence:.4f}\n"
                    f"Action: {result.action.value}\n"
                    f"Reason: {reason}"
                ),
                "packet_id": result.packet_id,
                "timestamp": result.timestamp,
            }).encode("utf-8")

            req = urllib.request.Request(
                self._url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status == 200
        except Exception as e:
            logger.warning(f"Webhook alert failed to {self._url}: {e}")
            return False


class AlertManager:
    """
    Coordinates alert routing.
    Evaluates whether a verdict should trigger alerts and dispatches to all senders.
    Thread-safe with rate limiting.
    """

    def __init__(
        self,
        senders: List[IAlertSender] = None,
        rate_limit_seconds: float = 10.0,
    ):
        self._senders: List[IAlertSender] = senders or []
        self._rate_limit = rate_limit_seconds
        self._last_alert: dict = {}  # ip -> timestamp
        self._lock = threading.Lock()

    def add_sender(self, sender: IAlertSender) -> None:
        self._senders.append(sender)

    def should_alert(self, result: VerdictResult) -> bool:
        """Only alert on MALICIOUS/CRITICAL, with per-IP rate limiting."""
        from models.packet_data import Zone
        if result.verdict not in (Zone.MALICIOUS, Zone.CRITICAL):
            return False

        now = time.time()
        with self._lock:
            last = self._last_alert.get(result.src_ip, 0)
            if now - last < self._rate_limit:
                return False
            self._last_alert[result.src_ip] = now
        return True

    def dispatch(self, result: VerdictResult, reason: str) -> int:
        """
        Send alert to all registered senders.
        Returns number of successful deliveries.
        """
        if not self.should_alert(result):
            return 0

        successes = 0
        for sender in self._senders:
            try:
                if sender.send(result, reason):
                    successes += 1
            except Exception as e:
                logger.error(f"Alert sender {type(sender).__name__} failed: {e}")
        return successes
