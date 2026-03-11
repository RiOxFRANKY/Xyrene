"""
IP Enforcement Policies.
Implements IIPPolicy ABC and SlidingWindowPolicy with auto-expire blocklist.
"""

import time
import threading
from abc import ABC, abstractmethod
from typing import Dict, Set
from collections import deque
from models.packet_data import Zone, Action


class IIPPolicy(ABC):
    """Abstract Base Class for IP-based enforcement policies."""

    @abstractmethod
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        ...

    @abstractmethod
    def process_verdict(self, ip: str, zone: Zone, confidence: float) -> Action:
        """Process a verdict and return the enforcement action for this IP."""
        ...

    @abstractmethod
    def get_event_count(self, ip: str) -> int:
        """Return the current sliding-window event count for an IP."""
        ...


class SlidingWindowPolicy(IIPPolicy):
    """
    Stateful IP policy with sliding window event tracking and auto-expire blocklist.

    Blocking rules:
        - 3 MALICIOUS/CRITICAL events within 60s -> DROP (block for 300s)
        - 5 SUSPICIOUS events within 120s -> DROP (block for 300s)
    
    The blocklist is time-bounded: entries expire automatically after block_duration_sec.
    """

    def __init__(
        self,
        malicious_threshold: int = 3,
        malicious_window: float = 60.0,
        suspicious_threshold: int = 5,
        suspicious_window: float = 120.0,
        block_duration: float = 300.0,
        whitelist: Set[str] = None,
    ):
        self._malicious_threshold = malicious_threshold
        self._malicious_window = malicious_window
        self._suspicious_threshold = suspicious_threshold
        self._suspicious_window = suspicious_window
        self._block_duration = block_duration
        self._whitelist: Set[str] = whitelist or set()

        # IP -> deque of event timestamps
        self._malicious_events: Dict[str, deque] = {}
        self._suspicious_events: Dict[str, deque] = {}

        # IP -> block expiry time
        self._blocklist: Dict[str, float] = {}

        self._lock = threading.Lock()

    @property
    def blocklist(self) -> Dict[str, float]:
        """Return currently blocked IPs with their expiry times."""
        self._purge_expired()
        with self._lock:
            return dict(self._blocklist)

    @property
    def blocked_ips(self) -> Set[str]:
        """Return set of currently blocked IP addresses."""
        self._purge_expired()
        with self._lock:
            return set(self._blocklist.keys())

    @property
    def whitelist(self) -> Set[str]:
        return set(self._whitelist)

    def add_to_whitelist(self, ip: str) -> None:
        self._whitelist.add(ip)

    def remove_from_whitelist(self, ip: str) -> None:
        self._whitelist.discard(ip)

    def is_blocked(self, ip: str) -> bool:
        if ip in self._whitelist:
            return False
        self._purge_expired()
        with self._lock:
            return ip in self._blocklist

    def add_to_blocklist(self, ip: str, duration: float = None) -> None:
        """Manually block an IP."""
        if ip in self._whitelist:
            return
        dur = duration if duration is not None else self._block_duration
        with self._lock:
            self._blocklist[ip] = time.time() + dur

    def remove_from_blocklist(self, ip: str) -> None:
        """Manually unblock an IP."""
        with self._lock:
            self._blocklist.pop(ip, None)

    def get_event_count(self, ip: str) -> int:
        """Return total events (malicious + suspicious) in their respective windows."""
        now = time.time()
        count = 0
        with self._lock:
            if ip in self._malicious_events:
                q = self._malicious_events[ip]
                count += sum(1 for t in q if t > now - self._malicious_window)
            if ip in self._suspicious_events:
                q = self._suspicious_events[ip]
                count += sum(1 for t in q if t > now - self._suspicious_window)
        return count

    def process_verdict(self, ip: str, zone: Zone, confidence: float) -> Action:
        """
        Apply enforcement policy to a verdict.

        Returns PASS, FLAG, or DROP.
        """
        # Whitelisted IPs always pass
        if ip in self._whitelist:
            return Action.PASS

        # Already blocked -> DROP
        if self.is_blocked(ip):
            return Action.DROP

        now = time.time()

        with self._lock:
            if zone in (Zone.MALICIOUS, Zone.CRITICAL):
                dq = self._malicious_events.setdefault(ip, deque())
                dq.append(now)
                # Purge events outside window
                while dq and dq[0] < now - self._malicious_window:
                    dq.popleft()
                if len(dq) >= self._malicious_threshold:
                    self._blocklist[ip] = now + self._block_duration
                    return Action.DROP
                return Action.FLAG

            elif zone == Zone.SUSPICIOUS:
                dq = self._suspicious_events.setdefault(ip, deque())
                dq.append(now)
                while dq and dq[0] < now - self._suspicious_window:
                    dq.popleft()
                if len(dq) >= self._suspicious_threshold:
                    self._blocklist[ip] = now + self._block_duration
                    return Action.DROP
                return Action.FLAG

            elif zone == Zone.BLOCKED:
                return Action.DROP

            else:
                # BENIGN
                return Action.PASS

    def _purge_expired(self) -> None:
        """Remove expired entries from the blocklist."""
        now = time.time()
        with self._lock:
            expired = [ip for ip, exp in self._blocklist.items() if exp <= now]
            for ip in expired:
                del self._blocklist[ip]
