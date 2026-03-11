"""
Domain models for the IDS Python backend.
Defines enums, request/response schemas, and validation.
"""

import re
import uuid
import base64
from enum import Enum
from typing import Optional
from dataclasses import dataclass
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class Zone(str, Enum):
    """Classification zone for a packet verdict."""
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CRITICAL = "CRITICAL"
    BLOCKED = "BLOCKED"


class Action(str, Enum):
    """Enforcement action to take on a packet."""
    PASS = "PASS"
    FLAG = "FLAG"
    DROP = "DROP"


_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "OTHER"}


class PacketRequest(BaseModel):
    """
    Validated request model for incoming packet data from the Java backend.
    All fields are validated per the IDS specification.
    """
    src_ip: str = Field(..., description="Source IPv4 address")
    dst_ip: str = Field(..., description="Destination IPv4 address")
    protocol: str = Field(..., description="Protocol: TCP, UDP, ICMP, or OTHER")
    length: int = Field(..., ge=0, le=65535, description="Packet length in bytes")
    payload: str = Field(default="", description="Base64-encoded payload, max 131072 chars")
    timestamp: str = Field(..., description="ISO-8601 formatted timestamp")

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ipv4(cls, v: str) -> str:
        if not _IPV4_PATTERN.match(v):
            raise ValueError(f"Invalid IPv4 address: {v}")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        upper = v.upper()
        if upper not in _ALLOWED_PROTOCOLS:
            raise ValueError(f"Protocol must be one of {_ALLOWED_PROTOCOLS}, got: {v}")
        return upper

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, v: str) -> str:
        if len(v) > 131072:
            raise ValueError(f"Payload too large: {len(v)} chars (max 131072)")
        if v:
            try:
                base64.b64decode(v, validate=True)
            except Exception:
                raise ValueError("Payload is not valid base64")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            raise ValueError(f"Invalid ISO-8601 timestamp: {v}")
        return v


@dataclass(frozen=True)
class VerdictResult:
    """
    Immutable verdict result returned by the /analyze endpoint.
    Never includes raw payload data.
    """
    packet_id: str
    src_ip: str
    verdict: Zone
    confidence: float
    action: Action
    blocked: bool
    ip_event_count: int
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "packet_id": self.packet_id,
            "src_ip": self.src_ip,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "action": self.action.value,
            "blocked": self.blocked,
            "ip_event_count": self.ip_event_count,
            "timestamp": self.timestamp,
        }

    @staticmethod
    def create(
        src_ip: str,
        verdict: Zone,
        confidence: float,
        action: Action,
        blocked: bool,
        ip_event_count: int,
    ) -> "VerdictResult":
        return VerdictResult(
            packet_id=str(uuid.uuid4()),
            src_ip=src_ip,
            verdict=verdict,
            confidence=confidence,
            action=action,
            blocked=blocked,
            ip_event_count=ip_event_count,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
