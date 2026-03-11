"""
MITM-IDS Python Backend — FastAPI Application

Provides the ML-powered classification API consumed by the Java capture layer.
All endpoints follow the specification from todo.txt.

Routes:
  POST /api/analyze        — Main detection endpoint
  GET  /api/blocklist       — Current blocked IPs
  POST /api/blocklist/add   — Manually block an IP
  POST /api/blocklist/remove— Manually unblock an IP
  GET  /api/stats           — Runtime statistics
  GET  /api/logs            — Tail log files
  GET  /health              — Liveness probe
"""

import os
import time
import json
import re
from datetime import datetime
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Response
from pydantic import BaseModel

# Local imports
from config import IDSConfig
from models.packet_data import PacketRequest, VerdictResult, Zone, Action
from classifiers.xgboost_classifier import XGBoostClassifier
from policies.ip_policy import SlidingWindowPolicy
from logging_.base_logger import FileLogger
from alerts.alert_sender import AlertManager, ConsoleAlertSender, WebhookAlertSender


# ── Bootstrap ────────────────────────────────────────────────────────
cfg = IDSConfig.load()

# Resolve paths relative to this file
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _resolve(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(_BASE_DIR, path)


# 1. Classifier
classifier = XGBoostClassifier(
    model_path=_resolve(cfg.get("model.path")),
    feature_names_path=_resolve(cfg.get("model.feature_names_path")),
)
classifier.update_thresholds(
    suspicious=cfg.get("thresholds.suspicious"),
    malicious=cfg.get("thresholds.malicious"),
    critical=cfg.get("thresholds.critical"),
)

# 2. Policy
whitelist_ips = cfg.load_whitelist()
policy = SlidingWindowPolicy(
    malicious_threshold=cfg.get("policy.malicious_threshold"),
    malicious_window=cfg.get("policy.malicious_window_sec"),
    suspicious_threshold=cfg.get("policy.suspicious_threshold"),
    suspicious_window=cfg.get("policy.suspicious_window_sec"),
    block_duration=cfg.get("policy.block_duration_sec"),
    whitelist=whitelist_ips,
)

# 3. Logger
ids_logger = FileLogger(
    log_dir=_resolve(cfg.get("logging.log_dir")),
    max_bytes=cfg.get("logging.max_bytes"),
    backup_count=cfg.get("logging.backup_count"),
)

# 4. Alerts
alert_manager = AlertManager(rate_limit_seconds=cfg.get("alerts.rate_limit_seconds"))
alert_manager.add_sender(ConsoleAlertSender())
if cfg.get("alerts.enabled") and cfg.get("alerts.webhook_url"):
    alert_manager.add_sender(WebhookAlertSender(cfg.get("alerts.webhook_url")))

# 5. Stats
_stats = {
    "total_analyzed": 0,
    "benign": 0,
    "suspicious": 0,
    "malicious": 0,
    "critical": 0,
    "blocked": 0,
    "start_time": time.time(),
}


# ── FastAPI App ──────────────────────────────────────────────────────
app = FastAPI(
    title="MITM-IDS ML Engine",
    version="2.0.0",
    description="Intrusion Detection System — Python Classification Backend",
)


# ── POST /api/analyze ────────────────────────────────────────────────
@app.post("/api/analyze")
async def analyze_packet(request: PacketRequest):
    """
    Main detection pipeline:
      1. Check blocklist
      2. Run ML classification
      3. Apply enforcement policy
      4. Log verdict
      5. Dispatch alerts if needed
      6. Return VerdictResult (never includes raw payload)
    """
    _stats["total_analyzed"] += 1
    src_ip = request.src_ip

    # 1. Check blocklist
    if policy.is_blocked(src_ip):
        result = VerdictResult.create(
            src_ip=src_ip,
            verdict=Zone.BLOCKED,
            confidence=1.0,
            action=Action.DROP,
            blocked=True,
            ip_event_count=policy.get_event_count(src_ip),
        )
        _stats["blocked"] += 1
        ids_logger.log_verdict(request, result)
        return result.to_dict()

    # 2. ML classification — build feature dict from request
    features = {
        "src_ip": src_ip,
        "dst_ip": request.dst_ip,
        "protocol": request.protocol,
        "length": request.length,
    }
    confidence, zone = classifier.classify(features)

    # Track stats
    zone_key = zone.value.lower()
    if zone_key in _stats:
        _stats[zone_key] += 1

    # 3. Apply enforcement policy
    action = policy.process_verdict(src_ip, zone, confidence)
    is_blocked = action == Action.DROP

    if is_blocked:
        _stats["blocked"] += 1

    result = VerdictResult.create(
        src_ip=src_ip,
        verdict=zone,
        confidence=confidence,
        action=action,
        blocked=is_blocked,
        ip_event_count=policy.get_event_count(src_ip),
    )

    # 4. Log
    ids_logger.log_verdict(request, result)
    if is_blocked:
        ids_logger.log_block(src_ip, zone.value, "Policy threshold exceeded")

    # 5. Alerts
    alert_manager.dispatch(result, f"Zone={zone.value}, Confidence={confidence:.4f}")

    return result.to_dict()


# ── GET /api/blocklist ───────────────────────────────────────────────
@app.get("/api/blocklist")
async def get_blocklist():
    """Return currently blocked IPs with expiry info."""
    blocks = policy.blocklist
    now = time.time()
    return {
        "blocked_ips": [
            {"ip": ip, "expires_in_sec": max(0, int(exp - now))}
            for ip, exp in blocks.items()
        ],
        "count": len(blocks),
    }


# ── POST /api/blocklist/add ──────────────────────────────────────────
def sanitize_and_validate_ip(ip: str) -> str:
    clean_ip = ip.strip()
    if not re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)$", clean_ip):
        raise ValueError("Invalid IP format")
    if clean_ip in ("127.0.0.1", "0.0.0.0"):
        raise ValueError("IDOR Protection: Cannot modify system IPs")
    return clean_ip

class BlockRequest(BaseModel):
    ip: str
    duration_sec: Optional[int] = None
    model_config = {"extra": "forbid"}

@app.post("/api/blocklist/add")
async def add_to_blocklist(req: BlockRequest):
    """Manually block an IP address."""
    try:
        clean_ip = sanitize_and_validate_ip(req.ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    policy.add_to_blocklist(clean_ip, req.duration_sec)
    ids_logger.log_block(clean_ip, "MANUAL", "Administrator action")
    return {"message": f"IP {clean_ip} blocked", "blocked": True}


# ── POST /api/blocklist/remove ───────────────────────────────────────
class UnblockRequest(BaseModel):
    ip: str
    model_config = {"extra": "forbid"}

@app.post("/api/blocklist/remove")
async def remove_from_blocklist(req: UnblockRequest):
    """Manually unblock an IP address."""
    try:
        clean_ip = sanitize_and_validate_ip(req.ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    policy.remove_from_blocklist(clean_ip)
    return {"message": f"IP {clean_ip} removed from blocklist", "blocked": False}


# ── GET /api/stats ───────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    """Return real-time detection statistics."""
    uptime = time.time() - _stats["start_time"]
    return {
        **_stats,
        "uptime_seconds": int(uptime),
        "currently_blocked_count": len(policy.blocked_ips),
        "whitelisted_count": len(policy.whitelist),
    }


# ── GET /api/logs ────────────────────────────────────────────────────
@app.get("/api/logs")
async def get_logs(
    type: str = Query("verdicts", pattern="^(verdicts|blocks|alerts)$"),
    lines: int = Query(50, ge=1, le=500),
):
    """Tail the last N entries from a log file."""
    log_dir = _resolve(cfg.get("logging.log_dir"))
    log_file = os.path.join(log_dir, f"{type}.log")

    if not os.path.exists(log_file):
        return {"logs": [], "count": 0}

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
            tail = all_lines[-lines:]
            # Parse JSON lines for structured output
            parsed = []
            for line in tail:
                line = line.strip()
                if line:
                    try:
                        parsed.append(json.loads(line))
                    except json.JSONDecodeError:
                        parsed.append({"raw": line})
            return {"logs": parsed, "count": len(parsed)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading logs: {str(e)}")


# ── GET /health ──────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    """Liveness probe for the Java backend to check connectivity."""
    return {
        "status": "ok",
        "version": "2.0.0",
        "model": classifier.model_version,
        "uptime_seconds": int(time.time() - _stats["start_time"]),
    }


# ── Entrypoint ───────────────────────────────────────────────────────
if __name__ == "__main__":
    host = cfg.get("server.host", "0.0.0.0")
    port = cfg.get("server.port", 8000)
    print(f"Starting IDS ML Engine on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
