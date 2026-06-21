"""Event normalization: one canonical envelope for every telemetry source.

The platform emits three sibling dataclasses (`network.detectors.DetectionEvent`,
`auth.core.AuthEvent`, `fim.monitor.FimEvent`) plus raw `audit_events` rows.
`NormalizedEvent` is the common schema the correlation engine, scoring model,
and future Sigma support all consume. Source dataclasses are NOT modified —
this layer only reads them.
"""

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from detection.mitre import technique_ids_for
from detection.scoring import risk_score

# Extracts the username from auth module messages, e.g.
# "Authentication failed for user 'alice'." Case-insensitive because the auth
# core capitalizes the word in success messages ("User 'alice' authenticated
# successfully."); without IGNORECASE those AUTH_SUCCESS events would normalize
# with no entity, breaking any rule that correlates a success back to a user.
_USER_RE = re.compile(r"user '([^']+)'", re.IGNORECASE)
# Extracts detector name from network sensor audit messages, e.g.
# "DetectionEvent: CRITICAL from syn_scan - SYN scan detected from 10.0.0.9: ..."
_DETECTOR_RE = re.compile(r"DetectionEvent: \w+ from (\w+)")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass
class NormalizedEvent:
    """Canonical event envelope shared by all detection-engineering consumers."""

    timestamp: float
    severity: str  # INFO / WARNING / ERROR / CRITICAL
    category: str  # network / auth / fim / system
    event_name: str  # canonical name, e.g. syn_scan, AUTH_FAILURE, FIM_MODIFIED
    message: str
    entity: str | None = None  # primary subject: source IP, username, or filepath
    source_module: str = ""
    event_id: int | None = None  # audit_events.id when sourced from the DB
    context: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    risk_score: int = 0

    def __post_init__(self):
        if not self.mitre_techniques:
            self.mitre_techniques = technique_ids_for(self.event_name)
        if not self.risk_score:
            self.risk_score = risk_score(self.severity, self.event_name, self.context)


def from_detection_event(event) -> NormalizedEvent:
    """Normalizes a network `DetectionEvent` (duck-typed; class unmodified)."""
    ctx = dict(event.context or {})
    entity = ctx.get("source_ip") or ctx.get("ip_address")
    return NormalizedEvent(
        timestamp=event.timestamp,
        severity=event.level,
        category="network",
        event_name=event.detector_name,
        message=event.message,
        entity=entity,
        source_module=event.module_source,
        context=ctx,
    )


def from_auth_event(event) -> NormalizedEvent:
    """Normalizes an `AuthEvent` (duck-typed; class unmodified)."""
    match = _USER_RE.search(event.message)
    return NormalizedEvent(
        timestamp=event.timestamp,
        severity=event.level,
        category="auth",
        event_name=event.event_name,
        message=event.message,
        entity=match.group(1) if match else None,
        source_module=event.module_source,
        context=dict(event.context or {}),
    )


def from_fim_event(event) -> NormalizedEvent:
    """Normalizes a `FimEvent` (duck-typed; class unmodified)."""
    return NormalizedEvent(
        timestamp=event.timestamp,
        severity=event.level,
        category="fim",
        event_name=f"FIM_{event.event_type}",
        message=event.message,
        entity=event.filepath,
        source_module=event.module_source,
        context={"event_type": event.event_type, "filepath": event.filepath},
    )


def _classify_audit_row(module: str, message: str, context: dict) -> tuple[str, str, str | None]:
    """Derives (category, event_name, entity) from a raw audit_events row."""
    if module in ("network_sensor", "network"):
        detector = _DETECTOR_RE.search(message)
        ip = _IP_RE.search(message)
        return ("network", detector.group(1) if detector else "network_event",
                ip.group(1) if ip else None)

    if module in ("auth_core", "auth"):
        reason = context.get("reason_code", "")
        user = _USER_RE.search(message)
        entity = user.group(1) if user else None
        if "authenticated successfully" in message:
            return ("auth", "AUTH_SUCCESS", entity)
        if "Replay attack" in message:
            return ("auth", "REPLAY_ATTACK", entity)
        if reason == "RATE_LIMITED" or "Rate limited" in message:
            return ("auth", "RATE_LIMITED", entity)
        if "Authentication failed" in message:
            return ("auth", "AUTH_FAILURE", entity)
        if "revoked" in message:
            return ("auth", "USER_REVOKED", entity)
        return ("auth", "AUTH_EVENT", entity)

    if module in ("fim_monitor", "fim"):
        if "deleted" in message.lower():
            name = "FIM_DELETED"
        elif "integrity breach" in message.lower() or "modified" in message.lower():
            name = "FIM_MODIFIED"
        else:
            name = "FIM_EVENT"
        # FIM messages embed the path, e.g. "... breach detected in /etc/passwd."
        entity = None
        for marker in ("file ", " in "):
            if marker in message:
                tail = message.split(marker, 1)[1].strip().rstrip(".")
                if tail:
                    entity = tail.split()[0]
                    break
        return ("fim", name, entity)

    return ("system", "SYSTEM_EVENT", None)


def from_audit_row(row: dict) -> NormalizedEvent:
    """Normalizes a raw `audit_events` row (dict with the table's columns)."""
    try:
        context = json.loads(row.get("context_data") or "{}")
        if not isinstance(context, dict):
            context = {"raw": context}
    except (json.JSONDecodeError, TypeError):
        context = {}

    module = row.get("module_source", "")
    message = row.get("message", "")
    category, event_name, entity = _classify_audit_row(module, message, context)

    return NormalizedEvent(
        timestamp=float(row.get("timestamp") or time.time()),
        severity=row.get("level", "INFO"),
        category=category,
        event_name=event_name,
        message=message,
        entity=entity,
        source_module=module,
        event_id=row.get("id"),
        context=context,
    )
