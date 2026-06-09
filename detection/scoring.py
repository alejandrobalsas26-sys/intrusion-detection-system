"""Numeric risk scoring for normalized events and correlated incidents.

Produces a deterministic 0-100 score so the dashboard and correlation engine
can rank work for analysts instead of relying on bare severity strings.

Model: base score from severity, amplified by ATT&CK relevance and
contextual signals (attack volume, threshold breaches). Deliberately simple
and auditable — every component is visible in `explain()`.
"""

from typing import Any

from detection.mitre import technique_ids_for

SEVERITY_BASE: dict[str, int] = {
    "DEBUG": 0,
    "INFO": 10,
    "WARNING": 40,
    "ERROR": 55,
    "CRITICAL": 75,
}

# Event types with outsized real-world impact get a flat uplift.
HIGH_IMPACT_EVENTS = {"arp_spoofing", "REPLAY_ATTACK", "FIM_MODIFIED", "FIM_DELETED"}


def _context_amplifier(context: dict[str, Any]) -> int:
    """Bounded uplift from contextual volume/threshold signals."""
    bonus = 0
    port_count = context.get("port_count")
    if isinstance(port_count, int) and port_count > 0:
        bonus += min(10, port_count // 10)
    mac_history = context.get("mac_history")
    if isinstance(mac_history, list) and len(mac_history) > 2:
        bonus += 5
    if context.get("alert_threshold_exceeded"):
        bonus += 10
    return min(bonus, 15)


def risk_score(severity: str, event_name: str, context: dict[str, Any] | None = None) -> int:
    """Computes the 0-100 risk score for a single event."""
    score = SEVERITY_BASE.get((severity or "INFO").upper(), 10)
    if technique_ids_for(event_name):
        score += 5
    if event_name in HIGH_IMPACT_EVENTS:
        score += 5
    score += _context_amplifier(context or {})
    return max(0, min(100, score))


def explain(severity: str, event_name: str, context: dict[str, Any] | None = None) -> dict:
    """Returns the score with its components, for audit/UI transparency."""
    ctx = context or {}
    return {
        "severity_base": SEVERITY_BASE.get((severity or "INFO").upper(), 10),
        "attack_mapped_bonus": 5 if technique_ids_for(event_name) else 0,
        "high_impact_bonus": 5 if event_name in HIGH_IMPACT_EVENTS else 0,
        "context_amplifier": _context_amplifier(ctx),
        "total": risk_score(severity, event_name, ctx),
    }


def incident_score(event_scores: list[int], distinct_categories: int = 1) -> int:
    """Aggregates event scores into an incident score.

    The maximum event score anchors the incident; corroborating events and
    cross-category correlation (e.g. network + auth) push it higher.
    """
    if not event_scores:
        return 0
    score = max(event_scores)
    score += min(10, max(0, len(event_scores) - 1) * 2)  # corroboration
    score += max(0, distinct_categories - 1) * 5  # kill-chain breadth
    return max(0, min(100, score))
