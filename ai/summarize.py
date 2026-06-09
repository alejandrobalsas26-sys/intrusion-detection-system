"""Analyst-facing summarization of alerts and incidents.

Every function returns a result regardless of LLM availability: when the
local model is disabled or fails, a deterministic template summary is
produced instead, and the `source` field says which path was taken. This
keeps SOC workflows functional offline and makes the AI layer purely
additive.
"""

import json
import time
from typing import Any

from ai.client import LocalLLMClient
from detection.mitre import EVENT_TECHNIQUE_MAP, Technique

_SYSTEM_PROMPT = (
    "You are a SOC analyst assistant for an intrusion detection system. "
    "Summarize the security data you are given in 3-5 plain sentences: what "
    "happened, why it matters, and a sensible first response step. Do not "
    "invent details that are not present in the data."
)


def _technique_names(technique_ids: list[str]) -> list[str]:
    known: dict[str, Technique] = {}
    for techniques in EVENT_TECHNIQUE_MAP.values():
        for t in techniques:
            known[t.technique_id] = t
    return [
        f"{tid} ({known[tid].name})" if tid in known else tid for tid in technique_ids
    ]


def _format_ts(epoch: float | None) -> str:
    if not epoch:
        return "unknown time"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def _deterministic_incident_summary(incident: dict[str, Any]) -> str:
    techniques = incident.get("mitre_techniques") or []
    if isinstance(techniques, str):
        try:
            techniques = json.loads(techniques)
        except json.JSONDecodeError:
            techniques = []
    entities = incident.get("entities") or []
    if isinstance(entities, str):
        try:
            entities = json.loads(entities)
        except json.JSONDecodeError:
            entities = []

    parts = [
        f"{incident.get('severity', 'UNKNOWN')} incident "
        f"'{incident.get('title', 'untitled')}' "
        f"(rule: {incident.get('rule_name', 'unknown')}, "
        f"risk score {incident.get('risk_score', '?')}/100).",
        f"It spans {incident.get('event_count', '?')} event(s) between "
        f"{_format_ts(incident.get('first_event_ts'))} and "
        f"{_format_ts(incident.get('last_event_ts'))}.",
    ]
    if entities:
        parts.append(f"Involved entities: {', '.join(str(e) for e in entities)}.")
    if techniques:
        parts.append(f"Mapped ATT&CK techniques: {', '.join(_technique_names(techniques))}.")
    if incident.get("summary"):
        parts.append(str(incident["summary"]))
    return " ".join(parts)


def summarize_incident(
    incident: dict[str, Any], client: LocalLLMClient | None = None
) -> dict[str, str]:
    """Returns {'summary': str, 'source': 'llm'|'deterministic'}."""
    llm = client or LocalLLMClient()
    deterministic = _deterministic_incident_summary(incident)

    if llm.is_enabled():
        reply = llm.complete(
            _SYSTEM_PROMPT,
            "Summarize this correlated security incident for an analyst:\n"
            + json.dumps(incident, default=str, indent=2),
        )
        if reply:
            return {"summary": reply, "source": "llm"}

    return {"summary": deterministic, "source": "deterministic"}


def summarize_events(
    events: list[dict[str, Any]], client: LocalLLMClient | None = None
) -> dict[str, str]:
    """Summarizes a batch of raw audit events (e.g. for a shift handover)."""
    llm = client or LocalLLMClient()

    by_level: dict[str, int] = {}
    by_module: dict[str, int] = {}
    for e in events:
        by_level[e.get("level", "UNKNOWN")] = by_level.get(e.get("level", "UNKNOWN"), 0) + 1
        module = e.get("module_source", "unknown")
        by_module[module] = by_module.get(module, 0) + 1

    deterministic = (
        f"{len(events)} event(s) observed. "
        f"By severity: {', '.join(f'{k}={v}' for k, v in sorted(by_level.items())) or 'none'}. "
        f"By source: {', '.join(f'{k}={v}' for k, v in sorted(by_module.items())) or 'none'}."
    )

    if llm.is_enabled() and events:
        reply = llm.complete(
            _SYSTEM_PROMPT,
            "Summarize these security audit events for a shift handover:\n"
            + json.dumps(events[:100], default=str, indent=2),
        )
        if reply:
            return {"summary": reply, "source": "llm"}

    return {"summary": deterministic, "source": "deterministic"}
