"""Detection engineering core: normalization, scoring, MITRE mapping,
deduplication, and the correlation engine.

Public API:
    NormalizedEvent, from_detection_event, from_auth_event, from_fim_event,
    from_audit_row, risk_score, incident_score, techniques_for,
    EventDeduplicator, CorrelationEngine
"""

from detection.correlation import CorrelationEngine, IncidentCandidate
from detection.dedup import EventDeduplicator
from detection.mitre import Technique, technique_ids_for, techniques_for
from detection.normalize import (
    NormalizedEvent,
    from_audit_row,
    from_auth_event,
    from_detection_event,
    from_fim_event,
)
from detection.scoring import incident_score, risk_score

__all__ = [
    "CorrelationEngine",
    "EventDeduplicator",
    "IncidentCandidate",
    "NormalizedEvent",
    "Technique",
    "from_audit_row",
    "from_auth_event",
    "from_detection_event",
    "from_fim_event",
    "incident_score",
    "risk_score",
    "technique_ids_for",
    "techniques_for",
]
