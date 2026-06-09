"""MITRE ATT&CK technique mapping for Antigravity-IDS event types.

Maps the platform's canonical event names (see `detection.normalize`) to
ATT&CK technique identifiers so analysts can pivot from an alert directly
into the framework. Mappings are intentionally conservative: only techniques
the detector can actually evidence are listed.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        base = self.technique_id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{base}/"


# Canonical event name -> ATT&CK techniques evidenced by that event.
EVENT_TECHNIQUE_MAP: dict[str, tuple[Technique, ...]] = {
    "syn_scan": (Technique("T1046", "Network Service Discovery", "discovery"),),
    "arp_spoofing": (
        Technique("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning", "credential-access"),
    ),
    "AUTH_FAILURE": (Technique("T1110", "Brute Force", "credential-access"),),
    "RATE_LIMITED": (Technique("T1110", "Brute Force", "credential-access"),),
    "REPLAY_ATTACK": (
        Technique("T1550", "Use Alternate Authentication Material", "lateral-movement"),
    ),
    "FIM_MODIFIED": (Technique("T1565.001", "Data Manipulation: Stored Data", "impact"),),
    "FIM_DELETED": (
        Technique("T1070.004", "Indicator Removal: File Deletion", "defense-evasion"),
    ),
    "FIM_CREATED": (Technique("T1105", "Ingress Tool Transfer", "command-and-control"),),
}


def techniques_for(event_name: str) -> tuple[Technique, ...]:
    """Returns the ATT&CK techniques evidenced by a canonical event name."""
    return EVENT_TECHNIQUE_MAP.get(event_name, ())


def technique_ids_for(event_name: str) -> list[str]:
    """Returns just the technique ID strings (e.g. for JSON serialization)."""
    return [t.technique_id for t in techniques_for(event_name)]
