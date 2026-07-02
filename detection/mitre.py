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
    "icmp_sweep": (Technique("T1018", "Remote System Discovery", "discovery"),),
    "dns_ioc_query": (
        Technique("T1071.004", "Application Layer Protocol: DNS", "command-and-control"),
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
    # Synthetic keys: these are never produced by event normalization, so they
    # never tag a real event. They exist so correlation *rules* can attach a
    # precise sub-technique (via IncidentCandidate.extra_techniques) and so name
    # lookups (e.g. the AI summarizer) resolve the human-readable label.
    "password_spray": (
        Technique("T1110.003", "Brute Force: Password Spraying", "credential-access"),
    ),
    "credential_stuffing": (
        Technique("T1110.004", "Brute Force: Credential Stuffing", "credential-access"),
    ),
    "valid_accounts_suspected": (
        Technique("T1078", "Valid Accounts", "defense-evasion"),
    ),
}

# Flat technique_id -> Technique registry, derived once from the event map, for
# callers that look up a technique by its identifier (rules, playbooks).
TECHNIQUE_REGISTRY: dict[str, "Technique"] = {
    t.technique_id: t for techniques in EVENT_TECHNIQUE_MAP.values() for t in techniques
}


def techniques_for(event_name: str) -> tuple[Technique, ...]:
    """Returns the ATT&CK techniques evidenced by a canonical event name."""
    return EVENT_TECHNIQUE_MAP.get(event_name, ())


def technique_ids_for(event_name: str) -> list[str]:
    """Returns just the technique ID strings (e.g. for JSON serialization)."""
    return [t.technique_id for t in techniques_for(event_name)]


def technique_by_id(technique_id: str) -> Technique | None:
    """Looks up a known Technique by its ATT&CK identifier (or None)."""
    return TECHNIQUE_REGISTRY.get(technique_id)
