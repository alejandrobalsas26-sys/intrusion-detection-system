"""Analyst playbooks: per-rule confidence, tactic, and remediation guidance.

Turns a bare incident (rule + score) into something an analyst can act on:
*why* to believe it (confidence), *what* it represents (ATT&CK tactic), and
*what to do next* (concrete, IDS-specific remediation steps). This is read-time
enrichment — nothing here is persisted, so the mapping can evolve freely without
a schema migration, and incidents from older sweeps gain the guidance too.

Confidence is a base reliability estimate per rule (how prone the detection is to
false positives), nudged up by corroborating events on a specific incident.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Playbook:
    rule_name: str
    tactic: str  # human-readable ATT&CK tactic
    confidence: int  # base 0-100 reliability of the detection
    remediation: tuple[str, ...]
    references: tuple[str, ...] = field(default_factory=tuple)


PLAYBOOKS: dict[str, Playbook] = {
    "brute_force_burst": Playbook(
        rule_name="brute_force_burst",
        tactic="Credential Access",
        confidence=70,
        remediation=(
            "Confirm whether the source is a legitimate user failing repeatedly or an attacker.",
            "If malicious, block the source at the firewall/reverse proxy and consider revoking "
            "the targeted account: python -m auth.cli revoke <user>.",
            "Verify MFA_BACKOFF_MODE=reject and the dashboard login rate limit are active.",
        ),
        references=("https://attack.mitre.org/techniques/T1110/",),
    ),
    "password_spray": Playbook(
        rule_name="password_spray",
        tactic="Credential Access",
        confidence=65,
        remediation=(
            "Identify the common source(s) of the failures and block them upstream.",
            "Notify targeted users; require secret rotation for any account that then succeeded.",
            "Only raise CORRELATION_PASSWORD_SPRAY_USER_THRESHOLD after confirming a benign cause.",
        ),
        references=("https://attack.mitre.org/techniques/T1110/003/",),
    ),
    "auth_success_after_failures": Playbook(
        rule_name="auth_success_after_failures",
        tactic="Credential Access / Valid Accounts",
        confidence=80,
        remediation=(
            "Treat the account as potentially compromised until verified with the user.",
            "Revoke then re-enroll the user's TOTP: python -m auth.cli revoke <user>.",
            "Review activity following the successful login for signs of lateral movement.",
        ),
        references=("https://attack.mitre.org/techniques/T1078/",),
    ),
    "replay_attack": Playbook(
        rule_name="replay_attack",
        tactic="Lateral Movement",
        confidence=85,
        remediation=(
            "A TOTP or recovery code was reused within its window — assume token interception.",
            "Revoke the affected user and re-enroll; investigate for a stolen device or MITM.",
            "Preserve the audit trail before remediation: python -m logs seal.",
        ),
        references=("https://attack.mitre.org/techniques/T1550/",),
    ),
    "recon_then_auth": Playbook(
        rule_name="recon_then_auth",
        tactic="Discovery → Credential Access",
        confidence=60,
        remediation=(
            "Correlate the scanning source IP with the subsequent authentication failures.",
            "Block the source and watch for follow-on exploitation attempts.",
        ),
        references=("https://attack.mitre.org/techniques/T1046/",),
    ),
    "network_then_fim": Playbook(
        rule_name="network_then_fim",
        tactic="Impact / Defense Evasion",
        confidence=75,
        remediation=(
            "A monitored file changed right after a network attack — treat as a likely intrusion.",
            "Isolate the host, restore the file from a known-good baseline, then run: "
            "python -m logs check.",
            "Preserve logs and the audit database for forensics before remediating.",
        ),
        references=("https://attack.mitre.org/techniques/T1565/",),
    ),
    "ioc_match": Playbook(
        rule_name="ioc_match",
        tactic="Command and Control",
        confidence=90,
        remediation=(
            "The entity matches your threat-intel watchlist — block it at the perimeter now.",
            "Hunt for other activity involving the same indicator across the audit log.",
            "Confirm the indicator is still valid; stale IOCs cause avoidable noise.",
        ),
    ),
}

_GENERIC = Playbook(
    rule_name="generic",
    tactic="Unknown",
    confidence=50,
    remediation=(
        "Review the correlated events and the involved entities.",
        "Confirm whether the activity is expected before taking action.",
    ),
)


def playbook_for(rule_name: str) -> Playbook:
    """Returns the playbook for a rule, or a safe generic fallback."""
    return PLAYBOOKS.get(rule_name, _GENERIC)


def confidence_for(rule_name: str, event_count: int = 1) -> int:
    """Base confidence nudged up by corroborating events (capped at 100)."""
    base = playbook_for(rule_name).confidence
    corroboration = min(10, max(0, event_count - 1) * 2)
    return min(100, base + corroboration)


def enrich_incident(incident: dict) -> dict:
    """Adds tactic/confidence/remediation/references to an incident dict in place.

    Additive only: existing keys are never overwritten, so API consumers relying
    on the original shape are unaffected.
    """
    pb = playbook_for(incident.get("rule_name", ""))
    incident.setdefault("tactic", pb.tactic)
    incident.setdefault(
        "confidence", confidence_for(incident.get("rule_name", ""), incident.get("event_count", 1))
    )
    incident.setdefault("remediation", list(pb.remediation))
    incident.setdefault("references", list(pb.references))
    return incident
