"""Unit tests for event normalization, MITRE mapping, and risk scoring."""

import json
import time

from auth.core import AuthEvent
from detection.mitre import technique_ids_for, techniques_for
from detection.normalize import (
    from_audit_row,
    from_auth_event,
    from_detection_event,
    from_fim_event,
)
from detection.scoring import explain, incident_score, risk_score
from fim.monitor import FimEvent
from network.detectors import DetectionEvent


class TestNormalization:
    def test_detection_event_normalizes_with_entity_and_mitre(self):
        event = DetectionEvent(
            level="CRITICAL",
            module_source="network",
            detector_name="syn_scan",
            message="SYN scan detected from 10.0.0.9: 25 unique ports in 10s window.",
            timestamp=time.time(),
            context={"source_ip": "10.0.0.9", "port_count": 25},
        )
        norm = from_detection_event(event)
        assert norm.category == "network"
        assert norm.event_name == "syn_scan"
        assert norm.entity == "10.0.0.9"
        assert "T1046" in norm.mitre_techniques
        assert norm.risk_score > 75  # CRITICAL base + bonuses

    def test_arp_event_uses_ip_address_context_key(self):
        event = DetectionEvent(
            level="CRITICAL",
            module_source="network",
            detector_name="arp_spoofing",
            message="ARP Spoofing detected for IP 192.168.1.5.",
            timestamp=time.time(),
            context={"ip_address": "192.168.1.5", "mac_history": ["aa", "bb", "cc"]},
        )
        norm = from_detection_event(event)
        assert norm.entity == "192.168.1.5"
        assert "T1557.002" in norm.mitre_techniques

    def test_auth_event_extracts_username(self):
        event = AuthEvent(
            level="WARNING",
            event_name="AUTH_FAILURE",
            message="Authentication failed for user 'alice'.",
            context={"reason_code": "INVALID_TOKEN"},
        )
        norm = from_auth_event(event)
        assert norm.category == "auth"
        assert norm.entity == "alice"
        assert "T1110" in norm.mitre_techniques

    def test_fim_event_normalizes_filepath_entity(self):
        event = FimEvent(
            level="CRITICAL",
            event_type="MODIFIED",
            filepath="/etc/passwd",
            message="CRITICAL: Integrity breach detected in /etc/passwd.",
        )
        norm = from_fim_event(event)
        assert norm.category == "fim"
        assert norm.event_name == "FIM_MODIFIED"
        assert norm.entity == "/etc/passwd"
        assert "T1565.001" in norm.mitre_techniques


class TestAuditRowNormalization:
    def test_network_audit_row_classified(self):
        row = {
            "id": 1,
            "timestamp": time.time(),
            "level": "CRITICAL",
            "module_source": "network_sensor",
            "message": (
                "DetectionEvent: CRITICAL from syn_scan - SYN scan detected "
                "from 10.0.0.9: 25 unique ports in 10s window."
            ),
            "context_data": None,
        }
        norm = from_audit_row(row)
        assert norm.category == "network"
        assert norm.event_name == "syn_scan"
        assert norm.entity == "10.0.0.9"
        assert norm.event_id == 1

    def test_auth_failure_audit_row_classified(self):
        row = {
            "id": 2,
            "timestamp": time.time(),
            "level": "WARNING",
            "module_source": "auth_core",
            "message": "Authentication failed for user 'bob'.",
            "context_data": json.dumps({"reason_code": "INVALID_TOKEN"}),
        }
        norm = from_audit_row(row)
        assert norm.event_name == "AUTH_FAILURE"
        assert norm.entity == "bob"

    def test_replay_attack_audit_row_classified(self):
        row = {
            "id": 3,
            "timestamp": time.time(),
            "level": "CRITICAL",
            "module_source": "auth_core",
            "message": "Replay attack detected for user 'eve'.",
            "context_data": "{}",
        }
        norm = from_audit_row(row)
        assert norm.event_name == "REPLAY_ATTACK"
        assert norm.entity == "eve"

    def test_malformed_context_does_not_crash(self):
        row = {
            "id": 4,
            "timestamp": time.time(),
            "level": "INFO",
            "module_source": "unknown_module",
            "message": "something",
            "context_data": "{not json",
        }
        norm = from_audit_row(row)
        assert norm.category == "system"
        assert norm.context == {}


class TestMitreMapping:
    def test_known_events_have_techniques(self):
        for name in ("syn_scan", "arp_spoofing", "AUTH_FAILURE", "REPLAY_ATTACK"):
            assert technique_ids_for(name), f"{name} should map to ATT&CK"

    def test_unknown_event_maps_to_nothing(self):
        assert technique_ids_for("TOTALLY_UNKNOWN") == []

    def test_technique_url_format(self):
        tech = techniques_for("arp_spoofing")[0]
        assert tech.url == "https://attack.mitre.org/techniques/T1557/002/"


class TestRiskScoring:
    def test_severity_ordering_preserved(self):
        assert risk_score("CRITICAL", "x") > risk_score("WARNING", "x")
        assert risk_score("WARNING", "x") > risk_score("INFO", "x")

    def test_scores_clamped_to_0_100(self):
        score = risk_score(
            "CRITICAL",
            "arp_spoofing",
            {"port_count": 10000, "mac_history": ["a"] * 10, "alert_threshold_exceeded": True},
        )
        assert 0 <= score <= 100

    def test_explain_components_sum_to_total(self):
        breakdown = explain("CRITICAL", "syn_scan", {"port_count": 50})
        parts = (
            breakdown["severity_base"]
            + breakdown["attack_mapped_bonus"]
            + breakdown["high_impact_bonus"]
            + breakdown["context_amplifier"]
        )
        assert breakdown["total"] == min(100, parts)

    def test_incident_score_rewards_cross_category(self):
        single = incident_score([80], distinct_categories=1)
        multi = incident_score([80, 40], distinct_categories=2)
        assert multi > single
        assert incident_score([]) == 0
