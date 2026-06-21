"""Tests for analyst playbooks: confidence, tactic, and remediation enrichment."""

import unittest

from detection.playbook import (
    PLAYBOOKS,
    confidence_for,
    enrich_incident,
    playbook_for,
)

# Every rule_name the correlation engine can persist must have a playbook.
_EXPECTED_RULES = {
    "brute_force_burst",
    "password_spray",
    "auth_success_after_failures",
    "replay_attack",
    "recon_then_auth",
    "network_then_fim",
    "ioc_match",
}


class PlaybookCoverageTestCase(unittest.TestCase):
    def test_all_known_rules_have_playbooks(self):
        self.assertTrue(_EXPECTED_RULES.issubset(set(PLAYBOOKS)))

    def test_every_playbook_has_remediation(self):
        for name, pb in PLAYBOOKS.items():
            self.assertTrue(pb.remediation, f"{name} has no remediation steps")
            self.assertTrue(0 <= pb.confidence <= 100)

    def test_unknown_rule_returns_generic(self):
        pb = playbook_for("totally_unknown_rule")
        self.assertEqual(pb.tactic, "Unknown")
        self.assertTrue(pb.remediation)


class ConfidenceTestCase(unittest.TestCase):
    def test_confidence_rises_with_corroboration(self):
        base = confidence_for("brute_force_burst", event_count=1)
        more = confidence_for("brute_force_burst", event_count=10)
        self.assertGreater(more, base)

    def test_confidence_capped_at_100(self):
        self.assertLessEqual(confidence_for("ioc_match", event_count=1000), 100)


class EnrichIncidentTestCase(unittest.TestCase):
    def test_adds_enrichment_keys(self):
        incident = {"rule_name": "auth_success_after_failures", "event_count": 6}
        enriched = enrich_incident(incident)
        self.assertEqual(enriched["tactic"], "Credential Access / Valid Accounts")
        self.assertIn("confidence", enriched)
        self.assertIsInstance(enriched["remediation"], list)
        self.assertTrue(enriched["remediation"])

    def test_does_not_overwrite_existing_keys(self):
        incident = {"rule_name": "brute_force_burst", "tactic": "Custom"}
        enrich_incident(incident)
        self.assertEqual(incident["tactic"], "Custom")

    def test_unknown_rule_still_enriches(self):
        incident = {"rule_name": "mystery", "event_count": 1}
        enrich_incident(incident)
        self.assertEqual(incident["confidence"], 50)
        self.assertTrue(incident["remediation"])


if __name__ == "__main__":
    unittest.main()
