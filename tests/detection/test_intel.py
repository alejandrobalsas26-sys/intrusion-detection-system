"""Tests for local threat-intelligence (IOC) matching and the ioc_match rule."""

import ipaddress
import tempfile
import time
import unittest
from pathlib import Path

from detection.correlation import rule_ioc_match
from detection.intel import ThreatIntel
from detection.normalize import NormalizedEvent


def _event(entity, name="syn_scan", category="network", severity="CRITICAL"):
    return NormalizedEvent(
        timestamp=time.time(),
        severity=severity,
        category=category,
        event_name=name,
        message=f"{name} from {entity}",
        entity=entity,
    )


class ThreatIntelMatchingTestCase(unittest.TestCase):
    def setUp(self):
        self.ti = ThreatIntel(
            ip_indicators={"10.0.0.9"},
            cidr_indicators=[ipaddress.ip_network("192.168.5.0/24")],
            domain_indicators={"evil.com", "paypa1.com"},
        )

    def test_exact_ip_match(self):
        self.assertEqual(self.ti.match_ip("10.0.0.9"), "10.0.0.9")

    def test_cidr_match(self):
        self.assertEqual(self.ti.match_ip("192.168.5.42"), "192.168.5.0/24")

    def test_ip_non_match(self):
        self.assertIsNone(self.ti.match_ip("8.8.8.8"))

    def test_invalid_ip_returns_none(self):
        self.assertIsNone(self.ti.match_ip("not-an-ip"))
        self.assertIsNone(self.ti.match_ip(None))

    def test_exact_domain_match(self):
        self.assertEqual(self.ti.match_domain("evil.com"), "evil.com")

    def test_subdomain_matches_listed_parent(self):
        self.assertEqual(self.ti.match_domain("login.paypa1.com"), "paypa1.com")

    def test_domain_non_match(self):
        self.assertIsNone(self.ti.match_domain("google.com"))

    def test_unrelated_suffix_does_not_match(self):
        # 'notevil.com' must not match a listed 'evil.com' (label boundary).
        self.assertIsNone(self.ti.match_domain("notevil.com"))

    def test_has_indicators(self):
        self.assertTrue(self.ti.has_indicators())
        self.assertFalse(ThreatIntel().has_indicators())


class ThreatIntelFileLoadingTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ioc_test_")

    def _write(self, name, content):
        path = Path(self.tmp, name)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_parses_ips_cidrs_comments_and_blanks(self):
        ip_path = self._write(
            "ips.txt",
            "# malicious IPs\n10.0.0.9\n\n192.168.5.0/24  # internal compromise\nbogus-line\n",
        )
        ti = ThreatIntel.from_files(ip_path=ip_path)
        self.assertEqual(ti.match_ip("10.0.0.9"), "10.0.0.9")
        self.assertEqual(ti.match_ip("192.168.5.7"), "192.168.5.0/24")
        # 'bogus-line' is silently skipped, not fatal.
        self.assertTrue(ti.has_indicators())

    def test_parses_domains(self):
        dom_path = self._write("domains.txt", "evil.com\n# comment\nPHISH.NET\n")
        ti = ThreatIntel.from_files(domain_path=dom_path)
        self.assertEqual(ti.match_domain("evil.com"), "evil.com")
        # Case-insensitive: stored lowercased.
        self.assertEqual(ti.match_domain("a.phish.net"), "phish.net")

    def test_missing_file_is_empty_not_error(self):
        ti = ThreatIntel.from_files(ip_path="/no/such/file.txt")
        self.assertFalse(ti.has_indicators())


class IocMatchRuleTestCase(unittest.TestCase):
    def test_no_indicators_is_noop(self):
        events = [_event("10.0.0.9")]
        self.assertEqual(rule_ioc_match(events, intel=ThreatIntel()), [])

    def test_matching_ip_raises_incident(self):
        ti = ThreatIntel(ip_indicators={"10.0.0.9"})
        events = [_event("10.0.0.9"), _event("10.0.0.9", name="arp_spoofing")]
        incidents = rule_ioc_match(events, intel=ti)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].rule_name, "ioc_match")
        self.assertIn("10.0.0.9", incidents[0].entities)
        # Both events referencing the entity are gathered into the incident.
        self.assertEqual(len(incidents[0].events), 2)

    def test_non_matching_entities_are_silent(self):
        ti = ThreatIntel(ip_indicators={"10.0.0.9"})
        events = [_event("8.8.8.8")]
        self.assertEqual(rule_ioc_match(events, intel=ti), [])

    def test_distinct_entities_get_distinct_incidents(self):
        ti = ThreatIntel(cidr_indicators=[ipaddress.ip_network("10.0.0.0/8")])
        events = [_event("10.1.1.1"), _event("10.2.2.2")]
        incidents = rule_ioc_match(events, intel=ti)
        self.assertEqual(len(incidents), 2)


if __name__ == "__main__":
    unittest.main()
