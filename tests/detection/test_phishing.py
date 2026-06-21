"""Tests for the local, explainable phishing/scam URL analyzer."""

import unittest

from detection.phishing import _levenshtein, analyze_domain, analyze_url


class LegitimateUrlsTestCase(unittest.TestCase):
    """Real brand and common domains must not be flagged (false-positive guard)."""

    def test_known_good_domains_are_low_risk(self):
        for url in (
            "https://github.com",
            "https://www.amazon.com/gp/cart",
            "https://accounts.google.com/signin",
            "https://paypal.com",
            "https://outlook.office365.com",
        ):
            verdict = analyze_url(url)
            self.assertEqual(verdict.risk, "low", f"{url} -> {verdict.score}: {verdict.reasons}")

    def test_brand_substring_domain_is_not_impersonation(self):
        # 'googleblog' contains 'google' but not at a label boundary -> no flag.
        verdict = analyze_url("https://googleblog.com")
        self.assertEqual(verdict.risk, "low")


class PhishingSignalsTestCase(unittest.TestCase):
    def test_ip_host_is_flagged(self):
        verdict = analyze_url("http://192.168.0.5/login.php")
        self.assertIn(verdict.risk, ("suspicious", "high"))
        self.assertTrue(any("IP address" in r for r in verdict.reasons))
        # An IP host must not also be described as having subdomains.
        self.assertFalse(any("subdomain" in r.lower() for r in verdict.reasons))

    def test_userinfo_trick_is_flagged(self):
        verdict = analyze_url("http://trusted.com@evil.com")
        self.assertIn(verdict.risk, ("suspicious", "high"))
        self.assertEqual(verdict.host, "evil.com")
        self.assertTrue(any("userinfo" in r.lower() for r in verdict.reasons))

    def test_typosquat_is_flagged_with_technique(self):
        verdict = analyze_url("https://paypa1.com")
        self.assertIn(verdict.risk, ("suspicious", "high"))
        self.assertTrue(any("typosquat" in r.lower() for r in verdict.reasons))
        self.assertIn("T1566.002", verdict.techniques)

    def test_brand_impersonation_subdomain_is_flagged(self):
        verdict = analyze_url("https://paypal.secure-login.ru/verify")
        self.assertIn(verdict.risk, ("suspicious", "high"))
        self.assertTrue(any("impersonation" in r.lower() for r in verdict.reasons))

    def test_punycode_host_is_flagged(self):
        verdict = analyze_url("https://xn--pypal-4ve.com/login")
        self.assertIn(verdict.risk, ("suspicious", "high"))
        self.assertTrue(any("punycode" in r.lower() for r in verdict.reasons))

    def test_combined_signals_reach_high(self):
        verdict = analyze_url("http://paypal-login.verify-account.tk/secure?update=1")
        self.assertEqual(verdict.risk, "high")
        self.assertGreaterEqual(verdict.score, 60)

    def test_abused_tld_with_keywords_is_suspicious(self):
        verdict = analyze_url("https://secure-update-account-verify-login.tk/")
        self.assertIn(verdict.risk, ("suspicious", "high"))


class AnalyzerContractTestCase(unittest.TestCase):
    def test_reasons_always_present(self):
        for url in ("https://github.com", "http://192.168.0.5", "garbage"):
            self.assertTrue(analyze_url(url).reasons)

    def test_reasons_are_ascii_safe(self):
        # Reasons are printed to a Windows cp1252 console; guard against
        # reintroducing non-ASCII characters that crash the CLI.
        verdict = analyze_url("http://trusted.com@paypa1-login.tk/verify")
        for reason in verdict.reasons:
            reason.encode("ascii")  # raises UnicodeEncodeError on regression

    def test_score_is_bounded(self):
        verdict = analyze_url(
            "http://paypal-login.verify-account-secure-update.tk/signin?confirm=1"
        )
        self.assertGreaterEqual(verdict.score, 0)
        self.assertLessEqual(verdict.score, 100)

    def test_as_dict_shape(self):
        d = analyze_url("https://paypa1.com").as_dict()
        self.assertEqual(
            set(d), {"target", "host", "score", "risk", "reasons", "techniques"}
        )

    def test_bare_domain_parses_without_scheme(self):
        verdict = analyze_domain("paypa1.com")
        self.assertEqual(verdict.host, "paypa1.com")

    def test_custom_brand_extends_protection(self):
        # 'acmebank' is not a default brand; a typosquat is invisible until added.
        self.assertEqual(analyze_url("https://acmebnk.com").risk, "low")
        flagged = analyze_url("https://acmebnk.com", extra_brands={"acmebank"})
        self.assertIn(flagged.risk, ("suspicious", "high"))


class LevenshteinTestCase(unittest.TestCase):
    def test_distance_values(self):
        self.assertEqual(_levenshtein("paypal", "paypal"), 0)
        self.assertEqual(_levenshtein("paypa1", "paypal"), 1)
        self.assertEqual(_levenshtein("", "abc"), 3)
        self.assertEqual(_levenshtein("kitten", "sitting"), 3)


if __name__ == "__main__":
    unittest.main()
