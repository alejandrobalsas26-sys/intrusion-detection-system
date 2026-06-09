"""Tests for the AI assistance layer: client isolation and summarization
fallbacks. The LLM endpoint is always mocked — no network access."""

import io
import json
import unittest
from unittest.mock import patch

from ai.client import LocalLLMClient
from ai.summarize import summarize_events, summarize_incident

INCIDENT = {
    "id": 1,
    "rule_name": "brute_force_burst",
    "title": "Brute force suspected against user 'alice'",
    "severity": "WARNING",
    "risk_score": 57,
    "mitre_techniques": '["T1110"]',
    "entities": '["alice"]',
    "event_count": 6,
    "first_event_ts": 1750000000.0,
    "last_event_ts": 1750000050.0,
    "summary": "6 authentication failures for 'alice' within 300s.",
    "status": "open",
}


def _fake_llm_response(content: str):
    body = json.dumps({"choices": [{"message": {"content": content}}]}).encode()

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    return _Resp(body)


class LocalLLMClientTestCase(unittest.TestCase):
    def test_disabled_by_default(self):
        client = LocalLLMClient(backend="none")
        self.assertFalse(client.is_enabled())
        self.assertIsNone(client.complete("sys", "user"))

    def test_rejects_non_http_endpoint(self):
        client = LocalLLMClient(backend="ollama", endpoint="file:///etc/passwd")
        self.assertIsNone(client.complete("sys", "user"))

    @patch("ai.client.urllib.request.urlopen")
    def test_successful_completion(self, mock_urlopen):
        mock_urlopen.return_value = _fake_llm_response("Attack summary here.")
        client = LocalLLMClient(backend="ollama", endpoint="http://127.0.0.1:11434/v1/x")
        self.assertEqual(client.complete("sys", "user"), "Attack summary here.")

    @patch("ai.client.urllib.request.urlopen", side_effect=TimeoutError("slow"))
    def test_timeout_returns_none(self, _mock):
        client = LocalLLMClient(backend="ollama", endpoint="http://127.0.0.1:11434/v1/x")
        self.assertIsNone(client.complete("sys", "user"))

    @patch("ai.client.urllib.request.urlopen")
    def test_malformed_payload_returns_none(self, mock_urlopen):
        mock_urlopen.return_value = _fake_llm_response("")
        mock_urlopen.return_value = io.BytesIO(b"not json")
        mock_urlopen.return_value.__enter__ = lambda s: s
        mock_urlopen.return_value.__exit__ = lambda s, *a: None
        client = LocalLLMClient(backend="ollama", endpoint="http://127.0.0.1:11434/v1/x")
        self.assertIsNone(client.complete("sys", "user"))


class SummarizeFallbackTestCase(unittest.TestCase):
    def test_incident_summary_deterministic_when_disabled(self):
        result = summarize_incident(INCIDENT, client=LocalLLMClient(backend="none"))
        self.assertEqual(result["source"], "deterministic")
        self.assertIn("brute_force_burst", result["summary"])
        self.assertIn("alice", result["summary"])
        self.assertIn("T1110", result["summary"])

    @patch("ai.client.urllib.request.urlopen")
    def test_incident_summary_uses_llm_when_available(self, mock_urlopen):
        mock_urlopen.return_value = _fake_llm_response("LLM analysis of the incident.")
        client = LocalLLMClient(backend="ollama", endpoint="http://127.0.0.1:11434/v1/x")
        result = summarize_incident(INCIDENT, client=client)
        self.assertEqual(result["source"], "llm")
        self.assertEqual(result["summary"], "LLM analysis of the incident.")

    @patch("ai.client.urllib.request.urlopen", side_effect=TimeoutError("down"))
    def test_llm_failure_falls_back_to_deterministic(self, _mock):
        client = LocalLLMClient(backend="ollama", endpoint="http://127.0.0.1:11434/v1/x")
        result = summarize_incident(INCIDENT, client=client)
        self.assertEqual(result["source"], "deterministic")
        self.assertIn("brute_force_burst", result["summary"])

    def test_events_summary_deterministic_counts(self):
        events = [
            {"level": "WARNING", "module_source": "auth_core", "message": "fail"},
            {"level": "WARNING", "module_source": "auth_core", "message": "fail"},
            {"level": "CRITICAL", "module_source": "network_sensor", "message": "scan"},
        ]
        result = summarize_events(events, client=LocalLLMClient(backend="none"))
        self.assertEqual(result["source"], "deterministic")
        self.assertIn("3 event(s)", result["summary"])
        self.assertIn("WARNING=2", result["summary"])
        self.assertIn("network_sensor=1", result["summary"])

    def test_empty_events_summary(self):
        result = summarize_events([], client=LocalLLMClient(backend="none"))
        self.assertIn("0 event(s)", result["summary"])


if __name__ == "__main__":
    unittest.main()
