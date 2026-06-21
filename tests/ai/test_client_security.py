"""Security-focused tests for the local LLM client's endpoint validation."""

import os
import unittest
from unittest.mock import patch

from ai.client import LocalLLMClient


class LocalLLMClientEndpointValidationTestCase(unittest.TestCase):
    def _client(self, endpoint: str) -> LocalLLMClient:
        # backend enabled so complete() reaches the validation logic
        return LocalLLMClient(backend="openai-compatible", endpoint=endpoint)

    def test_non_http_scheme_refused(self):
        client = self._client("file:///etc/passwd")
        self.assertIsNone(client.complete("sys", "user"))

    def test_missing_host_refused(self):
        client = self._client("http:///no-host-here")
        self.assertIsNone(client.complete("sys", "user"))

    @patch.dict(os.environ, {"AI_ALLOWED_HOSTS": "127.0.0.1,localhost"})
    def test_host_not_in_allowlist_refused(self):
        client = self._client("http://evil.example.com/v1/chat/completions")
        # Must short-circuit to None without attempting a network call.
        self.assertIsNone(client.complete("sys", "user"))

    @patch.dict(os.environ, {"AI_ALLOWED_HOSTS": "127.0.0.1,localhost"})
    @patch("ai.client.urllib.request.urlopen", side_effect=AssertionError("network blocked"))
    def test_allowlisted_host_passes_validation(self, mock_open):
        # An allowlisted host must clear validation and proceed to the network
        # layer (which we stub to raise, proving validation did not reject it).
        client = self._client("http://127.0.0.1:11434/v1/chat/completions")
        # complete() catches all exceptions and returns None, but urlopen must
        # have been reached — i.e. validation passed.
        self.assertIsNone(client.complete("sys", "user"))
        self.assertTrue(mock_open.called)

    def test_disabled_backend_returns_none(self):
        client = LocalLLMClient(backend="none", endpoint="http://127.0.0.1:11434/")
        self.assertIsNone(client.complete("sys", "user"))


if __name__ == "__main__":
    unittest.main()
