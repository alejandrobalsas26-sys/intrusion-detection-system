"""Local LLM client for analyst assistance. Privacy-preserving by design.

Talks to any OpenAI-compatible chat-completions endpoint (Ollama, llama.cpp
server, vLLM, LM Studio) using only the standard library — no new runtime
dependencies. Disabled unless AI_BACKEND is configured; every failure path
returns None so callers always fall back to deterministic output.

Environment:
    AI_BACKEND            'none' (default) or 'openai-compatible'
    AI_ENDPOINT           default http://127.0.0.1:11434/v1/chat/completions (Ollama)
    AI_MODEL              default 'llama3.2'
    AI_TIMEOUT_SECONDS    default 20
    AI_MAX_TOKENS         default 400

Event data never leaves the host unless the operator deliberately points
AI_ENDPOINT at a remote service.
"""

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

from logs.logger import get_logger

logger = get_logger("ai_assistant")

DEFAULT_ENDPOINT = "http://127.0.0.1:11434/v1/chat/completions"


class LocalLLMClient:
    """Minimal OpenAI-compatible chat client with hard failure isolation."""

    def __init__(
        self,
        backend: str | None = None,
        endpoint: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ):
        self.backend = (backend or os.getenv("AI_BACKEND", "none")).strip().lower()
        self.endpoint = endpoint or os.getenv("AI_ENDPOINT", DEFAULT_ENDPOINT)
        self.model = model or os.getenv("AI_MODEL", "llama3.2")
        self.timeout = timeout or float(os.getenv("AI_TIMEOUT_SECONDS", "20"))
        self.max_tokens = int(os.getenv("AI_MAX_TOKENS", "400"))

    def is_enabled(self) -> bool:
        return self.backend in ("openai-compatible", "ollama")

    def complete(self, system_prompt: str, user_prompt: str) -> str | None:
        """Returns the model's reply, or None on ANY failure (caller falls back)."""
        if not self.is_enabled():
            return None

        scheme = urlparse(self.endpoint).scheme
        if scheme not in ("http", "https"):
            logger.error("AI endpoint has unsupported scheme: %s", scheme)
            return None

        payload = json.dumps(
            {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
        ).encode()

        request = urllib.request.Request(  # noqa: S310 (scheme validated above)
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(  # noqa: S310 (scheme validated above)
                request, timeout=self.timeout
            ) as response:
                body = json.loads(response.read().decode())
            content = body["choices"][0]["message"]["content"]
            return content.strip() if isinstance(content, str) else None
        except (urllib.error.URLError, TimeoutError) as e:
            logger.warning("Local LLM endpoint unreachable: %s", e)
            return None
        except (KeyError, IndexError, json.JSONDecodeError, ValueError) as e:
            logger.warning("Local LLM returned an unexpected payload: %s", e)
            return None
        except Exception:
            logger.exception("Unexpected error calling local LLM")
            return None
