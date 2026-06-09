"""Optional local-LLM analyst assistance. Privacy-preserving and fully
degradable: with AI_BACKEND unset every function still returns deterministic
summaries, so no workflow ever depends on a model being available."""

from ai.client import LocalLLMClient
from ai.summarize import summarize_events, summarize_incident

__all__ = ["LocalLLMClient", "summarize_events", "summarize_incident"]
