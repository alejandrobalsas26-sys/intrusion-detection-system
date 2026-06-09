"""Sliding-window event deduplication.

Detectors already clear their own state after alerting, but multiple layers
(sensor -> email, sensor -> log) can still emit the same logical event in
bursts. `EventDeduplicator` suppresses repeats of the same fingerprint inside
a configurable window. Off by default at every call site to preserve legacy
behavior.
"""

import hashlib
import threading
import time


class EventDeduplicator:
    """Thread-safe duplicate suppressor keyed by event fingerprint."""

    def __init__(self, window_seconds: float = 60.0, max_entries: int = 4096):
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def fingerprint(event_name: str, entity: str | None, severity: str = "") -> str:
        """Stable fingerprint for a logical event (not its timestamp/volume)."""
        raw = f"{event_name}|{entity or ''}|{severity}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_duplicate(self, fingerprint: str, now: float | None = None) -> bool:
        """Returns True (and keeps suppressing) if seen within the window.

        First sighting registers the fingerprint and returns False.
        """
        ts = now if now is not None else time.monotonic()
        with self._lock:
            self._evict(ts)
            last = self._seen.get(fingerprint)
            if last is not None and (ts - last) < self.window_seconds:
                return True
            self._seen[fingerprint] = ts
            return False

    def _evict(self, now: float) -> None:
        """Drops expired entries; bounds memory under sustained unique floods."""
        if len(self._seen) < self.max_entries:
            return
        cutoff = now - self.window_seconds
        self._seen = {fp: ts for fp, ts in self._seen.items() if ts >= cutoff}
        if len(self._seen) >= self.max_entries:
            # Still full of in-window entries: drop the oldest half deterministically.
            ordered = sorted(self._seen.items(), key=lambda kv: kv[1])
            self._seen = dict(ordered[len(ordered) // 2 :])
