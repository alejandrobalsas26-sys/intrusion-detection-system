"""Dashboard security primitives: login rate limiting and access decorators.

Rate limiting lives at the HTTP layer (fixed window per client IP, in-process)
so that an attacker can neither exhaust worker threads via the auth module's
sleep-based backoff nor brute-force TOTP codes from a single source. State is
per-app (created in the app factory), which keeps tests isolated and avoids
cross-instance surprises. For multi-process deployments put a shared limiter
(reverse proxy or Redis) in front — documented in docs/DEPLOYMENT.md.
"""

import os
import threading
import time
from functools import wraps

from flask import current_app, jsonify, redirect, request, session, url_for


class LoginRateLimiter:
    """Thread-safe fixed-window counter keyed by client IP."""

    def __init__(self, max_attempts: int | None = None, window_seconds: int | None = None):
        self.max_attempts = max_attempts or int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
        self.window_seconds = window_seconds or int(
            os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "60")
        )
        self._windows: dict[str, tuple[float, int]] = {}  # ip -> (window_start, count)
        self._lock = threading.Lock()

    def check(self, client_ip: str, now: float | None = None) -> tuple[bool, int]:
        """Registers an attempt. Returns (allowed, retry_after_seconds)."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            window_start, count = self._windows.get(client_ip, (ts, 0))
            if ts - window_start >= self.window_seconds:
                window_start, count = ts, 0
            count += 1
            self._windows[client_ip] = (window_start, count)
            # Opportunistic cleanup keeps memory bounded under IP churn.
            if len(self._windows) > 10_000:
                cutoff = ts - self.window_seconds
                self._windows = {
                    ip: wc for ip, wc in self._windows.items() if wc[0] >= cutoff
                }
            if count > self.max_attempts:
                retry_after = int(self.window_seconds - (ts - window_start)) + 1
                return False, retry_after
            return True, 0


def get_limiter() -> LoginRateLimiter:
    """Fetches the per-app limiter installed by the app factory."""
    return current_app.config["LOGIN_RATE_LIMITER"]


def login_required(view):
    """Redirects unauthenticated browsers to the login form; 401 for APIs."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/") or request.path.startswith("/events/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("main.login_form"))
        return view(*args, **kwargs)

    return wrapped


def require_role(*roles: str):
    """RBAC gate over the session role established at login.

    Usage: @require_role("admin") or @require_role("admin", "analyst").
    Unauthenticated -> login flow; authenticated without the role -> 403.
    """

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                return jsonify({"error": "insufficient privileges"}), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator
