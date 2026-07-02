import hmac
import json
import os
import re
import time

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth.core import get_user_role, list_users, verify_token
from dashboard.queries import (
    database_is_readable,
    get_active_users_count,
    get_audit_events_since,
    get_database_size_bytes,
    get_event_counts_by_level,
    get_fim_events_count,
    get_incidents,
    get_latest_event_timestamp,
    get_network_events,
    get_network_events_count,
    get_open_incidents_count,
    get_recent_audit_events,
)
from dashboard.security import get_limiter, login_required, require_role
from detection.playbook import enrich_incident

bp = Blueprint("main", __name__)

# Input contracts for the untrusted login boundary. Enrollment only ever
# creates usernames from this character set (see auth.cli), and the dashboard
# login path verifies TOTP codes, which pyotp emits as fixed-length digits.
# Rejecting anything else here stops oversized payloads and CRLF/control
# characters from ever reaching the auth core or the audit log (log forging).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TOTP_RE = re.compile(r"^[0-9]{6,8}$")


@bp.route("/", methods=["GET"])
@login_required
def home() -> str:
    """Dashboard home: shows summary and recent audit events."""
    return render_template(
        "index.html",
        audit_events=get_recent_audit_events(50),
        fim_events_count=get_fim_events_count(),
        active_users_count=get_active_users_count(),
        network_events=get_network_events(20),
        network_events_count=get_network_events_count(),
    )


@bp.route("/login", methods=["GET"])
def login_form() -> str:
    """Render login form."""
    return render_template("login.html")


@bp.route("/login", methods=["POST"])
def login_submit() -> Response:
    """Handle login submission with TOTP verification.

    Rate limited per client IP at the HTTP layer (fixed window) so a single
    source can neither brute-force TOTP codes nor tie up worker threads in
    the auth module's backoff path.
    """
    client_ip = request.remote_addr or "unknown"
    allowed, retry_after = get_limiter().check(client_ip)
    if not allowed:
        response = current_app.response_class(
            "Too many login attempts. Please retry later.\n",
            status=429,
            mimetype="text/plain",
        )
        response.headers["Retry-After"] = str(retry_after)
        return response

    username = request.form.get("username", "").strip()
    token = request.form.get("totp_code", "").strip()

    if not username or not token:
        flash("Username and TOTP code are required.", "error")
        return redirect(url_for("main.login_form"))

    # Reject malformed credentials before they reach the auth core. Using the
    # same generic message as a failed verification preserves anti-enumeration
    # (an attacker cannot distinguish "bad format" from "wrong code").
    if not _USERNAME_RE.match(username) or not _TOTP_RE.match(token):
        flash("Authentication failed. Please verify your credentials.", "error")
        return redirect(url_for("main.login_form"))

    event = verify_token(username, token)

    if event.event_name == "AUTH_SUCCESS":
        # Session fixation mitigation: clear + new keys
        session.clear()
        session.permanent = True
        session["user_id"] = username
        session["authenticated_at"] = time.time()
        # RBAC: bind the role at login time (users.role column).
        session["role"] = get_user_role(username) or "analyst"

        return redirect(url_for("main.home"))
    else:
        # Anti-enumeration: same message regardless of failure reason
        flash("Authentication failed. Please verify your credentials.", "error")
        return redirect(url_for("main.login_form"))


@bp.route("/logout", methods=["POST"])
def logout() -> Response:
    """Invalidate session and redirect to login."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("main.login_form"))


@bp.route("/events/stream")
@login_required
def event_stream() -> Response:
    """SSE endpoint: streams new audit events to authenticated clients.

    The stream is bounded (SSE_MAX_LIFETIME_SECONDS, default 15 min — the
    session lifetime) so a single client cannot hold a worker forever; EventSource
    reconnects automatically, which re-runs the authentication check above.
    Heartbeat comments keep intermediaries from buffering or killing the socket.
    """
    max_lifetime = int(os.getenv("SSE_MAX_LIFETIME_SECONDS", "900"))
    poll_interval = int(os.getenv("SSE_POLL_INTERVAL_SECONDS", "5"))

    def generate():
        last_id = 0
        started = time.monotonic()
        while time.monotonic() - started < max_lifetime:
            rows = get_audit_events_since(last_id)
            for row in rows:
                last_id = max(last_id, row.get("id", 0))
                yield f"data: {json.dumps(row)}\n\n"
            if not rows:
                yield ": heartbeat\n\n"
            time.sleep(poll_interval)

    # NOTE: spec used `bp.current_app` which does not exist on a Blueprint;
    # using Flask's `current_app` proxy to access the app's response_class.
    return current_app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@bp.route("/api/incidents", methods=["GET"])
@login_required
def api_incidents() -> Response:
    """Correlated incidents (newest first). Filter: ?status=open|acknowledged|closed."""
    status = request.args.get("status") or None
    if status and status not in ("open", "acknowledged", "closed"):
        return jsonify({"error": "invalid status filter"}), 400
    limit = min(request.args.get("limit", 50, type=int) or 50, 200)
    incidents = get_incidents(limit=limit, status=status)
    # mitre_techniques / entities are stored as JSON strings; decode for clients.
    for incident in incidents:
        for key in ("mitre_techniques", "entities"):
            try:
                incident[key] = json.loads(incident.get(key) or "[]")
            except (json.JSONDecodeError, TypeError):
                incident[key] = []
        # Read-time analyst enrichment: tactic, confidence, remediation hints.
        enrich_incident(incident)
    return jsonify({"incidents": incidents, "count": len(incidents)})


@bp.route("/api/users", methods=["GET"])
@require_role("admin")
def api_users() -> Response:
    """Enrolled-user roster for administrators (RBAC-gated).

    Read-only and free of secrets: only username, creation time, role, and
    active flag are exposed (never the encrypted TOTP secret or recovery
    codes). Non-admin sessions receive 403; unauthenticated requests 401.
    """
    return jsonify({"users": list_users()})


# --- Operational endpoints (no session: probes and scrapers can't do TOTP) ---


@bp.route("/healthz", methods=["GET"])
def healthz() -> Response:
    """Liveness probe: the process is serving requests."""
    return jsonify({"status": "ok"})


@bp.route("/readyz", methods=["GET"])
def readyz() -> Response:
    """Readiness probe: the audit database is reachable and readable."""
    if database_is_readable():
        return jsonify({"status": "ready"})
    return jsonify({"status": "unavailable", "reason": "audit database unreadable"}), 503


@bp.route("/metrics", methods=["GET"])
def metrics() -> Response:
    """Prometheus text exposition of aggregate counters.

    Only aggregate counts are exposed (no event payloads, usernames, or IPs).
    Even so, those counts reveal IDS operational state (e.g. whether an attack
    produced incidents), so an operator can set METRICS_TOKEN to require a
    bearer token. When unset, the endpoint stays public for probe/scraper
    compatibility — restrict it at the reverse proxy if your threat model needs.
    """
    expected_token = os.getenv("METRICS_TOKEN")
    if expected_token:
        auth_header = request.headers.get("Authorization", "")
        provided = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        # Constant-time comparison avoids leaking the token via timing.
        if not provided or not hmac.compare_digest(provided, expected_token):
            response = current_app.response_class(
                "Unauthorized\n", status=401, mimetype="text/plain"
            )
            response.headers["WWW-Authenticate"] = "Bearer"
            return response

    lines = [
        "# HELP ids_up Whether the dashboard process is up.",
        "# TYPE ids_up gauge",
        "ids_up 1",
        "# HELP ids_ready Whether the audit database is readable.",
        "# TYPE ids_ready gauge",
        f"ids_ready {1 if database_is_readable() else 0}",
        "# HELP ids_audit_events_total Audit events by level.",
        "# TYPE ids_audit_events_total counter",
    ]
    for level, count in sorted(get_event_counts_by_level().items()):
        lines.append(f'ids_audit_events_total{{level="{level}"}} {count}')
    lines += [
        "# HELP ids_fim_events_total File integrity events recorded.",
        "# TYPE ids_fim_events_total counter",
        f"ids_fim_events_total {get_fim_events_count()}",
        "# HELP ids_network_events_total Network detection events recorded.",
        "# TYPE ids_network_events_total counter",
        f"ids_network_events_total {get_network_events_count()}",
        "# HELP ids_active_users Active enrolled users.",
        "# TYPE ids_active_users gauge",
        f"ids_active_users {get_active_users_count()}",
        "# HELP ids_open_incidents Correlated incidents in open status.",
        "# TYPE ids_open_incidents gauge",
        f"ids_open_incidents {get_open_incidents_count()}",
        "# HELP ids_database_size_bytes On-disk size of the audit database (incl. WAL).",
        "# TYPE ids_database_size_bytes gauge",
        f"ids_database_size_bytes {get_database_size_bytes()}",
        "# HELP ids_last_event_timestamp_seconds Epoch time of the most recent audit event.",
        "# TYPE ids_last_event_timestamp_seconds gauge",
        f"ids_last_event_timestamp_seconds {get_latest_event_timestamp()}",
    ]
    return current_app.response_class(
        "\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4"
    )
