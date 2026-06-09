import json
import time

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth.core import verify_token
from dashboard.queries import (
    get_active_users_count,
    get_fim_events_count,
    get_network_events,
    get_network_events_count,
    get_recent_audit_events,
)

bp = Blueprint("main", __name__)


@bp.route("/", methods=["GET"])
def home() -> str:
    """Dashboard home: shows summary and recent audit events."""
    if "user_id" not in session:
        return redirect(url_for("main.login_form"))

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
    """Handle login submission with TOTP verification."""
    username = request.form.get("username", "").strip()
    token = request.form.get("totp_code", "").strip()

    if not username or not token:
        flash("Username and TOTP code are required.", "error")
        return redirect(url_for("main.login_form"))

    event = verify_token(username, token)

    if event.event_name == "AUTH_SUCCESS":
        # Session fixation mitigation: clear + new keys
        session.clear()
        session.permanent = True
        session["user_id"] = username
        session["authenticated_at"] = time.time()

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
def event_stream() -> Response:
    """SSE endpoint: streams new audit events to authenticated clients."""
    if "user_id" not in session:
        return "", 401

    import time as _time

    def generate():
        last_id = 0
        while True:
            from dashboard.queries import get_audit_events_since

            rows = get_audit_events_since(last_id)
            for row in rows:
                last_id = max(last_id, row.get("id", 0))
                yield f"data: {json.dumps(row)}\n\n"
            _time.sleep(5)

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
