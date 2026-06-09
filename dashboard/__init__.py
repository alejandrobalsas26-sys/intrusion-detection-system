import os
from datetime import timedelta

from flask import Flask
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

# Content Security Policy. Hosts are explicitly allow-listed so that only the
# Tailwind and Chart.js CDNs used by the templates can execute.
CSP = {
    "default-src": "'self'",
    "script-src": [
        "'self'",
        "https://cdn.tailwindcss.com",
        "https://cdn.jsdelivr.net",
    ],
    "style-src": [
        "'self'",
        "https://cdn.tailwindcss.com",
        "'unsafe-inline'",
    ],
    "img-src": ["'self'", "data:"],
    "font-src": ["'self'", "data:"],
    "connect-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'self'",
    "frame-ancestors": "'none'",
}

# Extensions instantiated at import time
csrf = CSRFProtect()


def create_app():
    """App Factory: Initializes and configures the Flask application."""
    app = Flask(__name__)

    app.secret_key = os.getenv("FLASK_SECRET_KEY")
    if not app.secret_key:
        raise RuntimeError(
            "FLASK_SECRET_KEY is required. Generate via: "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )

    is_production = os.getenv("FLASK_ENV") == "production"

    # Session security
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=is_production,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    )

    # --- Security Extensions ---
    csrf.init_app(app)

    # Security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer Policy.
    Talisman(
        app,
        content_security_policy=CSP,
        force_https=is_production,
        strict_transport_security=is_production,
        session_cookie_secure=is_production,
        frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
    )

    # --- Blueprint Registration ---
    from dashboard.routes import bp

    app.register_blueprint(bp)

    return app
