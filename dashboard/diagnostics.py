"""Startup configuration validation and operational diagnostics.

Validates the environment the dashboard (and the wider IDS) depends on *before*
it starts serving, and powers a `python -m dashboard --check` self-test so an
operator can confirm a deployment is wired correctly instead of discovering a
misconfiguration from a stack trace under load.

Every check here is read-only and side-effect free: nothing writes to the
database, mutates configuration, or imports a module whose import has side
effects (notably `auth.crypto`, which instantiates a Fernet cipher at import
time and would raise before this validator could report a friendly message).
Secrets are validated for *shape*, never logged.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

# Severity ordering for the worst-status rollup.
OK = "OK"
WARN = "WARN"
FAIL = "FAIL"

_PLACEHOLDERS = {
    "your_64_character_hex_secret_here",
    "your_fernet_key_here",
    "changeme",
    "",
}


@dataclass
class Check:
    """One diagnostic result line."""

    name: str
    status: str  # OK / WARN / FAIL
    detail: str


@dataclass
class Diagnostics:
    """Aggregate diagnostic report."""

    checks: list[Check] = field(default_factory=list)
    production: bool = False

    def add(self, name: str, status: str, detail: str) -> None:
        self.checks.append(Check(name, status, detail))

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == WARN]

    @property
    def ok(self) -> bool:
        """True when nothing fatal blocks startup."""
        return not self.failures


def _is_production(explicit: bool | None) -> bool:
    if explicit is not None:
        return explicit
    return os.getenv("FLASK_ENV", "").strip().lower() == "production"


def _check_flask_secret(report: Diagnostics) -> None:
    secret = os.getenv("FLASK_SECRET_KEY", "")
    if not secret or secret in _PLACEHOLDERS:
        report.add(
            "FLASK_SECRET_KEY",
            FAIL,
            "Missing or placeholder. Generate: "
            'python -c "import secrets; print(secrets.token_hex(32))"',
        )
        return
    if len(secret) < 32:
        report.add(
            "FLASK_SECRET_KEY",
            WARN,
            f"Set but short ({len(secret)} chars); use >= 64 hex chars for full entropy.",
        )
        return
    report.add("FLASK_SECRET_KEY", OK, "Present.")


def _check_mfa_key(report: Diagnostics) -> None:
    key = os.getenv("MFA_ENCRYPTION_KEY", "")
    if not key or key in _PLACEHOLDERS:
        report.add(
            "MFA_ENCRYPTION_KEY",
            FAIL,
            "Missing or placeholder. Generate: "
            "python -c \"from cryptography.fernet import Fernet; "
            'print(Fernet.generate_key().decode())"',
        )
        return
    try:
        from cryptography.fernet import Fernet

        Fernet(key.encode())
    except Exception as exc:  # noqa: BLE001 - report the shape error, never the key
        report.add("MFA_ENCRYPTION_KEY", FAIL, f"Invalid Fernet key ({type(exc).__name__}).")
        return
    report.add("MFA_ENCRYPTION_KEY", OK, "Valid Fernet key.")


def _check_db_path(report: Diagnostics) -> None:
    db_path = os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
    parent = Path(db_path).resolve().parent
    if parent.exists():
        if os.access(parent, os.W_OK):
            exists = Path(db_path).exists()
            report.add(
                "DB_PATH",
                OK,
                f"{db_path} ({'exists' if exists else 'will be created'}; dir writable).",
            )
        else:
            report.add("DB_PATH", FAIL, f"Directory not writable: {parent}")
    else:
        # Parent missing is recoverable (bootstrap mkdirs), but flag it so the
        # operator knows a fresh path is about to be created.
        report.add("DB_PATH", WARN, f"Parent directory does not exist yet: {parent}")


def _check_flask_env(report: Diagnostics) -> None:
    env = os.getenv("FLASK_ENV", "development").strip().lower()
    if env not in ("development", "production"):
        report.add(
            "FLASK_ENV",
            WARN,
            f"Unrecognized value '{env}'; expected 'development' or 'production'.",
        )
        return
    if env == "development" and report.production:
        report.add(
            "FLASK_ENV",
            WARN,
            "Serving in production mode but FLASK_ENV != production "
            "(secure cookies, HSTS, and HTTPS redirect stay OFF).",
        )
        return
    report.add("FLASK_ENV", OK, env)


def _check_production_server(report: Diagnostics) -> None:
    if not report.production:
        return
    try:
        import waitress  # noqa: F401

        report.add("Production server", OK, "Waitress available.")
    except ImportError:
        report.add(
            "Production server",
            FAIL,
            "Waitress not installed. Install: pip install waitress",
        )


def _check_backoff_mode(report: Diagnostics) -> None:
    # The dashboard factory defaults this to 'reject'; a sleep mode in a web
    # worker is a thread-exhaustion vector. Flag an explicit sleep override.
    mode = os.getenv("MFA_BACKOFF_MODE", "").strip().lower()
    if mode == "sleep":
        report.add(
            "MFA_BACKOFF_MODE",
            WARN,
            "Set to 'sleep' for the web tier — a blocking backoff is a DoS vector; "
            "prefer 'reject'.",
        )


def _check_optional_features(report: Diagnostics) -> None:
    # AI endpoint scheme sanity (only when a backend is enabled).
    backend = os.getenv("AI_BACKEND", "none").strip().lower()
    if backend not in ("none", ""):
        from urllib.parse import urlparse

        endpoint = os.getenv("AI_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
        scheme = urlparse(endpoint).scheme
        if scheme not in ("http", "https"):
            report.add("AI_ENDPOINT", WARN, f"Unsupported scheme '{scheme}'.")
        else:
            report.add("AI assist", OK, f"backend={backend}, endpoint scheme {scheme}.")

    # IOC list paths, if configured, should exist.
    for var in ("IOC_IP_LIST_PATH", "IOC_DOMAIN_LIST_PATH"):
        path = os.getenv(var, "").strip()
        if path and not Path(path).exists():
            report.add(var, WARN, f"Configured but file not found: {path}")
        elif path:
            report.add(var, OK, path)

    if report.production and not os.getenv("METRICS_TOKEN"):
        report.add(
            "METRICS_TOKEN",
            WARN,
            "Unset in production: /metrics is public. Set a token or restrict at the proxy.",
        )


def run_diagnostics(production: bool | None = None) -> Diagnostics:
    """Runs every startup check and returns a structured report.

    `production` forces the production rule set (stricter); when None it is
    inferred from FLASK_ENV.
    """
    report = Diagnostics(production=_is_production(production))
    _check_flask_secret(report)
    _check_mfa_key(report)
    _check_db_path(report)
    _check_flask_env(report)
    _check_production_server(report)
    _check_backoff_mode(report)
    _check_optional_features(report)
    return report


def format_report(report: Diagnostics) -> str:
    """Renders the report as aligned, human-readable lines for the CLI."""
    symbols = {OK: "[+]", WARN: "[!]", FAIL: "[x]"}
    width = max((len(c.name) for c in report.checks), default=0)
    lines = ["IDS configuration diagnostics", "=" * 30]
    for c in report.checks:
        lines.append(f" {symbols.get(c.status, '[?]')} {c.name.ljust(width)}  {c.detail}")
    lines.append("-" * 30)
    if report.ok:
        suffix = " with warnings" if report.warnings else ""
        lines.append(f"Result: READY{suffix} "
                     f"({len(report.warnings)} warning(s)).")
    else:
        lines.append(
            f"Result: NOT READY — {len(report.failures)} blocking issue(s), "
            f"{len(report.warnings)} warning(s)."
        )
    return "\n".join(lines)
