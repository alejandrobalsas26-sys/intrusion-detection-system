"""Generates a realistic multi-stage attack chain into the real event store.

Everything is local and unprivileged: auth/network events are inserted as
audit rows in the exact format the live modules emit, and the FIM stage is
*genuinely* end-to-end — it copies the demo files into a scratch directory,
baselines them with ``fim.initialize_baselines``, tampers with them on disk,
and lets ``fim.check_integrity`` discover the damage itself.

Timeline (relative seconds, latest event anchored at ``base_time``/now):

    0     syn_scan       recon from the attacker IP (203.0.113.66, TEST-NET-3)
    60..  AUTH_FAILURE   burst of 5 failures against 'admin'
    210.. AUTH_FAILURE   one failure each against 5 more accounts (spray)
    360   AUTH_SUCCESS   'admin' login lands after the burst
    now   FIM            real MODIFIED + CREATED from the tampered scratch dir

Expected incidents after a sweep: brute_force_burst, password_spray,
auth_success_after_failures, recon_then_auth, network_then_fim, and ioc_match
(the attacker IP is written to a local watchlist).
"""

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from detection.replay import insert_audit_records

ATTACKER_IP = "203.0.113.66"  # RFC 5737 documentation space — never routable
TARGET_USER = "admin"
SPRAY_USERS = ("alice", "bob", "carol", "dave", "svc_backup")

DEMO_DIR = Path(__file__).parent
PROTECTED_SOURCE = DEMO_DIR / "protected"
PROTECTED_LIVE = DEMO_DIR / "protected_live"  # scratch copy; gitignored
FIM_DEMO_CONFIG = DEMO_DIR / "_fim_demo_config.json"  # generated; gitignored
IOC_LIST = DEMO_DIR / "_demo_ioc_ips.txt"  # generated; gitignored


@dataclass
class DemoSummary:
    db_path: str
    events_created: int
    fim_events_created: int
    incidents_created: int | None  # None when the sweep was skipped
    incident_rules: list[str] = field(default_factory=list)
    protected_dir: str = ""
    ioc_list_path: str = ""


def build_records() -> list[dict]:
    """The synthetic (non-FIM) portion of the attack chain, as audit rows."""
    records: list[dict] = [
        {
            "offset_seconds": 0,
            "level": "CRITICAL",
            "module_source": "network_sensor",
            "message": (
                f"DetectionEvent: CRITICAL from syn_scan - SYN scan detected from "
                f"{ATTACKER_IP}: 35 unique ports in 10s window."
            ),
            "context": {"source_ip": ATTACKER_IP, "port_count": 35},
        }
    ]
    for i in range(5):
        records.append(
            {
                "offset_seconds": 60 + i * 30,
                "level": "WARNING",
                "module_source": "auth_core",
                "message": f"Authentication failed for user '{TARGET_USER}'.",
                "context": {"reason_code": "INVALID_TOTP", "source_ip": ATTACKER_IP},
            }
        )
    for i, user in enumerate(SPRAY_USERS):
        records.append(
            {
                "offset_seconds": 210 + i * 30,
                "level": "WARNING",
                "module_source": "auth_core",
                "message": f"Authentication failed for user '{user}'.",
                "context": {"reason_code": "INVALID_TOTP", "source_ip": ATTACKER_IP},
            }
        )
    records.append(
        {
            "offset_seconds": 360,
            "level": "INFO",
            "module_source": "auth_core",
            "message": f"User '{TARGET_USER}' authenticated successfully.",
            "context": {"source_ip": ATTACKER_IP},
        }
    )
    return records


def _retry_fs(op, path: Path, attempts: int = 6, delay: float = 0.35):
    """Retries a filesystem operation that can hit transient Windows locks."""
    for attempt in range(attempts):
        try:
            return op(path)
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)


def _reset_scratch_dir(source: Path, dest: Path) -> None:
    """(Re)creates the scratch copy without ever deleting ``dest`` itself.

    Windows AV/indexer scans hold a handle on recently-touched directories long
    enough that removing the directory fails with WinError 5, while the files
    inside stay deletable — so stale contents are cleared in place and the
    directory is reused across runs.
    """
    dest.mkdir(parents=True, exist_ok=True)
    for child in dest.iterdir():
        _retry_fs(shutil.rmtree if child.is_dir() else os.unlink, child)
    shutil.copytree(source, dest, dirs_exist_ok=True)


def _run_fim_stage(db_path: str) -> int:
    """Copies the demo files, baselines them, tampers, and runs a real check.

    Returns the number of FIM events dispatched (as counted in fim_events).
    """
    import contextlib
    import sqlite3

    import fim.monitor as fim_monitor

    # fim.monitor binds DB_PATH at import time; align it with the demo target.
    fim_monitor.DB_PATH = db_path

    _reset_scratch_dir(PROTECTED_SOURCE, PROTECTED_LIVE)

    config = {"critical_dirs": [{"path": str(PROTECTED_LIVE), "recursive": True}]}
    FIM_DEMO_CONFIG.write_text(json.dumps(config, indent=2), encoding="utf-8")

    # Reset baselines that previous demo runs left behind for the scratch dir
    # (a re-run would otherwise find the planted file already baselined and
    # raise no CREATED event). Scoped strictly to the demo-owned path.
    fim_monitor._bootstrap_fim_db()
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "DELETE FROM file_baselines WHERE filepath LIKE ?", (f"{PROTECTED_LIVE}%",)
        )
        conn.commit()

    # Baselining bootstraps the FIM schema and never writes fim_events, so the
    # "before" count taken right after it still precedes the tampering below.
    fim_monitor.initialize_baselines(str(FIM_DEMO_CONFIG))

    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        before = conn.execute("SELECT COUNT(*) FROM fim_events").fetchone()[0]

    credentials = PROTECTED_LIVE / "credentials.txt"
    with open(credentials, "a", encoding="utf-8") as handle:
        handle.write("\n# tampered: exfil marker added by demo attacker\n")
    (PROTECTED_LIVE / "implant.bat").write_text(
        "@echo off\r\nrem planted by demo attacker\r\n", encoding="utf-8"
    )

    fim_monitor.check_integrity()

    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        after = conn.execute("SELECT COUNT(*) FROM fim_events").fetchone()[0]
    return after - before


def run_demo(
    db_path: str | None = None,
    base_time: float | None = None,
    sweep: bool = True,
    suppress_email: bool = True,
) -> DemoSummary:
    """Generates the full attack chain and (optionally) correlates it."""
    resolved_db = db_path or os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
    if db_path:
        os.environ["DB_PATH"] = db_path

    if suppress_email:
        # A demo must never page a real inbox: with the sender cleared the
        # alert layer aborts fast (and logs that it did). Opt back in via
        # run_demo(suppress_email=False) / --live-email.
        os.environ["EMAIL_SENDER"] = ""

    result = insert_audit_records(build_records(), db_path=resolved_db, base_time=base_time)

    fim_count = _run_fim_stage(resolved_db)

    IOC_LIST.write_text(
        "# Local demo watchlist - the synthetic attacker\n" f"{ATTACKER_IP}\n",
        encoding="utf-8",
    )
    os.environ.setdefault("IOC_IP_LIST_PATH", str(IOC_LIST))

    incidents_created: int | None = None
    incident_rules: list[str] = []
    if sweep:
        import contextlib
        import sqlite3

        from detection.correlation import CorrelationEngine

        engine = CorrelationEngine(db_path=resolved_db)
        horizon = (base_time or time.time()) - 3600
        incidents_created = engine.sweep(since_ts=horizon)
        with contextlib.closing(sqlite3.connect(resolved_db)) as conn:
            incident_rules = sorted(
                row[0]
                for row in conn.execute(
                    "SELECT DISTINCT rule_name FROM incidents WHERE created_at >= ?",
                    (time.time() - 300,),
                ).fetchall()
            )

    return DemoSummary(
        db_path=resolved_db,
        events_created=result.inserted,
        fim_events_created=fim_count,
        incidents_created=incidents_created,
        incident_rules=incident_rules,
        protected_dir=str(PROTECTED_LIVE),
        ioc_list_path=str(IOC_LIST),
    )


def print_summary(summary: DemoSummary) -> None:
    """Operator-facing recap. ASCII only: Windows consoles default to cp1252."""
    print()
    print("=" * 62)
    print(" Antigravity-IDS demo attack chain generated")
    print("=" * 62)
    print(f"  Database:          {summary.db_path}")
    print(f"  Audit events:      {summary.events_created} synthetic rows inserted")
    print(f"  FIM events:        {summary.fim_events_created} raised by a real integrity check")
    print(f"  Tampered dir:      {summary.protected_dir}")
    print(f"  IOC watchlist:     {summary.ioc_list_path}")
    if summary.incidents_created is None:
        print("  Incidents:         sweep skipped - run: python -m detection")
    else:
        print(f"  Incidents:         {summary.incidents_created} new")
        for rule in summary.incident_rules:
            print(f"      - {rule}")
    print()
    print("  Next steps:")
    print("    1. python -m detection            (re-sweep; idempotent)")
    print("    2. python -m dashboard            (login UI on http://127.0.0.1:5000)")
    print("       No user yet? python -m auth.cli enroll <name>")
    print("    3. GET /api/incidents             (JSON incident feed, needs login)")
    print("       or: sqlite3 <db> \"SELECT rule_name, title, risk_score FROM incidents;\"")
    print()
