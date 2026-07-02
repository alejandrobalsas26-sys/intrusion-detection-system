"""Local validation pipeline for the IDS repository.

    python scripts/validate.py

Runs, in order: compileall over first-party code, the full pytest suite, and
then ruff / pip-audit only when those tools are installed — a missing optional
tool is reported and skipped, never treated as a failure. Exit code is 0 only
when every executed step passed.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# First-party code only: the virtualenv and generated scratch dirs are not
# ours to fix and would bury real findings in third-party noise.
COMPILE_TARGETS = (
    "ai",
    "alerts",
    "auth",
    "dashboard",
    "demo",
    "detection",
    "fim",
    "ids",
    "logs",
    "network",
    "samples",
    "scripts",
    "tests",
    "vision",
)


def _run(name: str, args: list[str]) -> bool:
    print(f"\n=== {name}: {sys.executable} {' '.join(args)}", flush=True)
    result = subprocess.run([sys.executable, *args], cwd=REPO_ROOT)  # noqa: S603
    print(f"=== {name}: {'OK' if result.returncode == 0 else f'FAILED (exit {result.returncode})'}")
    return result.returncode == 0


def _installed(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def main() -> int:
    failures: list[str] = []

    targets = [d for d in COMPILE_TARGETS if (REPO_ROOT / d).is_dir()]
    if not _run("compileall", ["-m", "compileall", "-q", *targets]):
        failures.append("compileall")

    if not _run("pytest", ["-m", "pytest", "-q"]):
        failures.append("pytest")

    if _installed("ruff"):
        if not _run("ruff", ["-m", "ruff", "check", "."]):
            failures.append("ruff")
    else:
        print("\n=== ruff: not installed, skipped (pip install ruff)")

    if _installed("pip_audit"):
        if not _run("pip-audit", ["-m", "pip_audit", "-r", "requirements.txt"]):
            failures.append("pip-audit")
    else:
        print("\n=== pip-audit: not installed, skipped (pip install pip-audit)")

    if failures:
        print(f"\n[x] Validation failed: {', '.join(failures)}")
        return 1
    print("\n[+] All validations passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
