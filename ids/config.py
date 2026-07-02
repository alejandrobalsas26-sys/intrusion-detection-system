"""Shared CLI configuration helpers."""


def load_env() -> bool:
    """Loads .env into the process (no overrides) when python-dotenv exists.

    Mirrors the per-module entry points, which all call load_dotenv() before
    binding configuration; returns False when the dependency is unavailable
    instead of failing, so the CLI still works in a minimal install.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return False
    load_dotenv()
    return True
