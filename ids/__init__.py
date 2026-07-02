"""One-command local orchestrator for the IDS platform.

    python -m ids check    import + configuration self-test
    python -m ids demo     reproducible offline attack-chain demo
    python -m ids run ...  start dashboard / correlator / sensor together

The per-module entry points (python -m dashboard, -m detection, -m network)
remain the primary interfaces; this package only sequences them.
"""
