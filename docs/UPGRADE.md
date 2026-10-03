# Upgrade notes

Stop the IDS processes before replacing source files or upgrading dependencies.
Make a SQLite backup and retain your existing `.env`, `MFA_ENCRYPTION_KEY`,
`FLASK_SECRET_KEY`, FIM configuration and enrolled users.

Install `requirements.txt` in your existing virtual environment, then run
`python -m pytest -q` and `python -m ids check`.

Schema changes are automatic and preserve existing users, encrypted secrets,
recovery codes, baselines, audit events and incidents:

* Auth adds nullable `auth_attempts.totp_step` and `totp_consumptions`.
  The old permanent unique numeric-token index becomes a searchable index.
  Recent successful legacy attempts retain their 90-second replay check.
* Audit adds `audit_retention_hashes`. Future production purges preserve sealed
  row fingerprints atomically, allowing full and partial segments to verify.
  Rows purged by older versions have no recorded proof: verification now fails
  closed for those missing rows. Restore their historical backup if available;
  do not erase checkpoints to hide a failure.

Existing dashboard cookies missing a valid authentication timestamp must log
in again. Sessions expire 15 minutes after authentication even during active
use. Role changes and user revocation apply on the next protected request;
an open SSE stream rechecks active status and expiry each poll.

Network events persist detector context, including domains and IPv6. Chain
rules require a shared `host_id`; recon/auth also requires matching source IPs.
Legacy events missing those fields no longer produce speculative cross-module
chains. The demo and supplied JSONL sample include the required metadata.

SMTP now verifies certificate and hostname with the operating system trust
store. For a private SMTP CA, install its root certificate in the trust store.

Regular wheels include nested network detectors, SQL schemas, HTML templates,
static assets and demo resources. Runtime dependencies require
`cryptography>=50.0.2`; `requirements.txt` pins the tested version.
