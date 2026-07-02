# Module L1: Email Alerts (SMTP)

Asynchronous e-mail notification of IDS security events. Designed for
network-fault tolerance, forensic granularity, and safe MIME attachment
handling (defense against *zip bombs* and *OOM kills*).

## Prerequisites (App Passwords)

Google has blocked basic SMTP authentication with regular passwords since
2022. An **App Password** is required for the sending account:
1. Enable 2FA (two-step verification) on your Google account.
2. Generate an application password at: [App Passwords](https://myaccount.google.com/apppasswords)
3. **WARNING:** NEVER commit the App Password. Define this credential only in
   the local environment (reference: `.env.example`).

## Environment Variables (12-Factor contract)

The module requires the following variables in the environment:

*   `EMAIL_SENDER`: Authorized sending address (e.g. ids.service.account@gmail.com).
*   `EMAIL_PASSWORD`: Generated 16-character App Password (no spaces).
*   `ALERT_RECEIVER`: Administrator or SOC address that receives the alerts.
*   `SMTP_HOST`: (Optional) SMTP server to use. Default: `smtp.gmail.com`.
*   `SMTP_PORT`: (Optional) Port for the STARTTLS connection. Default: `587`.
*   `ALERT_DEDUP_WINDOW_SECONDS`: (Optional) Suppress an identical alert
    (level + module + message) repeated within this window. Default: `0` (off).

## External Dependencies
*   `python-dotenv`: Loads `.env` variables in local development environments.
    The full dependency manifest lives in [`requirements.txt`](../requirements.txt).

## Usage Example
```python
from alerts import send_security_alert

# Logger (L0) injection and SMTP exception handling are transparent to callers.
success = send_security_alert(
    event_level="CRITICAL",
    module_source="ids_core",
    alert_message="Unauthorized access detected on port 22.",
    attachment_paths=["/var/log/auth.log"]  # safely skipped if missing or over 15 MB
)
```
