import mimetypes
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

from detection.dedup import EventDeduplicator
from logs import get_logger

# Module configuration constants
MAX_ATTACHMENT_SIZE_BYTES = 15 * 1024 * 1024  # conservative 15 MB, pre-Base64

# Module-level logger dependency
logger = get_logger("alerts")

# Duplicate-alert throttle (opt-in). With ALERT_DEDUP_WINDOW_SECONDS > 0, an
# identical alert (level + module + message) inside the window is suppressed
# so a chatty detector cannot flood the mailbox or trip the SMTP rate limit.
# Disabled by default to preserve the historical alert-per-event behavior.
_alert_throttle = EventDeduplicator(window_seconds=0)


def _is_throttled(event_level: str, module_source: str, alert_message: str) -> bool:
    window = int(os.getenv("ALERT_DEDUP_WINDOW_SECONDS", "0"))
    if window <= 0:
        return False
    _alert_throttle.window_seconds = window
    fingerprint = EventDeduplicator.fingerprint(module_source, alert_message, event_level)
    return _alert_throttle.is_duplicate(fingerprint)


def send_security_alert(
    event_level: str,
    module_source: str,
    alert_message: str,
    subject: str = None,
    attachment_paths: list[str] = None,
) -> bool:
    """
    Sends a security alert e-mail over SMTP with STARTTLS.

    Args:
        event_level (str): Alert severity level (e.g. 'CRITICAL', 'WARNING').
        module_source (str): Module that raised the alert (e.g. 'auth', 'ids_core').
        alert_message (str): Message body with the event details.
        subject (str, optional): Custom subject. When None, a standard format is generated.
        attachment_paths (list[str], optional): Paths to forensic-evidence files to attach.

    Returns:
        bool: True if the message was handed to the SMTP server successfully. False on
              authentication, network, or protocol errors (failures land in the L0 logger).

    Raises:
        None: Every exception is caught and handled internally.
    """
    # Default subject when none is provided
    if not subject:
        subject = f"[{event_level.upper()}] IDS Alert - {module_source}"

    # Duplicate suppression (opt-in via ALERT_DEDUP_WINDOW_SECONDS)
    if _is_throttled(event_level, module_source, alert_message):
        logger.info(
            "Duplicate alert suppressed within dedup window: %s / %s",
            module_source,
            subject,
        )
        return False

    sender_email = os.getenv("EMAIL_SENDER")
    sender_password = os.getenv("EMAIL_PASSWORD")
    receiver_email = os.getenv("ALERT_RECEIVER")

    # Basic credential validation
    if not all([sender_email, sender_password, receiver_email]):
        logger.error("Missing SMTP credentials in environment. Alert aborted.")
        return False

    # Twelve-Factor App: externalized configuration with safe defaults
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))

    msg = EmailMessage()
    msg.set_content(alert_message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # --- Attachment processing ---
    for path_str in attachment_paths or []:
        path = Path(path_str)

        try:
            # Check existence before querying size
            if not path.exists():
                logger.warning("Attachment skipped: File not found at %s", path)
                continue

            # Enforce the size limit
            if path.stat().st_size > MAX_ATTACHMENT_SIZE_BYTES:
                logger.warning(
                    "Attachment skipped: Size exceeds limit (%s bytes) for %s",
                    MAX_ATTACHMENT_SIZE_BYTES,
                    path,
                )
                continue

            # MIME type detection
            ctype, encoding = mimetypes.guess_type(str(path))
            if ctype is None or encoding is not None:
                # Strict octet-stream fallback for unknown or compressed types
                ctype = "application/octet-stream"

            maintype, subtype = ctype.split("/", 1)

            # Read and attach safely
            with open(path, "rb") as f:
                file_data = f.read()

            msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=path.name)
        except PermissionError:
            logger.warning("Attachment skipped: Permission denied reading %s", path)
            continue
        except Exception:
            # Read catch-all: one corrupt file must not abort the loop
            logger.exception("Attachment skipped: Unexpected error reading %s", path)
            continue
    # ---------------------------------------------

    try:
        # SMTP client with STARTTLS and a defensive timeout
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        logger.info("SMTP security alert '%s' sent successfully to %s", subject, receiver_email)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.critical(
            "SMTP Authentication failed. Check EMAIL_SENDER and App Passwords. Alert not sent!"
        )
        return False
    except (smtplib.SMTPConnectError, TimeoutError, smtplib.SMTPServerDisconnected) as e:
        logger.error("SMTP connection failed or timed out: %s. Alert degraded.", e)
        return False
    except smtplib.SMTPException as e:
        logger.error("SMTP protocol error: %s", e)
        return False
    except Exception:
        # Safety net: logs unexpected exceptions with full traceback to forensic DB.
        logger.exception("Unexpected exception during SMTP transmission. Alert failed.")
        return False
