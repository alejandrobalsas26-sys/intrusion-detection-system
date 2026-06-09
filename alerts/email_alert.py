import mimetypes
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

from logs import get_logger

# Constantes de configuración del módulo
MAX_ATTACHMENT_SIZE_BYTES = 15 * 1024 * 1024  # 15 MB conservador para pre-Base64

# Inyectar dependencia del logger a nivel de módulo (Lectura A)
logger = get_logger("alerts")


def send_security_alert(
    event_level: str,
    module_source: str,
    alert_message: str,
    subject: str = None,
    attachment_paths: list[str] = None,
) -> bool:
    """
    Envía una alerta de seguridad por correo electrónico usando SMTP con STARTTLS.

    Args:
        event_level (str): Nivel de severidad de la alerta (ej. 'CRITICAL', 'WARNING').
        module_source (str): Nombre del módulo que originó la alerta (ej. 'auth', 'ids_core').
        alert_message (str): Cuerpo del mensaje con el detalle del evento.
        subject (str, optional): Asunto personalizado. Si es None, genera un formato estándar.
        attachment_paths (list[str], optional): Lista de rutas a archivos de evidencia forense.

    Returns:
        bool: True si el correo fue transmitido exitosamente al servidor SMTP. False si hubo
              errores de autenticación, red o protocolo (los fallos se registran en el L0 logger).

    Raises:
        None: Todas las excepciones son capturadas y gestionadas internamente.
    """
    # Generar subject por defecto si no se provee
    if not subject:
        subject = f"[{event_level.upper()}] IDS Alert - {module_source}"

    sender_email = os.getenv("EMAIL_SENDER")
    sender_password = os.getenv("EMAIL_PASSWORD")
    receiver_email = os.getenv("ALERT_RECEIVER")

    # Validación básica de credenciales
    if not all([sender_email, sender_password, receiver_email]):
        logger.error("Missing SMTP credentials in environment. Alert aborted.")
        return False

    # Twelve-Factor App: Configuración externalizada con defaults seguros
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))

    msg = EmailMessage()
    msg.set_content(alert_message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # --- PROCESAMIENTO DE ADJUNTOS (Commit #2 y #3) ---
    for path_str in attachment_paths or []:
        path = Path(path_str)

        try:
            # Validar existencia antes de consultar tamaño
            if not path.exists():
                logger.warning("Attachment skipped: File not found at %s", path)
                continue

            # Validar tamaño
            if path.stat().st_size > MAX_ATTACHMENT_SIZE_BYTES:
                logger.warning(
                    "Attachment skipped: Size exceeds limit (%s bytes) for %s",
                    MAX_ATTACHMENT_SIZE_BYTES,
                    path,
                )
                continue

            # Detección de MIME type
            ctype, encoding = mimetypes.guess_type(str(path))
            if ctype is None or encoding is not None:
                # Fallback estricto a octet-stream si es desconocido o está comprimido
                ctype = "application/octet-stream"

            maintype, subtype = ctype.split("/", 1)

            # Leer y adjuntar de forma segura
            with open(path, "rb") as f:
                file_data = f.read()

            msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=path.name)
        except PermissionError:
            logger.warning("Attachment skipped: Permission denied reading %s", path)
            continue
        except Exception:
            # Catch-all de lectura para no abortar el bucle por un archivo corrupto
            logger.exception("Attachment skipped: Unexpected error reading %s", path)
            continue
    # ---------------------------------------------

    try:
        # Inicializar cliente SMTP con STARTTLS y timeout defensivo
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
