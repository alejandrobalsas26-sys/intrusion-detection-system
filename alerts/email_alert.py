import smtplib
import os
import mimetypes
from pathlib import Path
from email.message import EmailMessage
from logs import get_logger

# Inyectar dependencia del logger a nivel de módulo (Lectura A)
logger = get_logger("alerts")

def send_security_alert(
    event_level: str, 
    module_source: str, 
    alert_message: str, 
    subject: str = None, 
    attachment_paths: list[str] = None
) -> bool:
    """
    Envía una alerta de seguridad por correo electrónico usando SMTP con STARTTLS.
    """
    # Generar subject por defecto si no se provee
    if not subject:
        subject = f"[{event_level.upper()}] IDS Alert - {module_source}"
        
    sender_email = os.getenv("EMAIL_SENDER")
    sender_password = os.getenv("EMAIL_PASSWORD")
    receiver_email = os.getenv("ALERT_RECEIVER")
    
    # Validación básica de credenciales
    if not all([sender_email, sender_password, receiver_email]):
        return False
        
    # Twelve-Factor App: Configuración externalizada con defaults seguros
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
        
    msg = EmailMessage()
    msg.set_content(alert_message)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email
    
    # --- PROCESAMIENTO DE ADJUNTOS (Commit #2) ---
    for path_str in (attachment_paths or []):
        path = Path(path_str)
        
        try:
            # Validar existencia antes de consultar tamaño
            if not path.exists():
                # TODO(commit-3): logger.warning here on skip (FileNotFound)
                continue
                
            # Validar tamaño (15 MB límite conservador pre-Base64)
            if path.stat().st_size > 15 * 1024 * 1024:
                # TODO(commit-3): logger.warning here on skip (Size limit exceeded)
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
                
            msg.add_attachment(
                file_data, 
                maintype=maintype, 
                subtype=subtype, 
                filename=path.name
            )
        except PermissionError:
            # TODO(commit-3): logger.warning here on skip (PermissionError)
            continue
        except Exception:
            # Catch-all de lectura para no abortar el bucle por un archivo corrupto
            # TODO(commit-3): logger.warning here on skip (Unexpected error reading attachment)
            continue
    # ---------------------------------------------
    
    try:
        # Inicializar cliente SMTP con STARTTLS y timeout defensivo
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except smtplib.SMTPException:
        # El manejo de errores y la instrumentación del logger vendrán en el Commit #3
        return False
    except Exception:
        # Catch-all base temporal
        return False