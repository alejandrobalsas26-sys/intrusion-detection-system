import smtplib
import os
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