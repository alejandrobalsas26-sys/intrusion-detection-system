# Módulo L1: Email Alerts (SMTP)

Módulo encargado de la notificación asíncrona de eventos de seguridad del IDS. Diseñado con foco en tolerancia a fallos de red, granularidad forense y manejo seguro de adjuntos MIME (defensa contra *zip bombs* y *OOM kills*).

## Requisitos Previos (App Passwords)

Google bloquea la autenticación SMTP básica con contraseñas regulares desde 2022. Es obligatorio utilizar una **App Password** para la cuenta emisora:
1. Activa 2FA (Verificación en dos pasos) en tu cuenta de Google.
2. Genera una contraseña de aplicación en: [App Passwords](https://myaccount.google.com/apppasswords)
3. **ADVERTENCIA:** NUNCA commitees la App Password. Define esta credencial únicamente en el entorno local (referencia: `.env.example`).

## Variables de Entorno (Contrato 12-Factor)

El módulo requiere las siguientes variables definidas en el entorno:

*   `EMAIL_SENDER`: Correo emisor autorizado (ej. ids.service.account@gmail.com).
*   `EMAIL_PASSWORD`: App Password generada de 16 caracteres (sin espacios).
*   `ALERT_RECEIVER`: Correo del administrador o SOC que recibirá las alertas.
*   `SMTP_HOST`: (Opcional) Servidor SMTP a utilizar. Default: `smtp.gmail.com`.
*   `SMTP_PORT`: (Opcional) Puerto para la conexión STARTTLS. Default: `587`.

## Dependencias Externas
*   `python-dotenv`: Requerido para la carga de variables `.env` en entornos de desarrollo local. *(Nota: El manifiesto completo de dependencias se añadirá en la rama `chore(infra)` tras el merge de este módulo).*

## Ejemplo de Uso
```python
from alerts import send_security_alert

# La inyección del logger (L0) y el manejo de excepciones SMTP operan de forma transparente.
success = send_security_alert(
    event_level="CRITICAL",
    module_source="ids_core",
    alert_message="Se ha detectado acceso no autorizado en el puerto 22.",
    attachment_paths=["/var/log/auth.log"] # Ignorado de forma segura si no existe o excede 15MB.
)
