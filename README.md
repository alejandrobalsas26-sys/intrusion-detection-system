# Intrusion Detection System (IDS)

## Project Overview
Sistema convergente para detección de intrusos combinando seguridad física (cámara/facial) y seguridad lógica (monitoreo de red).

## Architecture
- `vision/`: Detección facial y liveness detection.
- `auth/`: Autenticación multifactor (MFA).
- `network/`: Escaneo de puertos y anomalías.
- `alerts/`: Notificaciones automáticas por correo.

## Tech Stack
* Python 3.10+
* OpenCV & MediaPipe
* Scapy
* SQLite3

## Setup & Installation
1. Clonar el repositorio.
2. Copiar `.env.example` a `.env` y configurar las credenciales reales.
3. Instalar dependencias (pendientes).

## Status
Actualmente en fase de inicialización (scaffolding base).

## Módulos del Sistema

*   **[Logs (L0)](./logs/):** Sistema de auditoría forense basado en SQLite con fallback text-based.
*   **[Alerts (L1)](./alerts/):** Sistema de notificaciones SMTP tolerante a fallos con soporte MIME y telemetría granular.
 