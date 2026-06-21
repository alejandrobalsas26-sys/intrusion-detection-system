# Intrusion Detection System (IDS)

## Project Overview
Sistema convergente para detección de intrusos combinando seguridad física (cámara/facial) y seguridad lógica (monitoreo de red).

## Architecture
- `auth/`: Autenticación multifactor (MFA).
- `network/`: Escaneo de puertos y anomalías.
- `alerts/`: Notificaciones automáticas por correo.

## Tech Stack
* Python 3.11+
* Flask + Waitress (dashboard and Windows-friendly production WSGI server)
* Scapy (network sensor)
* SQLite3 (WAL) — unified event store
* cryptography (Fernet) + pyotp (TOTP MFA)
* OpenCV (planned `vision/` module — experimental, not yet tracked)

## Setup & Installation
1. Clonar el repositorio.
2. Copiar `.env.example` a `.env` y configurar las credenciales reales.
3. Instalar dependencias: `pip install -r requirements.txt`

## Status
Actualmente en fase de inicialización (scaffolding base).

## Módulos del Sistema

*   **[Logs (L0)](./logs/):** Sistema de auditoría forense basado en SQLite con fallback text-based. Incluye mantenimiento operacional (`python -m logs`): retención, integrity/quick check, VACUUM, WAL checkpoint, y sellado tamper-evident con cadena de hashes (`seal` / `verify-chain`).
*   **[Alerts (L1)](./alerts/):** Sistema de notificaciones SMTP tolerante a fallos con soporte MIME y telemetría granular. Supresión opcional de alertas duplicadas (`ALERT_DEDUP_WINDOW_SECONDS`).
 
*   **[Dashboard (L8)](./dashboard/):** Consola Flask de visualizacion read-only (patron Application Factory) con autenticacion TOTP y mitigacion de session fixation. Añade rate limiting de login por IP, RBAC (`users.role`), endpoints operacionales (`/healthz`, `/readyz`, `/metrics` Prometheus), API de incidentes (`/api/incidents`) y diagnóstico de configuración al arranque (`python -m dashboard --check`). Servidor de producción vía Waitress.
*   **[Detection](./detection/):** Núcleo de ingeniería de detección: normalización de eventos, mapeo MITRE ATT&CK, risk scoring (0–100), deduplicación y motor de correlación con ventanas deslizantes que genera incidentes (`python -m detection`). Reglas: fuerza bruta, password spray, login exitoso tras ráfaga de fallos, replay, recon→auth, network→FIM y coincidencia con listas IOC. Incluye inteligencia de amenazas local opcional (`intel.py`), análisis explicable de URLs de phishing (`phishing.py`) y playbooks de remediación por regla (`playbook.py`).
*   **[AI](./ai/):** Asistencia opcional con LLM local (Ollama/llama.cpp/vLLM, API OpenAI-compatible) para resumir alertas e incidentes. Privacy-first: desactivado por defecto y con fallback determinista sin red.

### Dashboard Module

The Dashboard is a Flask read-only console (Application Factory pattern) that surfaces audit and File Integrity Monitoring (FIM) events. It performs **no writes**: the data layer opens every SQLite connection through the `file:<path>?mode=ro` URI (`sqlite3.connect(..., uri=True)`), so the database engine itself rejects any `INSERT`/`UPDATE`/`DELETE` regardless of query content. This is a defense-in-depth guarantee enforced below the application layer. Authentication is delegated to the TOTP verifier in `auth/core.py`, and state-changing routes (e.g. `/logout`) are POST-only to resist CSRF.

> **Session invalidation note:** Logout clears the current cookie but cannot revoke previously-issued cookies (signed-cookie limitation). For production deployments with sensitive data, migrate to server-side session storage (Flask-Session + Redis) to enable true revocation.

## Documentation

* [Architecture](./docs/ARCHITECTURE.md) — diagrama de capas, modelo de datos, trust boundaries.
* [Roadmap & gap analysis](./docs/ROADMAP.md) — auditoría completa y plan de modernización por fases.
* [Deployment](./docs/DEPLOYMENT.md) — local, producción en Windows con Waitress, checklist de producción, ruta de migración a PostgreSQL.
* [Operations](./docs/OPERATIONS.md) — health/metrics, retención, backups, triaje de incidentes.
* [Security](./docs/SECURITY.md) — modelo de amenazas, gestión de secretos, limitaciones conocidas.

## Quick start (local, Windows-friendly)

```powershell
copy .env.example .env                 # configurar secretos
pip install -r requirements.txt
python -m auth.cli enroll admin ; python -m auth.cli set-role admin admin
python -m dashboard --check            # validar configuración
python -m dashboard --production       # servir vía Waitress (127.0.0.1:5000)
```

Run the correlation engine (`python -m detection --interval 60`) and the daily
retention/seal jobs (`python -m logs purge --vacuum`, `python -m logs seal`) as
scheduled tasks. See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md).

## Roadmap

- **`vision/` (planned — not yet implemented):** Detección facial y liveness detection para la capa de seguridad física. El directorio aún no existe en el repositorio.
- Ver [docs/ROADMAP.md](./docs/ROADMAP.md) para las fases 2 (Sigma rules, FIM de directorios, structured logging JSON, búsqueda en dashboard) y 3 (PostgreSQL, sesiones server-side, OpenTelemetry, analítica de comportamiento).
