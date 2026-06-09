# Antigravity-IDS dashboard image.
# Non-root, slim base, production WSGI server (gunicorn).
FROM python:3.12-slim

# Security: never run as root; libpcap is only needed by the network sensor,
# which is NOT part of this image (it requires host networking + CAP_NET_RAW
# and should run on the host or in a dedicated privileged sidecar).
RUN groupadd --gid 10001 ids && useradd --uid 10001 --gid ids --create-home ids

WORKDIR /app

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

COPY ai/ ai/
COPY alerts/ alerts/
COPY auth/ auth/
COPY dashboard/ dashboard/
COPY detection/ detection/
COPY fim/ fim/
COPY logs/logger.py logs/maintenance.py logs/schema.sql logs/__init__.py logs/__main__.py logs/
COPY network/ network/

# Event store lives on a volume so it survives container replacement.
RUN mkdir -p /data && chown ids:ids /data
ENV DB_PATH=/data/ids_database.sqlite3 \
    FAILSAFE_LOG_PATH=/data/failsafe.log \
    FLASK_ENV=production \
    PYTHONUNBUFFERED=1

USER ids
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "dashboard:create_app()"]
