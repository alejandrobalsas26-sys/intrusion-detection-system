import json
import logging
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path


class SQLiteAuditHandler(logging.Handler):
    """
    Handler forense de alta disponibilidad con persistencia en SQLite.
    Implementa redundancia automática (Failsafe) y blindaje contra SQLi.
    """

    def __init__(self, db_path: str, failsafe_path: str):
        super().__init__()
        self.db_path = db_path
        self.failsafe_path = failsafe_path
        self.schema_path = Path(__file__).parent / "schema.sql"
        self._bootstrap_db()

    def _bootstrap_db(self):
        """Asegura la infraestructura de datos antes de la primera ingesta."""
        try:
            # Bug #2 Fix: mkdir garantiza que el path exista en despliegues limpios
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                # Unicode Fix: Forzamos encoding para evitar errores de charmap en Windows
                with open(self.schema_path, encoding="utf-8") as f:
                    conn.executescript(f.read())
        except Exception as e:
            sys.stderr.write(f"CRITICAL BOOTSTRAP ERROR: {e}\n")

    def emit(self, record: logging.LogRecord):
        """Inyecta el evento en la DB. Falla hacia el log de texto si hay bloqueo de DB."""
        try:
            context_data = getattr(record, "context", {})
            context_json = json.dumps(context_data) if context_data else None

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = "INSERT INTO audit_events (timestamp, level, module_source, message, context_data) VALUES (?, ?, ?, ?, ?)"  # noqa: E501
                # SQLi Protection: Binding paramétrico nativo
                cursor.execute(
                    query,
                    (
                        record.created,
                        record.levelname,
                        record.name,
                        record.getMessage(),
                        context_json,
                    ),
                )
        except Exception as e:
            self._write_failsafe(record, e)

    def _write_failsafe(self, record: logging.LogRecord, error: Exception):
        """
        Capa de redundancia C1. Escribe en texto plano si la capa C0 (SQLite) no está disponible.
        """
        failsafe_msg = f"[{datetime.now().isoformat()}] SQLITE_FAIL ({error}) | {record.levelname} - {record.name} - {record.getMessage()}\n"  # noqa: E501
        try:
            Path(self.failsafe_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.failsafe_path, "a", encoding="utf-8") as f:
                f.write(failsafe_msg)
        except Exception:
            # Última línea de defensa: Salida estándar de error del sistema
            sys.stderr.write("FATAL FALLBACK ERROR: " + failsafe_msg)
            self.handleError(record)


def get_logger(module_name: str) -> logging.Logger:
    """Fábrica de loggers con singleton de handler para evitar duplicidad de registros."""
    logger = logging.getLogger(module_name)
    logger.propagate = False
    logger.setLevel(logging.INFO)

    if not any(isinstance(h, SQLiteAuditHandler) for h in logger.handlers):
        # Bug #1 Fix: Path.resolve() gestiona inteligentemente rutas relativas y absolutas
        db_path_env = os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
        failsafe_env = os.getenv("FAILSAFE_LOG_PATH", "./logs/failsafe.log")

        abs_db_path = Path(db_path_env).resolve()
        abs_failsafe_path = Path(failsafe_env).resolve()

        handler = SQLiteAuditHandler(str(abs_db_path), str(abs_failsafe_path))
        logger.addHandler(handler)

    return logger
