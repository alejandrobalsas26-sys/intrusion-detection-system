import logging
import sqlite3
import os
import sys
import json
from pathlib import Path
from datetime import datetime

class SQLiteAuditHandler(logging.Handler):
    def __init__(self, db_path: str, failsafe_path: str):
        super().__init__()
        self.db_path = db_path
        self.failsafe_path = failsafe_path
        self.schema_path = Path(__file__).parent / "schema.sql"
        self._bootstrap_db()

    def _bootstrap_db(self):
        try:
            # Bug #2 Resuelto: Asegurar que el directorio exista antes de conectar
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                with open(self.schema_path, "r") as f:
                    conn.executescript(f.read())
        except Exception as e:
            sys.stderr.write(f"CRITICAL BOOTSTRAP ERROR: {e}\n")

    def emit(self, record: logging.LogRecord):
        try:
            context_data = getattr(record, "context", {})
            context_json = json.dumps(context_data) if context_data else None
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = "INSERT INTO audit_events (timestamp, level, module_source, message, context_data) VALUES (?, ?, ?, ?, ?)"
                cursor.execute(query, (record.created, record.levelname, record.name, record.getMessage(), context_json))
                # Removed redundant conn.commit()
        except Exception as e:
            self._write_failsafe(record, e)

# ... (deja tu función _write_failsafe como está) ...
def get_logger(module_name: str) -> logging.Logger:
    logger = logging.getLogger(module_name)
    logger.propagate = False
    logger.setLevel(logging.INFO)
    
    if not any(isinstance(h, SQLiteAuditHandler) for h in logger.handlers):
        # Bug #1 Resuelto: Dejar que pathlib resuelva si es absoluto o relativo
        db_path_env = os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
        failsafe_env = os.getenv("FAILSAFE_LOG_PATH", "./logs/failsafe.log")
        
        abs_db_path = Path(db_path_env).resolve()
        abs_failsafe_path = Path(failsafe_env).resolve()
        
        handler = SQLiteAuditHandler(str(abs_db_path), str(abs_failsafe_path))
        logger.addHandler(handler)
        
    return logger