import logging
import sqlite3
import os
import sys
import json
from pathlib import Path
from datetime import datetime

class SQLiteAuditHandler(logging.Handler):
    """Custom logging handler que inyecta eventos directamente a SQLite con WAL."""
    
    def __init__(self, db_path: str, failsafe_path: str):
        super().__init__()
        self.db_path = db_path
        self.failsafe_path = failsafe_path
        
        # Trampa 2 Resuelta: Ruta absoluta al schema.sql basada en la ubicación de este archivo
        self.schema_path = Path(__file__).parent / "schema.sql"
        
        # Inicializar la base de datos al arrancar
        self._bootstrap_db()

    def _bootstrap_db(self):
        """Ejecuta schema.sql para garantizar idempotencia al arranque."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Trampa 3 Resuelta: executescript para comandos múltiples
                with open(self.schema_path, "r") as f:
                    conn.executescript(f.read())
        except Exception as e:
            # Si hasta la creación falla, reportarlo a consola inmediatamente
            sys.stderr.write(f"CRITICAL BOOTSTRAP ERROR: Failed to initialize SQLite DB: {e}\n")

    def emit(self, record: logging.LogRecord):
        """Captura un evento, extrae datos forenses y lo inserta en SQLite."""
        try:
            # Extraer variables extra pasadas en el log (ej. logger.warning("msg", extra={"ip": "1.1.1.1"}))
            context_data = getattr(record, "context", {})
            context_json = json.dumps(context_data) if context_data else None
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Trampa 1 Resuelta: Inserción parametrizada (?) contra Inyección SQL
                query = """
                    INSERT INTO audit_events (timestamp, level, module_source, message, context_data)
                    VALUES (?, ?, ?, ?, ?)
                """
                cursor.execute(query, (
                    record.created,          # Timestamp epoch en segundos nativo de logging
                    record.levelname,        # INFO, WARNING, CRITICAL
                    record.name,             # Nombre del módulo (ej. 'vision')
                    record.getMessage(),     # Mensaje formateado
                    context_json             # JSON string o None
                ))
                conn.commit()
                
        except Exception as e:
            # Fallback en caso de error en I/O de SQLite
            self._write_failsafe(record, e)

    def _write_failsafe(self, record: logging.LogRecord, error: Exception):
        """Escribe en log de texto plano si SQLite falla. Deriva a stderr si esto también falla."""
        failsafe_msg = f"[{datetime.now().isoformat()}] SQLITE_FAIL ({error}) | {record.levelname} - {record.name} - {record.getMessage()}\n"
        try:
            # Trampa 2 (variante): Asegurar que el directorio padre del failsafe exista
            Path(self.failsafe_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.failsafe_path, "a") as f:
                f.write(failsafe_msg)
        except Exception:
            # Último recurso absoluto: Escupir al sistema
            sys.stderr.write("FATAL FALLBACK ERROR: " + failsafe_msg)
            self.handleError(record)


def get_logger(module_name: str) -> logging.Logger:
    """Fábrica que retorna un logger configurado con SQLiteAuditHandler."""
    logger = logging.getLogger(module_name)
    
    # Prevenir duplicación en el root logger
    logger.propagate = False
    
    # Definir nivel mínimo a capturar
    logger.setLevel(logging.INFO)
    
    # Trampa 4 Resuelta: Anti-duplicación de handlers
    has_sqlite_handler = any(isinstance(h, SQLiteAuditHandler) for h in logger.handlers)
    
    if not has_sqlite_handler:
        # Carga perezosa de rutas (asume que dotenv se cargó en main.py, si no, usa valores por defecto)
        db_path = os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
        failsafe_path = os.getenv("FAILSAFE_LOG_PATH", "./logs/failsafe.log")
        
        # Trampa 2 (variante): Asegurar que los paths de BD y failsafe resuelvan correctamente desde el CWD
        base_dir = Path.cwd()
        abs_db_path = base_dir / db_path.strip("./")
        abs_failsafe_path = base_dir / failsafe_path.strip("./")
        
        # Instanciar e inyectar el handler
        handler = SQLiteAuditHandler(str(abs_db_path), str(abs_failsafe_path))
        logger.addHandler(handler)
        
    return logger 