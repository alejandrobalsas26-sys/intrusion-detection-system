import sqlite3

conn = sqlite3.connect('logs/ids_database.sqlite3')
cur = conn.cursor()
cur.execute(
    "SELECT timestamp, level, module_source, message, context_data"
    " FROM audit_events ORDER BY id DESC LIMIT 10"
)
for row in cur.fetchall():
    print(row)
