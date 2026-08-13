import sqlite3

conn = sqlite3.connect("vulnmonitor.db")

cursor = conn.cursor()

cursor.execute("SELECT id, empresa_id, nome FROM ativos")

print(cursor.fetchall())

conn.close()