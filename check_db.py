import sqlite3
from pathlib import Path

database_path = Path(__file__).with_name("references.db")
connection = sqlite3.connect(database_path)
cursor = connection.cursor()

cursor.execute("SELECT * FROM references_table")
rows = cursor.fetchall()

print("Number of records:", len(rows))
print(rows)

connection.close()
