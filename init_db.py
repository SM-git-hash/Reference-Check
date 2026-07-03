import sqlite3
from pathlib import Path

database_path = Path(__file__).with_name("references.db")
connection = sqlite3.connect(database_path)
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS references_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_name TEXT NOT NULL,
    referee_name TEXT NOT NULL,
    referee_email TEXT NOT NULL,
    organisation TEXT NOT NULL,
    job_title TEXT NOT NULL,
    relationship TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    rehire TEXT NOT NULL,
    clinical_competence TEXT NOT NULL,
    communication_skills TEXT NOT NULL,
    professional_conduct TEXT NOT NULL,
    reference_text TEXT NOT NULL,
    signature TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

connection.commit()
connection.close()

print("Database created successfully.")
