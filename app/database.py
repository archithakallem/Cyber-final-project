import sqlite3

conn = sqlite3.connect("data/cyberscan.db", check_same_thread=False)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()


def init_db():
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            exposure REAL,
            threat REAL,
            context REAL,
            risk REAL
        )
        """
    )
    conn.commit()


def save_scan(target, scores):
    cursor.execute(
        """
        INSERT INTO scans (target, exposure, threat, context, risk)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            target,
            scores["exposure"],
            scores["threat"],
            scores["context"],
            scores["risk"],
        ),
    )
    conn.commit()


def get_history(target):
    cursor.execute(
        "SELECT id, target, timestamp, exposure, threat, context, risk FROM scans WHERE target=? ORDER BY timestamp ASC, id ASC",
        (target,),
    )
    return [dict(row) for row in cursor.fetchall()]
