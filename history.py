
import sqlite3
from datetime import datetime

def create_history_table():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            prediction TEXT,
            threat_score INTEGER,
            scan_date TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(email, prediction, threat_score):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (email, prediction, threat_score, scan_date)
        VALUES (?, ?, ?, ?)
    """, (
        email,
        prediction,
        threat_score,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_history():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scan_history
        ORDER BY id DESC
    """)

    records = cursor.fetchall()
    conn.close()
    return records

def get_analytics():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT prediction, COUNT(*)
        FROM scan_history
        GROUP BY prediction
    """)

    records = cursor.fetchall()
    conn.close()

    return dict(records)
