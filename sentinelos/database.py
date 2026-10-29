"""Module 9: Database / Logging - stores events and alerts in SQLite."""
import os
import json
import sqlite3
import logging
import datetime

from . import config

os.makedirs(config.DATA_DIR, exist_ok=True)
logging.basicConfig(
    filename=config.LOG_PATH, level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("sentinelos")


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path=config.DB_PATH):
        # check_same_thread=False: the dashboard scans in a background thread
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, event_type TEXT, process TEXT, pid INTEGER,
                severity TEXT, details TEXT);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, alert_type TEXT, process TEXT, pid INTEGER,
                score INTEGER, severity TEXT, reasons TEXT, details TEXT,
                status TEXT DEFAULT 'NEW', response TEXT DEFAULT '');
        """)
        self.conn.commit()

    def add_event(self, event_type, process="", pid=0, severity="INFO", details=""):
        self.conn.execute(
            "INSERT INTO events (timestamp, event_type, process, pid, severity, details)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (now(), event_type, process, pid, severity, details))
        self.conn.commit()
        log.info("%s | %s | PID=%s | %s | %s", event_type, process, pid, severity, details)

    def add_alert(self, alert_type, process, pid, score, severity, reasons, details=None):
        cur = self.conn.execute(
            "INSERT INTO alerts (timestamp, alert_type, process, pid, score, severity,"
            " reasons, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now(), alert_type, process, pid, score, severity,
             ", ".join(reasons), json.dumps(details or {})))
        self.conn.commit()
        log.warning("%s | %s | PID=%s | %s | score=%s | %s",
                    alert_type, process, pid, severity, score, ", ".join(reasons))
        return cur.lastrowid

    def set_alert_status(self, alert_id, status, response=""):
        self.conn.execute("UPDATE alerts SET status = ?, response = ? WHERE id = ?",
                          (status, response, alert_id))
        self.conn.commit()
        log.info("ALERT_RESPONSE | alert=%s | %s | %s", alert_id, status, response)

    def recent_alerts(self, limit=200):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]

    def recent_events(self, limit=300):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    def get_alert(self, alert_id):
        row = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None
