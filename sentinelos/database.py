"""Module 9: Database / Logging - stores events and alerts in SQLite."""
import os
import csv
import json
import socket
import sqlite3
import logging
import datetime
import threading

from . import config

os.makedirs(config.DATA_DIR, exist_ok=True)
logging.basicConfig(
    filename=config.LOG_PATH, level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("sentinelos")

HOSTNAME = socket.gethostname()


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path=config.DB_PATH):
        # check_same_thread=False + a lock: the scanner, the dashboard and the
        # agent server all use the database from different threads
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
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
        # Columns added in version 2 (keeps databases from version 1 working)
        for table, column in [("events", "endpoint"), ("alerts", "endpoint"),
                              ("alerts", "mitre")]:
            cols = [r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")]
            if column not in cols:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT DEFAULT ''")
        self.conn.commit()

    def _write(self, sql, params):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid

    def _read(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params)]

    def add_event(self, event_type, process="", pid=0, severity="INFO", details="",
                  endpoint=HOSTNAME):
        self._write(
            "INSERT INTO events (timestamp, event_type, process, pid, severity, details,"
            " endpoint) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now(), event_type, process, pid, severity, details, endpoint))
        log.info("%s | %s | %s | PID=%s | %s | %s",
                 endpoint, event_type, process, pid, severity, details)

    def add_alert(self, alert_type, process, pid, score, severity, reasons, details=None,
                  mitre=(), endpoint=HOSTNAME, timestamp=None):
        alert_id = self._write(
            "INSERT INTO alerts (timestamp, alert_type, process, pid, score, severity,"
            " reasons, details, mitre, endpoint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp or now(), alert_type, process, pid, score, severity,
             ", ".join(reasons), json.dumps(details or {}), ", ".join(mitre), endpoint))
        log.warning("%s | %s | %s | PID=%s | %s | score=%s | %s",
                    endpoint, alert_type, process, pid, severity, score, ", ".join(reasons))
        return alert_id

    def set_alert_status(self, alert_id, status, response=""):
        self._write("UPDATE alerts SET status = ?, response = ? WHERE id = ?",
                    (status, response, alert_id))
        log.info("ALERT_RESPONSE | alert=%s | %s | %s", alert_id, status, response)

    def recent_alerts(self, limit=200):
        return self._read("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    def recent_events(self, limit=300):
        return self._read("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def get_alert(self, alert_id):
        rows = self._read("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return rows[0] if rows else None

    def export_csv(self, path, table="alerts"):
        """Write every row of `table` to a CSV file. Returns the row count."""
        rows = self._read(f"SELECT * FROM {table} ORDER BY id")
        with open(path, "w", newline="", encoding="utf-8") as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
        return len(rows)
