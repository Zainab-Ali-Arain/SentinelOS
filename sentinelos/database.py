"""Module 9: Database / Logging - stores events and alerts in SQLite."""
import os
import csv
import json
import socket
import sqlite3
import logging
import datetime
import threading
from logging.handlers import RotatingFileHandler

from . import config

os.makedirs(config.DATA_DIR, exist_ok=True)
# The log file rolls over at LOG_MAX_MB so it can never fill the disk
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[RotatingFileHandler(config.LOG_PATH, maxBytes=config.LOG_MAX_MB * 1024 * 1024,
                                  backupCount=config.LOG_BACKUPS, encoding="utf-8")])
log = logging.getLogger("sentinelos")

# Name shown on the dashboard; set SENTINEL_NAME (or --name) to choose your own
HOSTNAME = os.environ.get("SENTINEL_NAME") or socket.gethostname()


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
        self.cleanup()

    def cleanup(self, days=config.EVENT_RETENTION_DAYS):
        """Delete activity-log events older than `days` so the database stays small.
        Alerts are kept. Returns how many events were deleted."""
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            deleted = self.conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,)).rowcount
            self.conn.commit()
            if deleted:
                self.conn.execute("VACUUM")  # give the freed space back to the disk
        return deleted

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

    def recent_alerts(self, limit=200, endpoint=None):
        """Newest alerts; `endpoint` limits them to one laptop (None = all)."""
        if endpoint is None:
            return self._read("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        return self._read("SELECT * FROM alerts WHERE endpoint = ? ORDER BY id DESC LIMIT ?",
                          (endpoint, limit))

    EVENT_GROUPS = {"process": "PROCESS_%", "file": "FILE_%", "login": "LOGIN_%",
                    "response": "RESPONSE_%", "network": "%CONNECTION%"}

    def recent_events(self, limit=300, group="", search="", endpoint=None):
        """Newest events, optionally only one group (e.g. "process"), matching text
        or one laptop (`endpoint`, None = all)."""
        sql, params = "SELECT * FROM events WHERE 1=1", []
        if endpoint is not None:
            sql += " AND endpoint = ?"
            params.append(endpoint)
        if group in self.EVENT_GROUPS:
            sql += " AND event_type LIKE ?"
            params.append(self.EVENT_GROUPS[group])
        if search:
            sql += " AND (event_type || ' ' || process || ' ' || details || ' ' || endpoint) LIKE ?"
            params.append(f"%{search}%")
        return self._read(sql + " ORDER BY id DESC LIMIT ?", (*params, limit))

    def event_counts(self, column, endpoint=None):
        """How many events per event_type or per endpoint (for the charts)."""
        if column not in ("event_type", "endpoint"):
            raise ValueError(column)
        where, params = ("WHERE endpoint = ?", (endpoint,)) if endpoint is not None else ("", ())
        return {r["k"]: r["n"] for r in self._read(
            f"SELECT {column} AS k, COUNT(*) AS n FROM events {where} GROUP BY {column}", params)}

    def get_alert(self, alert_id):
        rows = self._read("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return rows[0] if rows else None

    def export_csv(self, path, table="alerts", endpoint=None):
        """Write every row of `table` (or only one laptop's) to a CSV file. Returns the row count."""
        if endpoint is None:
            rows = self._read(f"SELECT * FROM {table} ORDER BY id")
        else:
            rows = self._read(f"SELECT * FROM {table} WHERE endpoint = ? ORDER BY id", (endpoint,))
        with open(path, "w", newline="", encoding="utf-8") as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
        return len(rows)
