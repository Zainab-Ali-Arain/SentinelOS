"""Module 7: Alert Manager + the main scan loop that ties every module together.

Workflow: collect -> analyze -> score -> alert -> log.
"""
import os
import time

from . import config
from .database import Database
from .detection import analyze
from .file_monitor import FileMonitor
from .network_monitor import get_connections
from .process_monitor import ProcessMonitor
from .system_info import get_system_info

LEVEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class SentinelEngine:
    def __init__(self):
        self.db = Database()
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor()
        self.last_alert = {}   # (type, pid) -> time, to avoid alert spam
        self.state = {}        # latest scan results, read by the dashboard

    def start(self):
        self.file_monitor.start()
        self.db.add_event("EDR_START", details=f"Watching {config.WATCH_DIR}")

    def stop(self):
        self.file_monitor.stop()
        self.db.add_event("EDR_STOP")

    def scan(self):
        """Run one full detection cycle and return the results."""
        processes = self.process_monitor.scan()
        connections = get_connections()
        burst = self.file_monitor.is_burst()
        scored = analyze(processes, connections, burst)

        new_alerts = []
        for proc in scored:
            if LEVEL_ORDER.index(proc["level"]) >= LEVEL_ORDER.index(config.ALERT_LEVEL):
                alert = self._raise("PROCESS_ALERT", proc["name"], proc["pid"],
                                    proc["score"], proc["level"], proc["reasons"],
                                    {"path": proc["path"], "cmdline": proc["cmdline"],
                                     "cpu": proc["cpu_percent"], "memory_mb": proc["memory_mb"]})
                if alert:
                    new_alerts.append(alert)

        if burst:
            alert = self._raise("RANSOMWARE_BEHAVIOR", "file system", 0, 30, "HIGH",
                                [f"{self.file_monitor.recent_count()} file changes in "
                                 f"{config.FILE_BURST_WINDOW_SEC}s"])
            if alert:
                new_alerts.append(alert)

        changes = self.file_monitor.check_integrity()
        if changes:
            # one alert per scan, listing what changed (avoids 100s of alerts)
            names = [f"{os.path.basename(p)} {s.lower()}" for p, s in changes]
            alert = self._raise("FILE_INTEGRITY", f"{len(changes)} protected file(s)", 0, 40,
                                "HIGH", names[:5] + (["..."] if len(names) > 5 else []),
                                {"files": [p for p, _ in changes]})
            if alert:
                new_alerts.append(alert)

        for ev in self.file_monitor.take_new_events():
            self.db.add_event("FILE_" + ev["type"], details=ev["path"])

        for c in connections:
            if c["suspicious"]:
                self.db.add_event("SUSPICIOUS_CONNECTION", c["process"], c["pid"], "MEDIUM",
                                  f"{c['local']} -> {c['remote_ip']}:{c['remote_port']}")

        counts = {lvl: 0 for lvl in LEVEL_ORDER}
        for p in scored:
            counts[p["level"]] += 1
        threat = next((lvl for lvl in reversed(LEVEL_ORDER) if counts[lvl]), "LOW")

        self.state = {
            "system": get_system_info(),
            "processes": scored,
            "connections": connections,
            "file_events": list(self.file_monitor.events)[-200:],
            "monitored_files": self.file_monitor.file_count(),
            "risk_counts": counts,
            "threat_level": threat,
            "new_alerts": new_alerts,
        }
        return self.state

    def _raise(self, alert_type, process, pid, score, level, reasons, details=None):
        """Create an alert unless the same one was raised recently."""
        key = (alert_type, pid if pid else process, level)  # re-alert if level rises
        if time.time() - self.last_alert.get(key, 0) < config.ALERT_COOLDOWN_SEC:
            return None
        self.last_alert[key] = time.time()
        alert_id = self.db.add_alert(alert_type, process, pid, score, level, reasons, details)
        return {"id": alert_id, "type": alert_type, "process": process, "pid": pid,
                "score": score, "level": level, "reasons": reasons}
