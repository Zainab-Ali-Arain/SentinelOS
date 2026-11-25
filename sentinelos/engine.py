"""Module 7: Alert Manager + the main scan loop that ties every module together.

Workflow: collect -> analyze -> score -> alert -> log.
"""
import os
import time

from . import config
from .database import Database, HOSTNAME
from .detection import analyze
from .file_monitor import FileMonitor
from .lists import IocList, TrustedList
from .network_monitor import get_connections
from .process_monitor import ProcessMonitor
from .system_info import get_system_info
from .usb_monitor import UsbMonitor

LEVEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class SentinelEngine:
    def __init__(self):
        self.db = Database()
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor()
        self.iocs = IocList()
        self.trusted = TrustedList()
        self.usb_monitor = UsbMonitor()
        self.last_alert = {}   # (type, pid, level) -> time, to avoid alert spam
        self.state = {}        # latest scan results, read by the dashboard

    def start(self):
        self.file_monitor.start()
        self.db.add_event("EDR_START", details=f"Watching {config.WATCH_DIR}")
        if config.LOCKDOWN_PROTECTED:
            from . import recovery
            locked, failed = recovery.lock_all()
            self.db.add_event("LOCKDOWN_ON",
                              details=f"{locked} file(s) locked, {len(failed)} could not be locked")

    def stop(self):
        self.file_monitor.stop()
        self.usb_monitor.close()
        self.db.add_event("EDR_STOP")

    def scan(self):
        """Run one full detection cycle and return the results."""
        processes = self.process_monitor.scan()
        connections = get_connections()
        burst = self.file_monitor.is_burst()
        scored = analyze(processes, connections, burst, self.iocs, self.trusted)

        new_alerts = []
        for proc in scored:
            if LEVEL_ORDER.index(proc["level"]) >= LEVEL_ORDER.index(config.ALERT_LEVEL):
                alert = self._raise("PROCESS_ALERT", proc["name"], proc["pid"],
                                    proc["score"], proc["level"], proc["reasons"],
                                    {"app": proc["app"], "path": proc["path"],
                                     "cmdline": proc["cmdline"],
                                     "parent": f"{proc['parent_name']} ({proc['ppid']})",
                                     "cpu": proc["cpu_percent"], "memory_mb": proc["memory_mb"],
                                     "notes": proc["notes"]},
                                    proc["mitre"])
                if alert:
                    new_alerts.append(alert)

        if burst:
            alert = self._raise("RANSOMWARE_BEHAVIOR", "file system", 0, 30, "HIGH",
                                [f"{self.file_monitor.recent_count()} file changes in "
                                 f"{config.FILE_BURST_WINDOW_SEC}s"],
                                mitre=[config.MITRE["RANSOMWARE_BEHAVIOR"]])
            if alert:
                new_alerts.append(alert)

        # Real OS-protected files (hosts, startup, /etc/passwd, ...) -> CRITICAL
        if config.PROTECT_SYSTEM_FILES:
            sys_changes = self.file_monitor.check_protected()
            if sys_changes:
                names = [f"{os.path.basename(p)} {s.lower()}" for p, s in sys_changes]
                alert = self._raise("FILE_INTEGRITY", f"{len(sys_changes)} SYSTEM file(s)",
                                    0, 110, "CRITICAL",
                                    names[:5] + (["..."] if len(names) > 5 else []),
                                    {"files": [p for p, _ in sys_changes], "protected": True},
                                    [config.MITRE["FILE_INTEGRITY"]])
                if alert:
                    new_alerts.append(alert)
                if config.AUTO_RECOVERY:
                    fixed = [p for p, _ in sys_changes if self.file_monitor.recover_protected(p)]
                    if fixed:
                        self.db.add_event("FILE_RECOVERED", f"{len(fixed)} system file(s)", 0,
                                          "HIGH", ", ".join(os.path.basename(p) for p in fixed))
                        ra = self._raise("FILE_RECOVERED", f"{len(fixed)} system file(s)", 0, 40,
                                         "HIGH",
                                         [f"restored {os.path.basename(p)}" for p in fixed[:5]],
                                         {"files": fixed})
                        if ra:
                            new_alerts.append(ra)

        changes = self.file_monitor.check_integrity()
        if changes:
            # one alert per scan, listing what changed (avoids 100s of alerts)
            names = [f"{os.path.basename(p)} {s.lower()}" for p, s in changes]
            alert = self._raise("FILE_INTEGRITY", f"{len(changes)} protected file(s)", 0, 40,
                                "HIGH", names[:5] + (["..."] if len(names) > 5 else []),
                                {"files": [p for p, _ in changes]},
                                [config.MITRE["FILE_INTEGRITY"]])
            if alert:
                new_alerts.append(alert)
            if config.AUTO_RECOVERY:
                fixed = [p for p, _ in changes if self.file_monitor.recover(p)]
                if fixed:
                    self.db.add_event("FILE_RECOVERED", f"{len(fixed)} protected file(s)", 0,
                                      "HIGH", ", ".join(os.path.basename(p) for p in fixed))
                    ra = self._raise("FILE_RECOVERED", f"{len(fixed)} protected file(s)", 0, 40,
                                     "HIGH",
                                     [f"restored {os.path.basename(p)}" for p in fixed[:5]],
                                     {"files": fixed})
                    if ra:
                        new_alerts.append(ra)

        # ---- Dark web / Tor usage ----
        tor_conns = [c for c in connections if c.get("tor")]
        tor_procs = [p for p in scored
                     if p["name"].lower() in config.TOR_PROCESS_NAMES]
        if tor_conns or tor_procs:
            if tor_procs:
                who = tor_procs[0]["name"]
                pid = tor_procs[0]["pid"]
                reason = f"Tor program running: {who}"
            else:
                who = tor_conns[0]["process"]
                pid = tor_conns[0]["pid"]
                reason = (f"{who} connected to a Tor port "
                          f"{tor_conns[0]['remote_ip']}:{tor_conns[0]['remote_port']}")
            alert = self._raise("DARK_WEB", who, pid, config.DARK_WEB_SCORE, "HIGH",
                                [reason], {"connections": [
                                    f"{c['remote_ip']}:{c['remote_port']}" for c in tor_conns[:5]]},
                                [config.MITRE["DARK_WEB"]])
            if alert:
                new_alerts.append(alert)
            self.db.add_event("DARK_WEB", who, pid, "HIGH", reason)

        # ---- USB / removable media (insert + data-leak on removal) ----
        if config.USB_MONITOR:
            inserted, removed = self.usb_monitor.poll()
            for drv in inserted:
                detail = (f"{drv['device']} at {drv['mount']} | "
                          f"size {drv['total_mb']} MB (used {drv['used_mb']} MB, "
                          f"free {drv['free_mb']} MB) | inserted {drv['time']}")
                self.db.add_event("USB_INSERTED", "removable media", 0, "MEDIUM", detail)
                alert = self._raise("USB_INSERTED", drv["device"], 0, 25, "HIGH",
                                    [f"Removable drive inserted: {drv['mount']}",
                                     f"capacity {drv['total_mb']} MB, free {drv['free_mb']} MB"],
                                    drv, [config.MITRE["USB_INSERTED"]])
                if alert:
                    new_alerts.append(alert)
            for rep in removed:
                summary = (f"{rep['device']} removed after {rep['duration_sec']}s | "
                           f"{rep['file_count']} file(s), {rep['mb']} MB copied to it")
                if rep["file_count"] > 0:
                    # Files were written to the USB while it was connected -> possible leak
                    self.db.add_event("USB_DATA_LEAK", "removable media", 0, "HIGH", summary)
                    names = [os.path.basename(f["path"]) for f in rep["files"]]
                    alert = self._raise(
                        "USB_DATA_LEAK", rep["device"], 0, 50,
                        config.USB_LEAK_ALERT_LEVEL,
                        [f"{rep['file_count']} file(s) ({rep['mb']} MB) copied to USB "
                         f"in {rep['duration_sec']}s"] + names[:5]
                        + (["..."] if len(names) > 5 else []),
                        rep, [config.MITRE["USB_DATA_LEAK"]])
                    if alert:
                        new_alerts.append(alert)
                else:
                    self.db.add_event("USB_REMOVED", "removable media", 0, "LOW", summary)

        # ---- Duplicate / mass file creation (virus staging) ----
        if self.file_monitor.is_duplication():
            n = self.file_monitor.recent_created_count()
            alert = self._raise("DUPLICATE_FILES", "file system", 0, 30, "HIGH",
                                [f"{n} new files created in "
                                 f"{config.FILE_CREATE_WINDOW_SEC}s (possible duplication)"],
                                mitre=[config.MITRE["DUPLICATE_FILES"]])
            if alert:
                new_alerts.append(alert)

        for ev in self.file_monitor.take_new_events():
            self.db.add_event("FILE_" + ev["type"], details=ev["path"])

        # Process timeline (start / stop events)
        for p in self.process_monitor.started:
            self.db.add_event("PROCESS_START", f"{p['app']} ({p['name']})", p["pid"],
                              details=f"parent={p['parent_name']} ({p['ppid']}) {p['path']}")
        for p in self.process_monitor.stopped:
            self.db.add_event("PROCESS_STOP", f"{p['app']} ({p['name']})", p["pid"])

        for c in connections:
            if c["suspicious"]:
                self.db.add_event("SUSPICIOUS_CONNECTION", c["process"], c["pid"], "MEDIUM",
                                  f"{c['local']} -> {c['remote_ip']}:{c['remote_port']}")

        counts = {lvl: 0 for lvl in LEVEL_ORDER}
        for p in scored:
            counts[p["level"]] += 1
        threat = next((lvl for lvl in reversed(LEVEL_ORDER) if counts[lvl]), "LOW")

        self.state = {
            "hostname": HOSTNAME,
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

    def _raise(self, alert_type, process, pid, score, level, reasons, details=None, mitre=()):
        """Create an alert unless the same one was raised recently."""
        key = (alert_type, pid if pid else process, level)  # re-alert if level rises
        if time.time() - self.last_alert.get(key, 0) < config.ALERT_COOLDOWN_SEC:
            return None
        self.last_alert[key] = time.time()
        alert_id = self.db.add_alert(alert_type, process, pid, score, level, reasons,
                                     details, mitre)
        return {"id": alert_id, "type": alert_type, "process": process, "pid": pid,
                "score": score, "level": level, "reasons": reasons, "mitre": list(mitre),
                "details": details or {}, "endpoint": HOSTNAME,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
