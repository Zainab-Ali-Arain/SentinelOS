"""Multi-endpoint support.

AGENT: runs on a group member's laptop, scans it and sends a report to the
server every few seconds (HTTP + JSON, protected by a shared token).
HUB:   lives inside the web server and keeps the latest report of every
endpoint (including the server laptop itself) plus a short history for graphs.

Only use this on computers whose owner has agreed to be monitored.
"""
import os
import json
import time
import hmac
import hashlib
import threading
import urllib.request
from collections import deque

from . import config

HISTORY_POINTS = 120  # points kept per endpoint for the graphs


def sign_request(body, timestamp):
    """HMAC-SHA256 over timestamp+body, keyed by the shared token."""
    return hmac.new(config.AGENT_TOKEN.encode(),
                    timestamp.encode() + body, hashlib.sha256).hexdigest()


def _load_queue():
    try:
        with open(config.AGENT_QUEUE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _save_queue(pending):
    try:
        with open(config.AGENT_QUEUE_PATH, "w") as f:
            json.dump(pending[-500:], f)  # cap so the queue file can't grow forever
    except OSError:
        pass


def build_report(state, alerts):
    """Everything the dashboard needs about one endpoint from one scan."""
    return {
        "hostname": state["hostname"],
        "system": state["system"],
        "threat_level": state["threat_level"],
        "risk_counts": state["risk_counts"],
        "monitored_files": state["monitored_files"],
        "processes": [
            {k: p[k] for k in ("pid", "ppid", "name", "app", "system", "parent_name", "cpu_percent",
                               "memory_mb", "threads", "score", "level", "reasons",
                               "notes", "mitre", "path", "username", "start_time")}
            for p in state["processes"]],
        "connections": state["connections"][:300],
        "file_events": state["file_events"][-50:],
        "alerts": alerts,
    }


class Hub:
    """Latest state of every endpoint, shared by the web pages."""

    def __init__(self, db):
        self.db = db
        self.lock = threading.Lock()
        self.endpoints = {}  # hostname -> report + ip + last_seen + history

    def update(self, report, ip, local=False):
        host = str(report["hostname"])[:64]
        if not local:  # local alerts were already saved by the local engine
            for a in report.get("alerts", []):
                self.db.add_alert(a["type"], a["process"], a["pid"], a["score"], a["level"],
                                  a["reasons"], a.get("details"), a.get("mitre", []),
                                  endpoint=host, timestamp=a.get("timestamp"))
        point = {"t": time.time(), "cpu": report["system"]["cpu_percent"],
                 "ram": report["system"]["ram_used_percent"],
                 "procs": len(report["processes"])}
        with self.lock:
            old = self.endpoints.get(host)
            if old is None:
                self.db.add_event("ENDPOINT_CONNECTED", details=f"{host} ({ip})", endpoint=host)
            history = old["history"] if old else deque(maxlen=HISTORY_POINTS)
            history.append(point)
            self.endpoints[host] = {**report, "ip": ip, "last_seen": time.time(),
                                    "local": local, "history": history}

    def _view(self, e, full):
        view = {k: v for k, v in e.items() if full or k not in
                ("processes", "connections", "file_events", "history")}
        view["online"] = time.time() - e["last_seen"] < config.ENDPOINT_OFFLINE_SEC
        view["history"] = list(e["history"])
        view["process_count"] = len(e["processes"])
        view.pop("alerts", None)
        return view

    def summary(self):
        with self.lock:
            return [self._view(e, False) for e in self.endpoints.values()]

    def detail(self, host):
        with self.lock:
            e = self.endpoints.get(host)
            return self._view(e, True) if e else None


# ------------------------------ agent ------------------------------
def run_agent(server_ip):
    """Monitor this computer and send results to the central server."""
    from .engine import SentinelEngine
    from .database import HOSTNAME

    url = f"http://{server_ip}:{config.WEB_PORT}/api/report"
    engine = SentinelEngine()
    engine.start()
    pending = _load_queue()  # alerts not delivered yet (survive restart/crash)
    if pending:
        print(f"Loaded {len(pending)} queued alert(s) from a previous run.")
    print(f"SentinelOS agent running on {HOSTNAME}")
    print(f"Reporting to {url} every {config.AGENT_INTERVAL_SEC}s. Press Ctrl+C to stop.\n")
    try:
        while True:
            # Local protection (detection, backup, recovery) always runs, even
            # if the dashboard is unreachable - only delivery is queued.
            state = engine.scan()
            pending.extend(state["new_alerts"])
            _save_queue(pending)
            body = json.dumps(build_report(state, pending)).encode()
            ts = str(int(time.time()))
            headers = {"Content-Type": "application/json",
                       "X-Sentinel-Token": config.AGENT_TOKEN,
                       "X-Sentinel-Timestamp": ts,
                       "X-Sentinel-Sign": sign_request(body, ts)}
            req = urllib.request.Request(url, data=body, method="POST", headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
                print(f"[{time.strftime('%H:%M:%S')}] sent | threat {state['threat_level']}"
                      f" | {len(pending)} alert(s) synced")
                pending = []
                _save_queue(pending)  # delivered - clear the queue on disk
            except OSError as exc:
                print(f"[{time.strftime('%H:%M:%S')}] server not reachable ({exc}); "
                      f"queued {len(pending)} alert(s) for later")
            time.sleep(config.AGENT_INTERVAL_SEC)
    except KeyboardInterrupt:
        engine.stop()
        print("\nAgent stopped.")
