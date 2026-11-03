"""Multi-endpoint support.

AGENT: runs on a group member's laptop, scans it and sends a report to the
server every few seconds (HTTP + JSON, protected by a shared token).
HUB:   lives inside the web server and keeps the latest report of every
endpoint (including the server laptop itself) plus a short history for graphs.

Only use this on computers whose owner has agreed to be monitored.
"""
import json
import time
import threading
import urllib.request
from collections import deque

from . import config

HISTORY_POINTS = 120  # points kept per endpoint for the graphs


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
        "totals": {"threads": sum(p.get("threads", 0) for p in state["processes"]),
                   "handles": sum(p.get("handles", 0) for p in state["processes"])},
        "connections": state["connections"][:300],
        "file_events": state["file_events"][-50:],
        "alerts": alerts,
    }


def perf_rates(prev, cur):
    """Disk and network speeds from two consecutive `system` blocks.

    The agent only sends cumulative counters; the difference between two
    reports divided by the time between them is the speed. Returns {} when
    there is nothing to compare (first report, old agent, long gap, restart).
    """
    try:
        dt = float(cur["sampled_at"]) - float(prev["sampled_at"])
    except (KeyError, TypeError, ValueError):
        return {}
    if not 0 < dt <= 120:
        return {}

    def speed(new, old):
        return round(max(0.0, (new - old) / dt), 1)

    out = {}
    d0, d1 = prev.get("disk_io"), cur.get("disk_io")
    if d0 and d1:
        out["disk_read"] = speed(d1["read_bytes"], d0["read_bytes"])
        out["disk_write"] = speed(d1["write_bytes"], d0["write_bytes"])
        busy = (d1["busy_ms"] - d0["busy_ms"]) / (dt * 1000) * 100
        out["disk_active"] = round(min(100.0, max(0.0, busy)), 1)
    n0, n1 = prev.get("net") or {}, cur.get("net") or {}
    out["net"] = {name: [speed(c["sent"], n0[name]["sent"]), speed(c["recv"], n0[name]["recv"])]
                  for name, c in n1.items() if name in n0}
    return out


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


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
        totals = report.get("totals") if isinstance(report.get("totals"), dict) else {}
        threads = sum(int(p.get("threads", 0)) for p in report["processes"])
        handles = _number(totals.get("handles"))
        with self.lock:
            old = self.endpoints.get(host)
            if old:
                point.update(perf_rates(old["system"], report["system"]))
            if old is None:
                self.db.add_event("ENDPOINT_CONNECTED", details=f"{host} ({ip})", endpoint=host)
            history = old["history"] if old else deque(maxlen=HISTORY_POINTS)
            history.append(point)
            self.endpoints[host] = {**report, "ip": ip, "last_seen": time.time(),
                                    "local": local, "history": history,
                                    "threads": threads, "handles": handles or None}

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
    pending = []  # alerts not delivered yet (server unreachable)
    print(f"SentinelOS agent running on {HOSTNAME}")
    print(f"Reporting to {url} every {config.AGENT_INTERVAL_SEC}s. Press Ctrl+C to stop.\n")
    try:
        while True:
            state = engine.scan()
            pending.extend(state["new_alerts"])
            body = json.dumps(build_report(state, pending)).encode()
            req = urllib.request.Request(url, data=body, method="POST", headers={
                "Content-Type": "application/json", "X-Sentinel-Token": config.AGENT_TOKEN})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
                print(f"[{time.strftime('%H:%M:%S')}] sent | threat {state['threat_level']}"
                      f" | {len(pending)} new alert(s)")
                pending = []
            except OSError as exc:
                print(f"[{time.strftime('%H:%M:%S')}] server not reachable ({exc}); "
                      f"keeping {len(pending)} alert(s) for later")
            time.sleep(config.AGENT_INTERVAL_SEC)
    except KeyboardInterrupt:
        engine.stop()
        print("\nAgent stopped.")
