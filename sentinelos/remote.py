"""Multi-endpoint support: an AGENT on another laptop sends its results to a
central SERVER (the dashboard laptop) over the local network (HTTP + JSON).

Only use this on computers whose owner has agreed to be monitored.
"""
import hmac
import json
import time
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config

MAX_BODY = 2 * 1024 * 1024  # reject reports bigger than 2 MB


def build_report(state, alerts):
    """Small summary of one scan (the full process list is not needed)."""
    return {
        "hostname": state["hostname"],
        "system": state["system"],
        "threat_level": state["threat_level"],
        "risk_counts": state["risk_counts"],
        "process_count": len(state["processes"]),
        "top_processes": [
            {k: p[k] for k in ("pid", "name", "cpu_percent", "memory_mb", "score",
                               "level", "reasons", "path", "parent_name")}
            for p in state["processes"][:40]],
        "alerts": alerts,
    }


# ------------------------------ server ------------------------------
class EndpointServer:
    """Receives reports from agents. Runs inside the dashboard process."""

    def __init__(self, db, port=config.SERVER_PORT):
        self.db = db
        self.port = port
        self.endpoints = {}        # hostname -> latest report + ip + last_seen
        self.incoming_alerts = []  # remote alerts waiting to be shown as popups
        self.lock = threading.Lock()
        self.httpd = None

    def start(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                token = self.headers.get("X-Sentinel-Token", "")
                if not hmac.compare_digest(token, config.AGENT_TOKEN):
                    return self._reply(403, "bad token")
                length = int(self.headers.get("Content-Length", 0))
                if self.path != "/report" or not 0 < length <= MAX_BODY:
                    return self._reply(400, "bad request")
                try:
                    report = json.loads(self.rfile.read(length))
                    server.handle_report(report, self.client_address[0])
                except (ValueError, KeyError, TypeError) as exc:
                    return self._reply(400, f"invalid report: {exc}")
                self._reply(200, "ok")

            def _reply(self, code, text):
                self.send_response(code)
                self.end_headers()
                self.wfile.write(text.encode())

            def log_message(self, *args):  # keep the console quiet
                pass

        self.httpd = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.db.add_event("SERVER_START", details=f"Listening for agents on port {self.port}")

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()

    def handle_report(self, report, ip):
        host = str(report["hostname"])[:64]
        for a in report.get("alerts", []):
            self.db.add_alert(a["type"], a["process"], a["pid"], a["score"], a["level"],
                              a["reasons"], a.get("details"), a.get("mitre", []),
                              endpoint=host, timestamp=a.get("timestamp"))
        with self.lock:
            if host not in self.endpoints:
                self.db.add_event("ENDPOINT_CONNECTED", details=f"{host} ({ip})", endpoint=host)
            self.endpoints[host] = {**report, "ip": ip, "last_seen": time.time()}
            self.incoming_alerts.extend({**a, "endpoint": host} for a in report.get("alerts", []))

    def take_alerts(self):
        with self.lock:
            out, self.incoming_alerts = self.incoming_alerts, []
        return out

    def snapshot(self):
        """List of endpoints with an ONLINE/OFFLINE status."""
        with self.lock:
            items = list(self.endpoints.values())
        for e in items:
            e["online"] = time.time() - e["last_seen"] < config.ENDPOINT_OFFLINE_SEC
        return items


# ------------------------------ agent ------------------------------
def run_agent(server_ip):
    """Monitor this computer and send results to the central server."""
    from .engine import SentinelEngine
    from .database import HOSTNAME

    url = f"http://{server_ip}:{config.SERVER_PORT}/report"
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
