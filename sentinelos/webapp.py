"""Web dashboard: login, 4 dashboard pages, JSON APIs and the agent endpoint.

Run with:  python main.py   then open  http://localhost:8000
"""
import os
import hmac
import json
import time
import secrets
import tempfile
import threading
from functools import wraps

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

from . import config, response
from .auth import ROLES, UserStore
from .database import HOSTNAME
from .engine import SentinelEngine
from .remote import Hub, build_report

MAX_REPORT = 8 * 1024 * 1024  # biggest agent report we accept


def _secret_key():
    """Random key that signs login cookies; created once and kept in data/."""
    os.makedirs(config.DATA_DIR, exist_ok=True)
    if not os.path.exists(config.SECRET_FILE):
        with open(config.SECRET_FILE, "wb") as f:
            f.write(secrets.token_bytes(32))
    with open(config.SECRET_FILE, "rb") as f:
        return f.read()


def create_app(engine=None, users=None):
    app = Flask(__name__)
    app.secret_key = _secret_key()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      MAX_CONTENT_LENGTH=MAX_REPORT)
    engine = engine or SentinelEngine()
    users = users or UserStore()
    hub = Hub(engine.db)
    app.extensions["sentinel"] = {"engine": engine, "hub": hub, "users": users}

    # ---------- local monitoring loop (this laptop is an endpoint too) ----------
    def local_loop():
        engine.start()
        while True:
            try:
                state = engine.scan()
                hub.update(build_report(state, []), "this laptop", local=True)
            except Exception as exc:  # never let the monitor thread die
                engine.db.add_event("SCAN_ERROR", severity="MEDIUM", details=str(exc))
            time.sleep(config.SCAN_INTERVAL_MS / 1000)

    app.extensions["sentinel"]["start_monitor"] = lambda: threading.Thread(
        target=local_loop, daemon=True).start()

    # ---------- login helpers ----------
    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("user") or not users.role(session["user"]):
                if request.path.startswith("/api/"):
                    return jsonify(error="login required"), 401
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapper

    def admin_required(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if users.role(session["user"]) != "admin":
                return jsonify(error="admin only"), 403
            return view(*args, **kwargs)
        return wrapper

    @app.before_request
    def csrf_protect():
        """Every form/API POST must carry the session's CSRF token."""
        if request.method == "POST" and request.endpoint not in ("agent_report", "login"):
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
            if not hmac.compare_digest(sent, session.get("csrf", "")):
                abort(400, "bad CSRF token")

    @app.context_processor
    def template_globals():
        user = session.get("user")
        return {"user": user, "role": users.role(user) if user else None,
                "csrf": session.get("csrf", ""), "hostname": HOSTNAME}

    # ---------- pages ----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            name = request.form.get("username", "").strip()
            if users.locked(name):
                error = f"Too many wrong attempts. Try again in {config.LOGIN_LOCK_SEC} seconds."
            elif users.check(name, request.form.get("password", "")):
                session.clear()
                session["user"] = name
                session["csrf"] = secrets.token_hex(16)
                engine.db.add_event("LOGIN_SUCCESS", details=f"user={name} ip={request.remote_addr}")
                nxt = request.args.get("next", "/")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
            else:
                error = "Wrong username or password."
                engine.db.add_event("LOGIN_FAILED", severity="MEDIUM",
                                    details=f"user={name} ip={request.remote_addr}")
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def overview():
        return render_template("overview.html", page="overview")

    @app.route("/endpoints")
    @login_required
    def endpoints():
        return render_template("endpoints.html", page="endpoints")

    @app.route("/endpoint/<host>")
    @login_required
    def endpoint(host):
        return render_template("endpoint.html", page="endpoints", host=host)

    @app.route("/alerts")
    @login_required
    def alerts():
        return render_template("alerts.html", page="alerts")

    @app.route("/activity")
    @login_required
    def activity():
        return render_template("activity.html", page="activity")

    @app.route("/users", methods=["GET", "POST"])
    @login_required
    def users_page():
        if users.role(session["user"]) != "admin":
            abort(403)
        message = None
        if request.method == "POST":
            action, name = request.form.get("action"), request.form.get("username", "")
            try:
                if action == "add":
                    users.add(name, request.form.get("password", ""), request.form.get("role"))
                    message = f"User '{name}' saved."
                elif action == "delete" and name != session["user"]:
                    users.delete(name)
                    message = f"User '{name}' deleted."
                engine.db.add_event("USER_" + str(action).upper(),
                                    details=f"{name} by {session['user']}")
            except ValueError as exc:
                message = f"Error: {exc}"
        return render_template("users.html", page="users", users=users.list(),
                               roles=ROLES, message=message)

    # ---------- JSON APIs (used by the pages every few seconds) ----------
    @app.route("/api/overview")
    @login_required
    def api_overview():
        eps = hub.summary()
        alerts = engine.db.recent_alerts(500)
        by_type, by_endpoint = {}, {}
        for a in alerts:
            by_type[a["alert_type"]] = by_type.get(a["alert_type"], 0) + 1
            by_endpoint[a["endpoint"]] = by_endpoint.get(a["endpoint"], 0) + 1
        risk = {lvl: 0 for lvl in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
        for e in eps:
            if e["online"]:
                for lvl, n in e["risk_counts"].items():
                    risk[lvl] += n
        return jsonify(endpoints=eps, recent_alerts=alerts[:8], alert_total=len(alerts),
                       new_alerts=sum(a["status"] == "NEW" for a in alerts),
                       by_type=by_type, by_endpoint=by_endpoint, risk=risk)

    @app.route("/api/endpoints")
    @login_required
    def api_endpoints():
        return jsonify(endpoints=hub.summary())

    @app.route("/api/endpoint/<host>")
    @login_required
    def api_endpoint(host):
        data = hub.detail(host)
        if not data:
            return jsonify(error="unknown endpoint"), 404
        return jsonify(data)

    @app.route("/api/alerts")
    @login_required
    def api_alerts():
        return jsonify(alerts=engine.db.recent_alerts(500))

    @app.route("/api/events")
    @login_required
    def api_events():
        return jsonify(events=engine.db.recent_events(500))

    @app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
    @admin_required
    def api_alert_status(alert_id):
        status = (request.get_json(silent=True) or {}).get("status", "")
        if status not in ("REVIEWED", "INVESTIGATED", "RESOLVED", "FALSE_POSITIVE"):
            return jsonify(error="bad status"), 400
        engine.db.set_alert_status(alert_id, status, f"by {session['user']}")
        return jsonify(ok=True)

    @app.route("/api/terminate", methods=["POST"])
    @admin_required
    def api_terminate():
        data = request.get_json(silent=True) or {}
        if data.get("host") != HOSTNAME:
            return jsonify(ok=False, message="Remote responses are disabled for safety. "
                                             "Respond on that laptop."), 400
        pid = int(data.get("pid", 0))
        ok, msg = response.terminate_process(pid)
        engine.db.add_event("RESPONSE_TERMINATE", data.get("name", ""), pid,
                            "INFO" if ok else "MEDIUM", f"{msg} (by {session['user']})")
        return jsonify(ok=ok, message=msg)

    @app.route("/api/investigate/<int:pid>")
    @login_required
    def api_investigate(pid):
        info = response.investigate(pid)
        return jsonify(info or {"error": "process has ended"})

    @app.route("/export/<table>.csv")
    @login_required
    def export(table):
        if table not in ("alerts", "events"):
            abort(404)
        path = os.path.join(tempfile.gettempdir(), f"sentinelos_{table}.csv")
        engine.db.export_csv(path, table)
        return send_file(path, as_attachment=True,
                         download_name=f"sentinelos_{table}_{time.strftime('%Y%m%d_%H%M')}.csv")

    # ---------- agents send their reports here ----------
    @app.route("/api/report", methods=["POST"], endpoint="agent_report")
    def agent_report():
        token = request.headers.get("X-Sentinel-Token", "")
        if not hmac.compare_digest(token, config.AGENT_TOKEN):
            return jsonify(error="bad token"), 403
        try:
            report = request.get_json(force=True)
            if report["hostname"] == HOSTNAME:
                return jsonify(error="agent has the same name as the server"), 400
            hub.update(report, request.remote_addr)
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify(error=f"invalid report: {exc}"), 400
        return jsonify(ok=True)

    return app


def run_server():
    from .setup import ensure_admin, lan_ip

    users = UserStore()
    ensure_admin(users)
    app = create_app(users=users)
    app.extensions["sentinel"]["start_monitor"]()
    ip = lan_ip()
    print("\n" + "=" * 60)
    print("  SentinelOS dashboard is running")
    print(f"  On this laptop:          http://localhost:{config.WEB_PORT}")
    print(f"  From other devices:      http://{ip}:{config.WEB_PORT}")
    print(f"  Agents connect with:     python main.py --agent {ip}")
    print("  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # quiet request logs
    app.run(host="0.0.0.0", port=config.WEB_PORT, threaded=True)
