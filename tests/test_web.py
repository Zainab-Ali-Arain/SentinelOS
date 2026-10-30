"""Tests for dashboard login and API security (run: python -m unittest)."""
import os
import json
import time
import tempfile
import unittest

from sentinelos import config
from sentinelos.auth import UserStore
from sentinelos.database import Database
from sentinelos.engine import SentinelEngine
from sentinelos.webapp import create_app


def fake_report(host):
    return {"hostname": host, "system": {"cpu_percent": 5, "ram_used_percent": 40},
            "threat_level": "LOW", "risk_counts": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "monitored_files": 0, "processes": [], "connections": [], "file_events": [], "alerts": []}


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.users = UserStore(os.path.join(self.tmp, "users.json"))
        self.users.add("admin", "admin123", "admin")
        self.users.add("teacher", "teach123", "viewer", "*")
        self.users.add("ali", "ali12345", "viewer", "Ali-Laptop")
        engine = SentinelEngine()
        engine.db = Database(os.path.join(self.tmp, "test.db"))  # keep tests out of data/
        self.app = create_app(engine=engine, users=self.users)
        self.db = engine.db
        hub = self.app.extensions["sentinel"]["hub"]
        for host in ("Ali-Laptop", "Sara-Laptop"):
            hub.update(fake_report(host), "10.0.0.9")
            self.db.add_alert("FILE_INTEGRITY", "x", 0, 40, "HIGH", ["test"], endpoint=host)
        self.client = self.app.test_client()

    def login(self, user, pw):
        return self.client.post("/login", data={"username": user, "password": pw})

    def csrf(self):
        with self.client.session_transaction() as s:
            return s.get("csrf", "")

    def test_pages_need_login(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.get("/api/overview").status_code, 401)

    def test_login_and_logout(self):
        self.assertEqual(self.login("admin", "admin123").status_code, 302)
        self.assertEqual(self.client.get("/api/overview").status_code, 200)
        self.client.get("/logout")
        self.assertEqual(self.client.get("/api/overview").status_code, 401)

    def test_wrong_password_and_lockout(self):
        for _ in range(config.LOGIN_MAX_FAILS):
            self.assertIn(b"Wrong username or password", self.login("admin", "nope").data)
        # even the right password is refused while locked
        self.assertIn(b"Too many wrong attempts", self.login("admin", "admin123").data)

    def test_passwords_are_hashed(self):
        with open(self.users.path) as f:
            self.assertNotIn("admin123", f.read())

    def test_viewer_cannot_respond(self):
        self.login("teacher", "teach123")
        r = self.client.post("/api/terminate", json={"host": "x", "pid": 1},
                             headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.get("/users").status_code, 403)

    def test_viewer_sees_only_own_laptop(self):
        self.login("ali", "ali12345")
        hosts = [e["hostname"] for e in self.client.get("/api/endpoints").get_json()["endpoints"]]
        self.assertEqual(hosts, ["Ali-Laptop"])
        alerts = self.client.get("/api/alerts").get_json()["alerts"]
        self.assertEqual({a["endpoint"] for a in alerts}, {"Ali-Laptop"})
        events = self.client.get("/api/events").get_json()["events"]
        self.assertEqual({e["endpoint"] for e in events}, {"Ali-Laptop"})
        self.assertEqual(self.client.get("/api/endpoint/Sara-Laptop").status_code, 404)
        self.assertEqual(self.client.get("/endpoint/Sara-Laptop").status_code, 403)
        self.assertNotIn(b"Sara-Laptop", self.client.get("/export/alerts.csv").data)

    def test_admin_and_all_laptops_viewer_see_everything(self):
        for user, pw in (("admin", "admin123"), ("teacher", "teach123")):
            self.login(user, pw)
            hosts = {e["hostname"] for e in self.client.get("/api/endpoints").get_json()["endpoints"]}
            self.assertTrue({"Ali-Laptop", "Sara-Laptop"} <= hosts)
            self.client.get("/logout")

    def test_viewer_needs_a_laptop(self):
        with self.assertRaises(ValueError):
            self.users.add("nolaptop", "secret12", "viewer")

    def test_old_events_are_cleaned_up(self):
        self.db._write("INSERT INTO events (timestamp, event_type, endpoint) VALUES (?, ?, ?)",
                       ("2000-01-01 00:00:00", "OLD_EVENT", "x"))
        self.assertEqual(self.db.cleanup(), 1)
        self.assertFalse(self.db.recent_events(search="OLD_EVENT"))
        self.assertTrue(self.db.recent_alerts())  # alerts are kept

    def test_post_without_csrf_token_is_rejected(self):
        self.login("admin", "admin123")
        r = self.client.post("/api/alerts/1/status", json={"status": "REVIEWED"})
        self.assertEqual(r.status_code, 400)

    def test_agent_needs_token(self):
        report = {"hostname": "Test-Laptop"}
        r = self.client.post("/api/report", data=json.dumps(report),
                             headers={"X-Sentinel-Token": "wrong"})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
