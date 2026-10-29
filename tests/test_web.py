"""Tests for dashboard login and API security (run: python -m unittest)."""
import os
import json
import tempfile
import unittest

from sentinelos import config
from sentinelos.auth import UserStore
from sentinelos.webapp import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.users = UserStore(os.path.join(self.tmp, "users.json"))
        self.users.add("admin", "admin123", "admin")
        self.users.add("teacher", "teach123", "viewer")
        self.app = create_app(users=self.users)
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
