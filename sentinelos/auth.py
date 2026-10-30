"""Dashboard user accounts. Passwords are stored as salted hashes, never plain text."""
import os
import json
import time
import threading

from werkzeug.security import generate_password_hash, check_password_hash

from . import config

ROLES = ("admin", "viewer")  # viewer = can look, cannot respond
ALL_LAPTOPS = "*"            # a viewer linked to "*" may see every laptop (e.g. teacher)


class UserStore:
    def __init__(self, path=config.USERS_FILE):
        self.path = path
        self.lock = threading.Lock()
        self.failures = {}  # username -> (count, first_fail_time)
        try:
            with open(path) as f:
                self.users = json.load(f)
        except (OSError, ValueError):
            self.users = {}

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.users, f, indent=2)

    def add(self, username, password, role="viewer", endpoint=""):
        """Save a user. A viewer only sees the laptop named in `endpoint`."""
        username, endpoint = username.strip(), endpoint.strip()
        if not username or not password:
            raise ValueError("username and password are required")
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if len(password) < 6:
            raise ValueError("password must be at least 6 characters")
        if role == "viewer" and not endpoint:
            raise ValueError("choose which laptop this viewer may see")
        with self.lock:
            self.users[username] = {"hash": generate_password_hash(password), "role": role,
                                    "endpoint": endpoint if role == "viewer" else ""}
            self._save()

    def delete(self, username):
        with self.lock:
            self.users.pop(username, None)
            self._save()

    def role(self, username):
        user = self.users.get(username)
        return user["role"] if user else None

    def scope(self, username):
        """Laptop this user may see: None = every laptop, otherwise one hostname.
        A viewer from an older users.json (no laptop chosen yet) sees nothing."""
        user = self.users.get(username)
        if not user:
            return ""
        if user["role"] == "admin" or user.get("endpoint") == ALL_LAPTOPS:
            return None
        return user.get("endpoint", "")

    def list(self):
        return [{"username": u, "role": d["role"], "endpoint": d.get("endpoint", "")}
                for u, d in sorted(self.users.items())]

    def locked(self, username):
        count, since = self.failures.get(username, (0, 0))
        if count >= config.LOGIN_MAX_FAILS:
            if time.time() - since < config.LOGIN_LOCK_SEC:
                return True
            self.failures.pop(username, None)
        return False

    def check(self, username, password):
        """True if the password is right. Too many wrong tries = short lockout."""
        if self.locked(username):
            return False
        user = self.users.get(username)
        if user and check_password_hash(user["hash"], password):
            self.failures.pop(username, None)
            return True
        count, since = self.failures.get(username, (0, time.time()))
        self.failures[username] = (count + 1, since)
        return False
