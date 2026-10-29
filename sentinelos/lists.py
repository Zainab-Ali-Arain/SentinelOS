"""IoC blocklist and user whitelist (trusted programs), both stored as JSON."""
import os
import json
import hashlib

from . import config

_hash_cache = {}  # (path, size, mtime) -> sha256, so each exe is hashed once


def exe_hash(path):
    """SHA-256 of an executable, cached until the file changes."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (path, st.st_size, st.st_mtime)
    if key not in _hash_cache:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            _hash_cache[key] = h.hexdigest()
        except OSError:
            _hash_cache[key] = ""
    return _hash_cache[key]


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


class IocList:
    """Known-bad hashes, process names and IPs (Indicators of Compromise)."""

    def __init__(self, path=config.IOC_FILE):
        data = _load(path, {})
        self.hashes = {h.lower() for h in data.get("hashes", [])}
        self.names = {n.lower() for n in data.get("names", [])}
        self.ips = set(data.get("ips", []))

    def match_process(self, proc):
        """Return a reason string if the process matches an IoC, else ''."""
        if proc["name"].lower() in self.names:
            return f"name {proc['name']}"
        if self.hashes and proc["path"]:
            digest = exe_hash(proc["path"])
            if digest in self.hashes:
                return f"hash {digest[:12]}..."
        return ""


class TrustedList:
    """Programs the user marked as safe (to remove false positives)."""

    def __init__(self, path=config.TRUSTED_FILE):
        self.path = path
        self.items = set(_load(path, []))

    @staticmethod
    def key(proc):
        return (proc.get("path") or proc["name"]).lower()

    def is_trusted(self, proc):
        return self.key(proc) in self.items

    def add(self, proc):
        self.items.add(self.key(proc))
        self._save()

    def remove(self, key):
        self.items.discard(key)
        self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(sorted(self.items), f, indent=2)
