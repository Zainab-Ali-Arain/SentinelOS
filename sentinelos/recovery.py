"""Module: Self-healing recovery + lockdown.

Two defensive responses that run LOCALLY on the agent (never driven remotely,
so there is no remote-command security hole):

1. Recovery  - when a protected file is modified or deleted, restore it from a
   known-good backup that was taken when the baseline was built.
2. Lockdown  - set OS-level permissions so a protected file cannot be modified
   or deleted at all (needs admin on Windows / root on Linux). Reversible.

Only operates on the project's own protected set (test_zone + the configured
protected files). Everything is reversible.
"""
import os
import json
import shutil
import hashlib
import subprocess

from . import config


def _key(path):
    """A stable filename for a backup, derived from the original absolute path."""
    return hashlib.sha256(os.path.abspath(path).encode()).hexdigest()[:16]


class Backup:
    """Keeps known-good copies of protected files so they can be restored."""

    def __init__(self, backup_dir=None):
        self.dir = backup_dir or config.BACKUP_DIR
        os.makedirs(self.dir, exist_ok=True)
        self.index_path = os.path.join(self.dir, "index.json")
        self.index = {}  # key -> original absolute path
        if os.path.exists(self.index_path):
            try:
                with open(self.index_path) as f:
                    self.index = json.load(f)
            except (OSError, ValueError):
                self.index = {}

    def save(self, path):
        """Store a known-good copy of a file (called when baseline is built)."""
        if not os.path.isfile(path):
            return False
        try:
            shutil.copy2(path, os.path.join(self.dir, _key(path)))
            self.index[_key(path)] = os.path.abspath(path)
            self._flush()
            return True
        except OSError:
            return False  # e.g. no permission - skip, don't crash

    def restore(self, path):
        """Put the known-good copy back (recover a tampered/deleted file)."""
        src = os.path.join(self.dir, _key(path))
        if not os.path.exists(src):
            return False
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.copy2(src, path)
            return True
        except OSError:
            return False

    def _flush(self):
        try:
            with open(self.index_path, "w") as f:
                json.dump(self.index, f, indent=2)
        except OSError:
            pass


# ------------------------- OS-level lockdown -------------------------
def lock_path(path):
    """Block modify/delete on a file at the OS level. Returns (ok, message).

    Windows: deny Everyone write/append/delete via icacls (needs admin).
    Linux/macOS: set the immutable flag (needs root); else fall back to
    read-only permission bits.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return False, "not found"
    try:
        if os.name == "nt":
            # *S-1-1-0 = the Everyone group; WD=write-data AD=append DE=delete
            r = subprocess.run(["icacls", path, "/deny", "*S-1-1-0:(WD,AD,DE)"],
                               capture_output=True, text=True)
            return r.returncode == 0, (r.stdout or r.stderr).strip().splitlines()[-1:]
        r = subprocess.run(["chattr", "+i", path], capture_output=True, text=True)
        if r.returncode == 0:
            return True, "immutable"
        os.chmod(path, 0o444)
        return True, "read-only"
    except Exception as exc:  # noqa: BLE001 - report any OS error, don't crash
        return False, str(exc)


def unlock_path(path):
    """Reverse lock_path so the file can be changed again."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return False, "not found"
    try:
        if os.name == "nt":
            r = subprocess.run(["icacls", path, "/remove:d", "*S-1-1-0"],
                               capture_output=True, text=True)
            return r.returncode == 0, (r.stdout or r.stderr).strip().splitlines()[-1:]
        r = subprocess.run(["chattr", "-i", path], capture_output=True, text=True)
        if r.returncode == 0:
            return True, "mutable"
        os.chmod(path, 0o644)
        return True, "writable"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def protected_targets():
    """Every file the project protects: the watch folder + configured files."""
    targets = []
    if os.path.isdir(config.WATCH_DIR):
        for root, _d, files in os.walk(config.WATCH_DIR):
            targets.extend(os.path.join(root, n) for n in files)
    targets.extend(p for p in config.PROTECTED_FILES if os.path.isfile(p))
    for d in config.PROTECTED_DIRS:
        if os.path.isdir(d):
            for root, _d, files in os.walk(d):
                targets.extend(os.path.join(root, n) for n in files)
    return targets


def lock_all():
    """Lock every protected file. Returns (locked_count, failures)."""
    locked, failed = 0, []
    for path in protected_targets():
        ok, msg = lock_path(path)
        if ok:
            locked += 1
        else:
            failed.append((path, msg))
    return locked, failed


def unlock_all():
    unlocked, failed = 0, []
    for path in protected_targets():
        ok, msg = unlock_path(path)
        if ok:
            unlocked += 1
        else:
            failed.append((path, msg))
    return unlocked, failed
