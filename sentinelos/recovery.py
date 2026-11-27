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
import time
import json
import shutil
import hashlib
import subprocess

from . import config


def _key(path):
    """A stable filename for a backup, derived from the original absolute path."""
    return hashlib.sha256(os.path.abspath(path).encode()).hexdigest()[:16]


def _sha(path):
    """SHA-256 of a file (streamed, so large files don't blow up memory)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Backup:
    """Versioned known-good copies of protected files so they can be restored.

    Each protected file keeps a short history of versions (v1, v2, ...). A new
    version is stored only when the content actually changes (deduped by hash),
    which also prevents backup loops when recovery rewrites a file.
    index: key -> {"path": abspath, "versions": [{"file","sha","time"}, ...]}
    """

    def __init__(self, backup_dir=None):
        self.dir = backup_dir or config.BACKUP_DIR
        os.makedirs(self.dir, exist_ok=True)
        self.index_path = os.path.join(self.dir, "index.json")
        self.index = {}
        self._load()

    def _load(self):
        raw = {}
        if os.path.exists(self.index_path):
            try:
                with open(self.index_path) as f:
                    raw = json.load(f)
            except (OSError, ValueError):
                raw = {}
        for k, v in raw.items():
            if isinstance(v, str):  # migrate old single-copy format
                entry = {"path": v, "versions": []}
                legacy = os.path.join(self.dir, k)
                if os.path.exists(legacy):
                    try:
                        entry["versions"].append(
                            {"file": k, "sha": _sha(legacy),
                             "time": os.path.getmtime(legacy)})
                    except OSError:
                        pass
                self.index[k] = entry
            else:
                self.index[k] = v

    def save(self, path):
        """Store the current content as a new version (deduped by hash)."""
        if not os.path.isfile(path):
            return False
        key = _key(path)
        try:
            sha = _sha(path)
        except OSError:
            return False
        entry = self.index.setdefault(key, {"path": os.path.abspath(path), "versions": []})
        entry["path"] = os.path.abspath(path)
        versions = entry["versions"]
        if versions and versions[-1].get("sha") == sha:
            return True  # unchanged - no new version (prevents loops/duplicates)
        vfile = f"{key}__v{len(versions) + 1}_{int(time.time())}"
        dest = os.path.join(self.dir, vfile)
        try:
            shutil.copy2(path, dest)
        except OSError:
            return False
        if getattr(config, "PROTECT_BACKUPS", False):
            lock_path(dest)  # make this backup copy write/delete-proof
        versions.append({"file": vfile, "sha": sha, "time": time.time()})
        max_v = getattr(config, "MAX_VERSIONS", 10)
        while len(versions) > max_v:  # keep only the most recent N versions
            old = versions.pop(0)
            oldfile = os.path.join(self.dir, old["file"])
            if getattr(config, "PROTECT_BACKUPS", False):
                unlock_path(oldfile)  # must unlock before we can remove it
            try:
                os.remove(oldfile)
            except OSError:
                pass
        self._flush()
        return True

    def protect_existing(self):
        """Lock every stored backup version (called at startup). Returns count."""
        if not getattr(config, "PROTECT_BACKUPS", False):
            return 0
        n = 0
        for entry in self.index.values():
            for v in entry.get("versions", []):
                f = os.path.join(self.dir, v["file"])
                if os.path.exists(f):
                    ok, _ = lock_path(f)
                    n += 1 if ok else 0
        return n

    def restore(self, path, version=None):
        """Restore the latest version (default) or a specific 1-based version."""
        entry = self.index.get(_key(path))
        if not entry or not entry.get("versions"):
            legacy = os.path.join(self.dir, _key(path))  # pre-versioning fallback
            return self._copy_back(legacy, path) if os.path.exists(legacy) else False
        versions = entry["versions"]
        if version is None:
            chosen = versions[-1]
        else:
            if version < 1 or version > len(versions):
                return False
            chosen = versions[version - 1]
        return self._copy_back(os.path.join(self.dir, chosen["file"]), path)

    def list_versions(self, path):
        entry = self.index.get(_key(path))
        if not entry:
            return []
        return [{"n": i + 1, "time": v["time"], "sha": v["sha"][:12]}
                for i, v in enumerate(entry["versions"])]

    def tracked(self):
        """[(original_path, version_count)] for everything backed up."""
        return [(e["path"], len(e.get("versions", []))) for e in self.index.values()]

    def _copy_back(self, src, path):
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


def set_usb_write_protect(enable):
    """Strict mode: block ALL writes to removable drives (Windows, needs admin).

    Sets the StorageDevicePolicies\\WriteProtect registry value. Reversible.
    Returns (ok, message). No-op with a message on non-Windows.
    """
    if os.name != "nt":
        return False, "USB write-protect is only available on Windows"
    key = r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
    try:
        r = subprocess.run(["reg", "add", key, "/v", "WriteProtect", "/t", "REG_DWORD",
                            "/d", "1" if enable else "0", "/f"],
                           capture_output=True, text=True)
        ok = r.returncode == 0
        return ok, ("write-protect " + ("ON" if enable else "OFF")) if ok else r.stderr.strip()
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
