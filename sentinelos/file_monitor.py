"""Module 3: File Monitor - watches a directory and checks file integrity."""
import os
import time
import hashlib
import threading
from collections import deque

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from . import config


def sha256_of(path):
    """Return the SHA-256 hash of a file (read in chunks to save memory)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_any_event(self, event):
        if event.is_directory or event.event_type in ("opened", "closed", "closed_no_write"):
            return
        self.monitor._record(event.event_type, event.src_path,
                             getattr(event, "dest_path", ""))


class FileMonitor:
    """Runs watchdog in a background thread and keeps recent file events."""

    def __init__(self, watch_dir=config.WATCH_DIR):
        self.watch_dir = watch_dir
        os.makedirs(watch_dir, exist_ok=True)
        self.events = deque(maxlen=2000)   # recent events (thread-safe append)
        self.new_events = []               # events not yet saved to DB
        self.lock = threading.Lock()
        self.baseline = {}                 # path -> sha256 (integrity baseline)
        self.protected = {}                # real system files -> {mtime,size,sha}
        self.observer = None

    def start(self):
        self.build_baseline()
        if config.PROTECT_SYSTEM_FILES:
            self.build_protected_baseline()
        self.observer = Observer()
        self.observer.schedule(_Handler(self), self.watch_dir, recursive=True)
        self.observer.daemon = True
        self.observer.start()

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)

    def _record(self, event_type, path, dest=""):
        event = {"time": time.time(), "type": event_type.upper(),
                 "path": path, "dest": dest}
        with self.lock:
            self.events.append(event)
            self.new_events.append(event)

    def take_new_events(self):
        """Return events since the last call (for logging)."""
        with self.lock:
            out, self.new_events = self.new_events, []
        return out

    def recent_count(self, seconds=config.FILE_BURST_WINDOW_SEC):
        """How many file changes happened in the last `seconds`."""
        cutoff = time.time() - seconds
        with self.lock:
            return sum(1 for e in self.events if e["time"] >= cutoff)

    def is_burst(self):
        return self.recent_count() >= config.FILE_BURST_COUNT

    def recent_created_count(self, seconds=config.FILE_CREATE_WINDOW_SEC):
        """How many NEW files were created in the last `seconds`.

        A virus that duplicates itself or encrypts files into copies shows up
        as many CREATED events in a short time, separate from edits/deletes.
        """
        cutoff = time.time() - seconds
        with self.lock:
            return sum(1 for e in self.events
                       if e["time"] >= cutoff and e["type"] == "CREATED")

    def is_duplication(self):
        return self.recent_created_count() >= config.FILE_CREATE_COUNT

    # ---- File integrity monitoring (FIM) ----
    def build_baseline(self):
        """Hash every file currently in the watch dir. These are 'protected'."""
        self.baseline = {}
        for root, _dirs, files in os.walk(self.watch_dir):
            for name in files:
                path = os.path.join(root, name)
                digest = sha256_of(path)
                if digest:
                    self.baseline[path] = digest

    def check_integrity(self):
        """Compare protected files with the baseline.
        Returns a list of (path, status) where status is MODIFIED or DELETED."""
        changes = []
        for path, old in list(self.baseline.items()):
            if not os.path.exists(path):
                changes.append((path, "DELETED"))
                del self.baseline[path]
            else:
                new = sha256_of(path)
                if new and new != old:
                    changes.append((path, "MODIFIED"))
                    self.baseline[path] = new  # report each change once
        return changes

    def file_count(self):
        return sum(len(files) for _r, _d, files in os.walk(self.watch_dir))

    # ---- Real system-protected files (read-only integrity monitoring) ----
    @staticmethod
    def _file_meta(path):
        """(mtime, size, sha256) for a file, or None if it can't be read."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        sha = sha256_of(path)
        if sha is None:
            return None  # e.g. no permission (SAM/shadow) - skip, don't crash
        return {"mtime": st.st_mtime, "size": st.st_size, "sha": sha}

    def build_protected_baseline(self):
        """Hash the OS's protected files once. We only read them, never change."""
        self.protected = {}
        targets = list(config.PROTECTED_FILES)
        for d in config.PROTECTED_DIRS:
            if os.path.isdir(d):
                for root, _dirs, files in os.walk(d):
                    targets.extend(os.path.join(root, n) for n in files)
        for path in targets:
            meta = self._file_meta(path)
            if meta:
                self.protected[path] = meta

    def check_protected(self):
        """Re-check protected files. Returns [(path, MODIFIED|DELETED)].

        Cheap: only re-hashes a file when its mtime or size changed, so big
        system files are not hashed on every scan.
        """
        changes = []
        for path, old in list(self.protected.items()):
            try:
                st = os.stat(path)
            except OSError:
                changes.append((path, "DELETED"))
                del self.protected[path]
                continue
            if st.st_mtime == old["mtime"] and st.st_size == old["size"]:
                continue  # unchanged - skip hashing
            sha = sha256_of(path)
            if sha and sha != old["sha"]:
                changes.append((path, "MODIFIED"))
            self.protected[path] = {"mtime": st.st_mtime, "size": st.st_size,
                                    "sha": sha or old["sha"]}
        return changes

    def protected_count(self):
        return len(self.protected)
