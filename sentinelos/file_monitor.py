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
        self.observer = None

    def start(self):
        self.build_baseline()
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
