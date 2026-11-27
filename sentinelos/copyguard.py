"""Module: Copy-Guard - stop protected files being copied to local folders.

USB copying is handled in the USB monitor. This watches a few common local
destinations (Desktop, Documents, Downloads by default) so that a protected
file copied/pasted there is detected by its hash and removed, with an alert.

HONEST LIMIT: this detects-and-removes copies in the WATCHED folders only. It
cannot stop email attachments, cloud-sync uploads, screenshots, or copies to
folders that are not watched. True copy-prevention needs a kernel file-system
minifilter driver, which is out of scope for a Python project.
"""
import os
import threading

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from . import config


class _Handler(FileSystemEventHandler):
    def __init__(self, sink):
        self.sink = sink

    def _note(self, path):
        if path and not os.path.isdir(path):
            self.sink(path)

    def on_created(self, event):
        if not event.is_directory:
            self._note(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._note(getattr(event, "dest_path", "") or event.src_path)


class CopyGuard:
    """Watches destination folders and reports newly-arrived files."""

    def __init__(self, dirs=None):
        self.dirs = [d for d in (dirs or config.COPY_GUARD_DIRS) if os.path.isdir(d)]
        self.seen = {}           # path -> True (not yet reported)
        self.lock = threading.Lock()
        self.observers = []

    def start(self):
        for d in self.dirs:
            try:
                obs = Observer()
                obs.schedule(_Handler(self._sink), d, recursive=True)
                obs.daemon = True
                obs.start()
                self.observers.append(obs)
            except Exception:
                pass  # a folder we cannot watch is skipped, never fatal

    def _sink(self, path):
        with self.lock:
            self.seen[path] = True

    def new_writes(self):
        """Paths that appeared since the last call (then cleared)."""
        with self.lock:
            paths = list(self.seen.keys())
            self.seen.clear()
        return paths

    def stop(self):
        for obs in self.observers:
            try:
                obs.stop()
                obs.join(timeout=2)
            except Exception:
                pass
