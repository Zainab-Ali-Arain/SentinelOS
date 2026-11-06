"""Module 2: Process Monitor - collects information about running processes."""
import os
import time
import datetime

import psutil

from .app_names import app_name, is_system


class ProcessMonitor:
    """Collects process data. Remembers the previous scan so it can tell how
    much each process wrote to disk since then (used for file-burst blame)."""

    def __init__(self):
        self.prev_writes = {}  # pid -> write_count at last scan
        self.prev_names = None  # pid -> (name, app) at last scan (None = first scan)
        self.started, self.stopped = [], []  # process timeline since last scan
        self.own_pid = os.getpid()

    def scan(self, sample_seconds=1.0):
        """Return a list of dictionaries, one per running process.

        CPU usage is measured over `sample_seconds`: psutil needs two
        readings, so we take a first reading, wait, then take the real one.
        """
        procs = list(psutil.process_iter())
        for p in procs:
            try:
                p.cpu_percent(None)  # first reading (always returns 0.0)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        time.sleep(sample_seconds)

        results, writes = [], {}
        for p in procs:
            if p.pid == self.own_pid:
                continue  # don't monitor the EDR itself
            try:
                with p.oneshot():  # read all fields in one batch
                    info = {
                        "pid": p.pid,
                        "ppid": p.ppid(),
                        "name": p.name(),
                        "cpu_percent": round(p.cpu_percent(None), 1),
                        "memory_mb": round(p.memory_info().rss / (1024 ** 2), 1),
                        "threads": p.num_threads(),
                        "start_time": datetime.datetime.fromtimestamp(
                            p.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                        "path": _safe(p.exe, ""),
                        "cmdline": " ".join(_safe(p.cmdline, [])),
                        "username": _safe(p.username, ""),
                    }
                    io = _safe(p.io_counters, None)
                    count = io.write_count if io else 0
                    writes[p.pid] = count
                    info["writes_delta"] = max(0, count - self.prev_writes.get(p.pid, count))
                results.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue  # process ended or is protected - skip it
        self.prev_writes = writes

        # Parent name: lets us spot e.g. Word starting PowerShell
        names = {p["pid"]: p["name"] for p in results}
        for info in results:
            info["parent_name"] = names.get(info["ppid"], "")
            info["app"] = app_name(info["name"], info["path"])   # e.g. "Microsoft Word"
            info["system"] = is_system(info)                    # background OS process?

        # Timeline: compare this scan's PIDs with the previous scan
        if self.prev_names is None:
            self.started, self.stopped = [], []
        else:
            self.started = [p for p in results if p["pid"] not in self.prev_names]
            self.stopped = [{"pid": pid, "name": name, "app": app}
                            for pid, (name, app) in self.prev_names.items() if pid not in names]
        self.prev_names = {p["pid"]: (p["name"], p["app"]) for p in results}
        return results


def _safe(func, default):
    """Call a psutil method; return `default` if the OS refuses access."""
    try:
        return func()
    except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess,
            AttributeError, NotImplementedError, OSError):
        return default


def top_processes(processes, key="cpu_percent", limit=10):
    """Return the `limit` processes with the highest value for `key`."""
    return sorted(processes, key=lambda p: p[key], reverse=True)[:limit]
