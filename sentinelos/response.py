"""Module 8: Response - safe, user-confirmed actions.

Nothing here runs automatically. The dashboard asks the user first.
"""
import os
import shutil

import psutil

from . import config


def investigate(pid):
    """Return detailed information about a process (or None if it ended)."""
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = {
                "PID": p.pid, "Name": p.name(), "Parent PID": p.ppid(),
                "Status": p.status(), "Threads": p.num_threads(),
                "Memory (MB)": round(p.memory_info().rss / 1024 ** 2, 1),
            }
        for label, func in [("Path", p.exe), ("Command", p.cmdline),
                            ("User", p.username), ("Open files", p.open_files),
                            ("Connections", p.net_connections)]:
            try:
                value = func()
                if label == "Command":
                    value = " ".join(value)
                elif label == "Open files":
                    value = [f.path for f in value][:10]
                elif label == "Connections":
                    value = [f"{c.raddr.ip}:{c.raddr.port}" for c in value if c.raddr][:10]
                info[label] = value
            except (psutil.AccessDenied, OSError):
                info[label] = "access denied"
        return info
    except psutil.NoSuchProcess:
        return None


def terminate_process(pid):
    """Stop a process: polite terminate first, force kill if it ignores us."""
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
        return True, f"Terminated {name} (PID {pid})"
    except psutil.NoSuchProcess:
        return False, "Process already ended"
    except psutil.AccessDenied:
        return False, "Access denied - run the EDR as administrator"


def quarantine_file(path):
    """Move a file into the quarantine folder.
    Only files inside the monitored test folder are allowed (safety rule)."""
    path = os.path.abspath(path)
    if not path.startswith(os.path.abspath(config.WATCH_DIR) + os.sep):
        return False, "Only files inside the test folder can be quarantined"
    if not os.path.isfile(path):
        return False, "File not found"
    os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
    target = os.path.join(config.QUARANTINE_DIR, os.path.basename(path) + ".quarantined")
    shutil.move(path, target)
    return True, f"Moved to {target}"
