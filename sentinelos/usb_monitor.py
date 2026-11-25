"""Module: USB / removable-media monitor with data-leak (exfiltration) watch.

Watches for removable drives (USB sticks, external disks, SD cards) being
plugged in or removed. The OS does not push an event to us, so we take a
snapshot of the removable drives on every scan and compare it with the last
one: a drive that appears is an insert, one that disappears is a removal.

While a drive is connected we also watch what is WRITTEN to it. On removal we
report how many files and how many bytes were copied onto it - a simple
data-leak / exfiltration check (MITRE T1052.001). We also record the drive's
size and the time it stayed connected.

Cross-platform: uses psutil.disk_partitions() + psutil.disk_usage(), so it
works on Windows, Linux and macOS. The write-watch uses watchdog (already a
dependency).
"""
import os
import time
import threading

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from . import config


def _removable_drives():
    """Return {device: mountpoint} for every removable drive right now."""
    drives = {}
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception:
        return drives
    for p in parts:
        opts = (p.opts or "").lower()
        mount = p.mountpoint or ""
        is_removable = (
            "removable" in opts                       # Windows marks USB this way
            or "cdrom" in opts
            or mount.startswith("/media/")            # Linux auto-mount
            or mount.startswith("/run/media/")
            or mount.startswith("/Volumes/")          # macOS
        )
        if mount in ("/", "/System/Volumes/Data"):    # never the boot disk
            is_removable = False
        if is_removable:
            drives[p.device] = mount
    return drives


def _disk_size(mount):
    """(total, used, free) in bytes for a mountpoint, or zeros if unreadable."""
    try:
        u = psutil.disk_usage(mount)
        return u.total, u.used, u.free
    except Exception:
        return 0, 0, 0


class _WriteHandler(FileSystemEventHandler):
    """Records files written to the USB drive (path -> {size, time})."""

    def __init__(self, sink):
        self.sink = sink

    def _note(self, path):
        if path and not os.path.isdir(path):
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            self.sink(path, size)

    def on_created(self, event):
        if not event.is_directory:
            self._note(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._note(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._note(getattr(event, "dest_path", "") or event.src_path)


class _Drive:
    """One connected removable drive and the files copied onto it."""

    def __init__(self, device, mount):
        self.device = device
        self.mount = mount
        self.inserted_at = time.time()
        self.total, self.used, self.free = _disk_size(mount)
        self.writes = {}                 # path -> {"size", "time"}
        self.reported = set()            # paths already announced as "copied"
        self.lock = threading.Lock()
        self.observer = None
        if config.USB_WATCH_WRITES:
            self._start_watch()

    def _sink(self, path, size):
        with self.lock:
            self.writes[path] = {"size": size, "time": time.time()}

    def _start_watch(self):
        try:
            self.observer = Observer()
            self.observer.schedule(_WriteHandler(self._sink), self.mount, recursive=True)
            self.observer.daemon = True
            self.observer.start()
        except Exception:
            self.observer = None          # watching failed; insert/remove still work

    def close(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass

    def new_writes(self):
        """Files copied onto the USB that haven't been announced yet."""
        with self.lock:
            fresh = [{"path": p, "size": w["size"]} for p, w in self.writes.items()
                     if p not in self.reported]
            self.reported.update(self.writes.keys())
        return fresh

    def used_now_mb(self):
        _total, used, _free = _disk_size(self.mount)
        return round(used / 1048576, 1)

    def leak_report(self):
        with self.lock:
            files = [{"path": p, "size": w["size"]} for p, w in self.writes.items()]
        total_bytes = sum(f["size"] for f in files)
        return {
            "device": self.device,
            "mount": self.mount,
            "inserted_at": self.inserted_at,
            "removed_at": time.time(),
            "duration_sec": round(time.time() - self.inserted_at, 1),
            "total_mb": round(self.total / 1048576, 1),
            "used_at_insert_mb": round(self.used / 1048576, 1),
            "files": files,
            "file_count": len(files),
            "bytes": total_bytes,
            "mb": round(total_bytes / 1048576, 2),
        }


class UsbMonitor:
    """Tracks removable drives, their size/timing, and data written to them."""

    def __init__(self):
        self.drives = {}                 # device -> _Drive
        for dev, mount in _removable_drives().items():
            self.drives[dev] = _Drive(dev, mount)

    def poll(self):
        """Return (inserted, removed).

        inserted: [{device, mount, total_mb, used_mb, free_mb, time}]
        removed:  [leak_report dict]  (see _Drive.leak_report)
        """
        now = _removable_drives()
        inserted, removed = [], []

        for dev, mount in now.items():
            if dev not in self.drives:
                drive = _Drive(dev, mount)
                self.drives[dev] = drive
                inserted.append({
                    "device": dev, "mount": mount,
                    "total_mb": round(drive.total / 1048576, 1),
                    "used_mb": round(drive.used / 1048576, 1),
                    "free_mb": round(drive.free / 1048576, 1),
                    "time": time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(drive.inserted_at)),
                })

        for dev in list(self.drives):
            if dev not in now:
                drive = self.drives.pop(dev)
                report = drive.leak_report()
                drive.close()
                removed.append(report)

        return inserted, removed

    def live_activity(self):
        """Files copied to any connected USB since the last check (live).

        Each entry: device, mount, used_at_insert_mb, used_now_mb, new_files, bytes.
        """
        out = []
        for dev, drive in self.drives.items():
            fresh = drive.new_writes()
            if fresh:
                out.append({
                    "device": dev, "mount": drive.mount,
                    "used_at_insert_mb": round(drive.used / 1048576, 1),
                    "used_now_mb": drive.used_now_mb(),
                    "new_files": fresh,
                    "bytes": sum(f["size"] for f in fresh),
                })
        return out

    def close(self):
        for drive in self.drives.values():
            drive.close()
