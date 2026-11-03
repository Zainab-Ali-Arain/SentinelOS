"""Module 1: System Information - basic OS and machine details.

Besides the basics, this collects what the Overview page needs for its
Task-Manager-style view: CPU model/speed, memory split, disk and network
counters. Disk and network values are cumulative counters; the server turns
them into speeds (see remote.perf_rates) so agents stay simple.
"""
import platform
import socket
import sys
import time
import datetime
from functools import lru_cache

import psutil

DRIVE_REFRESH_SEC = 30          # drive capacity changes slowly, don't ask the OS every scan
_drives_cache = {"t": 0.0, "list": []}


@lru_cache(maxsize=1)
def _cpu_model():
    """Marketing name, e.g. 'Intel(R) Core(TM) i5-7300U CPU @ 2.60GHz'."""
    try:
        if sys.platform == "win32":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        if sys.platform.startswith("linux"):
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        if sys.platform == "darwin":
            import subprocess
            return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"],
                                           text=True, timeout=2).strip()
    except Exception:
        pass
    return platform.processor() or "Unknown processor"


@lru_cache(maxsize=1)
def _virtualization():
    """Is hardware virtualization (VT-x / AMD-V) available? Same check Task Manager uses."""
    try:
        if sys.platform == "win32":
            import ctypes
            # 21 = PF_VIRT_FIRMWARE_ENABLED
            return "Enabled" if ctypes.windll.kernel32.IsProcessorFeaturePresent(21) else "Disabled"
        if sys.platform.startswith("linux"):
            with open("/proc/cpuinfo") as f:
                text = f.read()
            return "Supported" if (" vmx" in text or " svm" in text) else "Not supported"
    except Exception:
        pass
    return "Unknown"


def _cpu_speed():
    """(current MHz, base MHz) or (None, None) if the OS does not say."""
    try:
        f = psutil.cpu_freq()
        if f:
            return round(f.current) or None, round(f.max) or None
    except Exception:
        pass
    return None, None


def _disk_io():
    """Cumulative disk counters (bytes and busy milliseconds), or None."""
    try:
        io = psutil.disk_io_counters()
    except Exception:
        return None
    if not io:
        return None
    busy = getattr(io, "busy_time", None)           # Linux
    if busy is None:
        busy = io.read_time + io.write_time          # Windows / macOS
    return {"read_bytes": io.read_bytes, "write_bytes": io.write_bytes, "busy_ms": busy}


def _drives():
    """Capacity of each drive, refreshed every DRIVE_REFRESH_SEC seconds."""
    now = time.time()
    if _drives_cache["list"] and now - _drives_cache["t"] < DRIVE_REFRESH_SEC:
        return _drives_cache["list"]
    drives = []
    try:
        for part in psutil.disk_partitions(all=False):
            if "cdrom" in part.opts or part.fstype in ("", "squashfs", "iso9660"):
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            drives.append({"mount": part.mountpoint.rstrip("\\") or part.mountpoint,
                           "total": usage.total, "used": usage.used})
    except Exception:
        pass
    _drives_cache.update(t=now, list=drives[:8])
    return _drives_cache["list"]


def _network():
    """Cumulative bytes per active network adapter (loopback is skipped)."""
    out = {}
    try:
        counters = psutil.net_io_counters(pernic=True)
        stats = psutil.net_if_stats()
    except Exception:
        return out
    for name, c in counters.items():
        st = stats.get(name)
        low = name.lower()
        if not st or not st.isup or low == "lo" or "loopback" in low:
            continue
        out[name] = {"sent": c.bytes_sent, "recv": c.bytes_recv, "speed": st.speed}
    return dict(list(out.items())[:8])


def get_system_info():
    """Return a dictionary with basic information about this computer."""
    boot = psutil.boot_time()
    memory = psutil.virtual_memory()
    try:
        swap = psutil.swap_memory()
        swap_total, swap_used = swap.total, swap.used
    except Exception:
        swap_total = swap_used = None
    mhz, base_mhz = _cpu_speed()
    now = time.time()
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_cores": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "ram_total_gb": round(memory.total / (1024 ** 3), 2),
        "ram_used_percent": memory.percent,
        "boot_time": datetime.datetime.fromtimestamp(boot).strftime("%Y-%m-%d %H:%M:%S"),
        "process_count": len(psutil.pids()),
        # ---- used by the Overview performance view ----
        "sampled_at": now,
        "uptime_sec": int(now - boot),
        "cpu_model": _cpu_model(),
        "cpu_physical": psutil.cpu_count(logical=False),
        "cpu_mhz": mhz,
        "cpu_base_mhz": base_mhz,
        "virtualization": _virtualization(),
        "ram_total": memory.total,
        "ram_used": memory.total - memory.available,
        "ram_available": memory.available,
        "ram_cached": getattr(memory, "cached", None),
        "swap_total": swap_total,
        "swap_used": swap_used,
        "disk_io": _disk_io(),
        "drives": _drives(),
        "net": _network(),
    }
