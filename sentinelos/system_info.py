"""Module 1: System Information - basic OS and machine details."""
import platform
import socket
import datetime

import psutil


def get_system_info():
    """Return a dictionary with basic information about this computer."""
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    memory = psutil.virtual_memory()
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_cores": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "ram_total_gb": round(memory.total / (1024 ** 3), 2),
        "ram_used_percent": memory.percent,
        "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        "process_count": len(psutil.pids()),
    }
