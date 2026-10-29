"""Module 4: Network Monitor - active connections and their processes."""
import psutil

from . import config


def get_connections():
    """Return a list of active TCP/UDP connections with the owning process.

    On some systems (macOS, or protected processes on Windows) the OS
    only shows this information to an administrator.
    """
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return []

    names = {}
    results = []
    for c in conns:
        if not c.raddr:
            continue  # only connections that talk to a remote address
        pid = c.pid or 0
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name() if pid else "?"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                names[pid] = "?"
        results.append({
            "pid": pid,
            "process": names[pid],
            "local": f"{c.laddr.ip}:{c.laddr.port}",
            "remote_ip": c.raddr.ip,
            "remote_port": c.raddr.port,
            "status": c.status,
            "suspicious": c.raddr.port in config.SUSPICIOUS_PORTS,
        })
    return results
