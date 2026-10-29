"""Modules 5 & 6: Detection Engine and Risk Engine.

Each rule looks at one behaviour and adds points. A process is only
considered dangerous when several indicators add up - one high-CPU
program on its own stays LOW, which keeps false positives down.
"""
import os

from . import config


def risk_level(score):
    for limit, level in config.RISK_LEVELS:
        if score <= limit:
            return level
    return "CRITICAL"


def _is_unknown(proc):
    path = proc["path"].lower()
    if proc["name"].lower() in config.KNOWN_PROCESS_NAMES:
        return False
    if not path:
        return True  # OS hid the path - we cannot verify it
    return not any(path.startswith(d) for d in config.TRUSTED_DIRS)


def _unusual_location(proc):
    """Check the executable AND the script it runs (e.g. python script.py)."""
    text = (proc["path"] + " " + proc["cmdline"]).lower().replace("/", os.sep)
    markers = [m.replace("/", os.sep) for m in config.UNUSUAL_PATH_MARKERS]
    return any(m in text for m in markers)


def analyze(processes, connections, file_burst):
    """Score every process. Returns a list sorted by score (highest first).

    `file_burst` is True when the file monitor saw a burst of changes; the
    burst is blamed on the untrusted process that wrote to disk the most
    since the last scan (the OS does not tell us who changed a file).
    """
    suspicious_pids = {c["pid"] for c in connections if c["suspicious"]}
    top_writer = None
    if file_burst:
        writers = [p for p in processes if p["writes_delta"] > 0]
        # Prefer untrusted writers: system programs write to disk all the time
        untrusted = [p for p in writers if _is_unknown(p) or _unusual_location(p)]
        candidates = untrusted or writers
        if candidates:
            top_writer = max(candidates, key=lambda p: p["writes_delta"])["pid"]

    results = []
    for proc in processes:
        reasons = []
        if _is_unknown(proc):
            reasons.append("unknown_process")
        if proc["cpu_percent"] >= config.HIGH_CPU_PERCENT:
            reasons.append("high_cpu")
        if _unusual_location(proc):
            reasons.append("unusual_path")
        if proc["pid"] == top_writer:
            reasons.append("file_burst")
        if proc["pid"] in suspicious_pids:
            reasons.append("suspicious_network")
        if len(reasons) >= 3:
            reasons.append("multiple_indicators")

        score = sum(config.SCORES[r] for r in reasons)
        results.append({**proc, "score": score, "level": risk_level(score),
                        "reasons": reasons})
    results.sort(key=lambda p: p["score"], reverse=True)
    return results
