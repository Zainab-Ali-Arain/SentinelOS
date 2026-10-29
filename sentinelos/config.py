"""Central settings for SentinelOS. Change values here to tune detection."""
import os
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Folders used by the EDR
WATCH_DIR = os.path.join(BASE_DIR, "test_zone")        # monitored directory
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")  # safe quarantine area
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")
LOG_PATH = os.path.join(DATA_DIR, "sentinel.log")

# How often the dashboard runs a scan (milliseconds)
SCAN_INTERVAL_MS = 3000

# ---- Detection thresholds ----
HIGH_CPU_PERCENT = 80          # CPU % considered "very high"
FILE_BURST_WINDOW_SEC = 10     # look at file events in this time window
FILE_BURST_COUNT = 50          # this many changes in the window = burst
ALERT_COOLDOWN_SEC = 60        # don't repeat the same alert for this long

# ---- Risk scoring model (project-defined points) ----
SCORES = {
    "unknown_process": 20,
    "high_cpu": 10,
    "unusual_path": 25,
    "file_burst": 30,
    "suspicious_network": 20,
    "multiple_indicators": 15,  # bonus when 3 or more indicators combine
}

# Score -> level. Alerts are raised from ALERT_LEVEL upwards.
RISK_LEVELS = [(30, "LOW"), (60, "MEDIUM"), (100, "HIGH")]  # above 100 = CRITICAL
ALERT_LEVEL = "HIGH"

# Executables inside these folders are treated as "known"
TRUSTED_DIRS = [
    r"c:\windows", r"c:\program files", r"c:\program files (x86)",
    "/usr", "/bin", "/sbin", "/lib", "/opt", "/snap",
    "/applications", "/system",
]
KNOWN_PROCESS_NAMES = {"code.exe", "explorer.exe", "chrome.exe", "msedge.exe"}

# Programs running from these places are unusual
UNUSUAL_PATH_MARKERS = [
    tempfile.gettempdir().lower(), r"\appdata\local\temp", r"\temp" + "\\",
    r"\downloads" + "\\", "/tmp/", "/downloads/",
]

# Remote ports commonly linked to backdoors / test shells
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6667, 12345, 9001}
