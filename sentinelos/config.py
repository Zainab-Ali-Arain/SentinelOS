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
IOC_FILE = os.path.join(BASE_DIR, "iocs.json")          # blocklist (IoCs)
TRUSTED_FILE = os.path.join(DATA_DIR, "trusted.json")   # user whitelist

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
    "suspicious_parent": 65,   # strong sign on its own -> HIGH
    "ioc_match": 110,           # known-bad hash/name/IP -> always CRITICAL
    "multiple_indicators": 15,  # bonus when 3 or more indicators combine
}

# MITRE ATT&CK technique for each indicator / alert type
MITRE = {
    "unknown_process": "T1036 Masquerading",
    "high_cpu": "T1496 Resource Hijacking",
    "unusual_path": "T1204.002 User Execution: Malicious File",
    "file_burst": "T1486 Data Encrypted for Impact",
    "suspicious_network": "T1571 Non-Standard Port",
    "suspicious_parent": "T1059 Command and Scripting Interpreter",
    "ioc_match": "Known Indicator of Compromise",
    "RANSOMWARE_BEHAVIOR": "T1486 Data Encrypted for Impact",
    "FILE_INTEGRITY": "T1565.001 Stored Data Manipulation",
}

# Office/document apps should never start a shell. If they do, it is a
# classic sign of a malicious macro or exploited document.
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "acrord32.exe", "acrobat.exe", "wordpad.exe", "mspub.exe",
}
SUSPICIOUS_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "sh", "bash",
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

# ---- Multi-endpoint (agent -> central server) ----
SERVER_PORT = 9900
# Shared secret: the agent and the server must use the same value.
# Change it before the demo.
AGENT_TOKEN = "change-this-secret-123"
AGENT_INTERVAL_SEC = 5
ENDPOINT_OFFLINE_SEC = 30   # no report for this long = endpoint offline
