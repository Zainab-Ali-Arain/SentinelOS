"""Central settings for SentinelOS. Change values here to tune detection."""
import os
import sys
import tempfile

if getattr(sys, "frozen", False):
    # Running as SentinelOS-Agent.exe: keep data next to the .exe
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
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
    "dark_web": "T1090.003 Multi-hop Proxy: Tor",
    "DARK_WEB": "T1090.003 Multi-hop Proxy: Tor",
    "USB_INSERTED": "T1091 Replication Through Removable Media",
    "USB_DATA_LEAK": "T1052.001 Exfiltration over USB",
    "USB_DATA_COPY": "T1052.001 Exfiltration over USB",
    "DUPLICATE_FILES": "T1486 Data Encrypted for Impact",
    "FILE_MOVED": "T1565.001 Stored Data Manipulation",
    "FILE_EXT_CHANGED": "T1486 Data Encrypted for Impact",
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

# ---- Dark web / anonymiser (Tor) detection ----
# How people reach the "dark web" (.onion) is the Tor network. We flag it two
# ways: a Tor program running, or a connection to a typical Tor port.
TOR_PROCESS_NAMES = {"tor.exe", "tor", "tor-real", "torbrowser.exe",
                     "start-tor-browser", "obfs4proxy.exe", "obfs4proxy"}
TOR_PORTS = {9001, 9030, 9040, 9050, 9051, 9150, 9151}
DARK_WEB_SCORE = 40   # points added when Tor use is detected

# ---- USB / removable media ----
USB_MONITOR = True            # watch for USB drives being plugged in
USB_WATCH_WRITES = True       # also watch what is copied TO the USB (data-leak check)
USB_LEAK_ALERT_LEVEL = "HIGH" # level for a removal where files were copied out

# ---- Real system-protected files (File Integrity Monitoring) ----
# These are OS files a normal program should never change. We only READ and
# HASH them (never modify/delete). If one changes, it is a strong sign of
# compromise -> CRITICAL alert. OS-aware so the same code works everywhere.
PROTECT_SYSTEM_FILES = True


def _protected_targets():
    """Return (files, dirs) of high-value protected paths for this OS."""
    files, dirs = [], []
    home = os.path.expanduser("~")
    if os.name == "nt":  # Windows
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        files.append(os.path.join(sysroot, "System32", "drivers", "etc", "hosts"))
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("ProgramData", r"C:\ProgramData")
        if appdata:
            dirs.append(os.path.join(appdata, "Microsoft", "Windows",
                                     "Start Menu", "Programs", "Startup"))
        dirs.append(os.path.join(programdata, "Microsoft", "Windows",
                                 "Start Menu", "Programs", "StartUp"))
    elif sys.platform == "darwin":  # macOS
        files += ["/etc/hosts", "/etc/sudoers"]
        dirs.append(os.path.join(home, "Library", "LaunchAgents"))
    else:  # Linux
        files += ["/etc/hosts", "/etc/passwd", "/etc/sudoers", "/etc/crontab"]
        files.append(os.path.join(home, ".ssh", "authorized_keys"))
    return files, dirs


PROTECTED_FILES, PROTECTED_DIRS = _protected_targets()

# ---- Self-healing recovery ----
# When a protected file is modified/deleted, restore it from a known-good
# backup taken when the baseline was built.
AUTO_RECOVERY = True
BACKUP_DIR = os.path.join(DATA_DIR, "backup")
# Keep a short version history of each protected file so any previous version
# can be restored, not just the latest known-good copy.
FILE_VERSIONING = True
MAX_VERSIONS = 10

# ---- Lockdown (OS-level write/delete protection) ----
# When True, the agent locks protected files on startup so they cannot be
# modified or deleted (needs admin/root). Also available via the command line:
#   python main.py --lock     (turn protection on)
#   python main.py --unlock   (turn it off again)
LOCKDOWN_PROTECTED = False

# ---- Duplicate / mass file-creation (ransomware-style staging) ----
# Separate from the generic "burst": this looks specifically at NEW files being
# created fast (a virus copying/duplicating itself or encrypting into copies).
FILE_CREATE_WINDOW_SEC = 10   # window for counting new-file creations
FILE_CREATE_COUNT = 25        # this many CREATED events in the window = alert

# ---- Web dashboard + agents ----
WEB_PORT = 8000            # dashboard: http://<server-ip>:8000
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SECRET_FILE = os.path.join(DATA_DIR, "secret.key")
# Shared secret: agents and the server must use the same value.
# Change it before the demo.
AGENT_TOKEN = "change-this-secret-123"
AGENT_INTERVAL_SEC = 5
ENDPOINT_OFFLINE_SEC = 30  # no report for this long = endpoint offline
LOGIN_MAX_FAILS = 5        # failed logins before a short lockout
LOGIN_LOCK_SEC = 60

# ---- Disk usage limits ----
EVENT_RETENTION_DAYS = 7   # activity-log events older than this are deleted (alerts are kept)
LOG_MAX_MB = 5             # sentinel.log rolls over at this size
LOG_BACKUPS = 2            # old log files kept (sentinel.log.1, .2)
