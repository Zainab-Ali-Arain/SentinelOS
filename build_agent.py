"""Build the agent-only package for group members' laptops.

    python build_agent.py          # -> dist/SentinelOS-Agent.zip  (needs Python on their laptop)
    python build_agent.py --exe    # -> dist/SentinelOS-Agent.exe  (no Python needed; build on Windows)

The package contains only the monitoring code - no dashboard, no user accounts,
no database of your alerts. AGENT_TOKEN from sentinelos/config.py is included,
so set it before building.
"""
import os
import sys
import shutil
import zipfile
import subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
AGENT_MODULES = ["__init__", "config", "system_info", "process_monitor", "file_monitor",
                 "network_monitor", "detection", "engine", "database", "lists", "remote",
                 "app_names"]
README = """SentinelOS Agent
================
This program only MONITORS this laptop (processes, files in test_zone,
network connections) and SENDS the results to the dashboard laptop.
It cannot be used to control this laptop and it has no dashboard.

1. Connect to the same Wi-Fi / hotspot as the dashboard laptop.
2. {run}
3. Type the dashboard laptop's IP and a name for this laptop.
4. Keep the window open. Press Ctrl+C to stop monitoring.
"""


def build_zip():
    os.makedirs(DIST, exist_ok=True)
    path = os.path.join(DIST, "SentinelOS-Agent.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(os.path.join(ROOT, "agent.py"), "SentinelOS-Agent/agent.py")
        z.write(os.path.join(ROOT, "iocs.json"), "SentinelOS-Agent/iocs.json")
        for m in AGENT_MODULES:
            z.write(os.path.join(ROOT, "sentinelos", m + ".py"), f"SentinelOS-Agent/sentinelos/{m}.py")
        z.writestr("SentinelOS-Agent/requirements.txt", "psutil>=6.0\nwatchdog>=3.0\n")
        z.writestr("SentinelOS-Agent/README.txt", README.format(
            run="Run once:  pip install -r requirements.txt\n   Then:      python agent.py"))
    print(f"Created {path}")


def build_exe():
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit("PyInstaller is missing. Run:  pip install pyinstaller")
    subprocess.check_call([
        sys.executable, "-m", "PyInstaller", "--onefile", "--console", "--clean", "--noconfirm",
        "--name", "SentinelOS-Agent", "--distpath", DIST,
        "--workpath", os.path.join(ROOT, "build"), "--specpath", os.path.join(ROOT, "build"),
        "--exclude-module", "flask", "--exclude-module", "tkinter",
        os.path.join(ROOT, "agent.py")])
    shutil.copy(os.path.join(ROOT, "iocs.json"), DIST)
    with open(os.path.join(DIST, "README.txt"), "w") as f:
        f.write(README.format(run="Double-click SentinelOS-Agent.exe"))
    print(f"\nCreated {os.path.join(DIST, 'SentinelOS-Agent.exe' if os.name == 'nt' else 'SentinelOS-Agent')}")
    print("Give the person the .exe, iocs.json and README.txt from the dist folder.")


if __name__ == "__main__":
    build_exe() if "--exe" in sys.argv else build_zip()
