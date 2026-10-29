"""SAFE TEST: rapidly creates and edits plain text files inside test_zone/burst.
Expected result: file events + RANSOMWARE_BEHAVIOR alert.
Nothing is encrypted and nothing outside test_zone is touched."""
import os
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
folder = os.path.join(BASE, "test_zone", "burst")
os.makedirs(folder, exist_ok=True)
print(f"File burst test running, PID {os.getpid()} (20 seconds)...")
end, i = time.time() + 20, 0
while time.time() < end:
    with open(os.path.join(folder, f"file_{i % 100}.txt"), "w") as f:
        f.write(f"harmless test content {i}\n")
    i += 1
    time.sleep(0.02)
print(f"Done. {i} file writes.")
