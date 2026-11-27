"""SAFE TEST: simulates ransomware behaviour inside test_zone/ransom only.

It creates many files quickly, then renames them with a .locked extension -
exactly what real ransomware does when it encrypts your files. Nothing is
actually encrypted, and nothing outside test_zone is touched.

Expected alerts on the dashboard:
  - DUPLICATE_FILES      (lots of new files created fast)
  - RANSOMWARE_BEHAVIOR  (burst of file activity)
  - FILE_EXT_CHANGED     (.txt -> .locked, the ransomware signature)
If auto-recovery is on, the protected originals are also restored.
"""
import os
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
folder = os.path.join(BASE, "test_zone", "ransom")
os.makedirs(folder, exist_ok=True)

print(f"Ransomware simulation running, PID {os.getpid()}...")
paths = []
for i in range(40):  # 1) burst of new files (mass/duplicate creation)
    p = os.path.join(folder, f"document_{i}.txt")
    with open(p, "w") as f:
        f.write("important user data\n")
    paths.append(p)
    time.sleep(0.03)

print("Created 40 files. Now 'encrypting' them (renaming to .locked)...")
time.sleep(2)
for p in paths:  # 2) extension change = ransomware signature
    try:
        os.rename(p, p + ".locked")
    except OSError:
        pass
    time.sleep(0.03)

print("Done. Watch the dashboard: DUPLICATE_FILES, RANSOMWARE_BEHAVIOR, FILE_EXT_CHANGED.")
