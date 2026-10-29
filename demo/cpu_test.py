"""SAFE TEST: uses a lot of CPU for 30 seconds, nothing else.
Expected result: high_cpu indicator, but risk stays LOW/MEDIUM
(shows the EDR does not flag a process for high CPU alone)."""
import os
import time

print(f"CPU test running, PID {os.getpid()} (30 seconds)...")
end = time.time() + 30
while time.time() < end:
    pass
print("Done.")
