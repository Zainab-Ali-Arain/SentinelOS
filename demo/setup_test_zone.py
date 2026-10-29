"""Create harmless sample files in test_zone/protected.
Run this BEFORE starting the EDR so these files become the integrity baseline."""
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
folder = os.path.join(BASE, "test_zone", "protected")
os.makedirs(folder, exist_ok=True)
for i in range(1, 11):
    with open(os.path.join(folder, f"document_{i}.txt"), "w") as f:
        f.write(f"This is harmless sample document number {i}.\n")
print(f"Created 10 sample files in {folder}")
