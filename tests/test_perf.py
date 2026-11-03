"""Tests for the Overview performance data (run: python -m unittest)."""
import os
import tempfile
import unittest

from sentinelos.database import Database
from sentinelos.remote import Hub, perf_rates
from sentinelos.system_info import get_system_info


def system(t, read=0, write=0, busy=0, sent=0, recv=0):
    return {"cpu_percent": 10, "ram_used_percent": 40, "sampled_at": t,
            "disk_io": {"read_bytes": read, "write_bytes": write, "busy_ms": busy},
            "net": {"Wi-Fi": {"sent": sent, "recv": recv, "speed": 866}}}


def report(host, sys_block, handles=None):
    procs = [{"threads": 3}, {"threads": 5}]
    r = {"hostname": host, "system": sys_block, "threat_level": "LOW",
         "risk_counts": {"LOW": 2, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
         "monitored_files": 0, "processes": procs, "connections": [], "file_events": [], "alerts": []}
    if handles is not None:
        r["totals"] = {"threads": 8, "handles": handles}
    return r


class PerfRateTests(unittest.TestCase):
    def test_speeds_from_counters(self):
        r = perf_rates(system(100), system(102, read=2_000_000, write=1_000_000, busy=1000,
                                           sent=2000, recv=20000))
        self.assertEqual(r["disk_read"], 1_000_000)
        self.assertEqual(r["disk_write"], 500_000)
        self.assertEqual(r["disk_active"], 50.0)          # 1000 ms busy in 2 s
        self.assertEqual(r["net"]["Wi-Fi"], [1000, 10000])

    def test_active_time_is_capped_at_100(self):
        r = perf_rates(system(0), system(1, busy=5000))
        self.assertEqual(r["disk_active"], 100.0)

    def test_counter_reset_never_gives_negative_speed(self):
        r = perf_rates(system(0, read=9_000_000, sent=500), system(2, read=10, sent=1))
        self.assertEqual(r["disk_read"], 0)
        self.assertEqual(r["net"]["Wi-Fi"][0], 0)

    def test_nothing_to_compare(self):
        self.assertEqual(perf_rates({}, system(5)), {})                  # old agent
        self.assertEqual(perf_rates(system(5), system(5)), {})           # same instant
        self.assertEqual(perf_rates(system(0), system(1000)), {})        # long gap
        self.assertEqual(perf_rates({"sampled_at": 1}, {"sampled_at": 3}), {"net": {}})  # no counters


class HubPerfTests(unittest.TestCase):
    def setUp(self):
        self.hub = Hub(Database(os.path.join(tempfile.mkdtemp(), "t.db")))

    def test_history_gets_speeds_and_totals(self):
        self.hub.update(report("Ali", system(100), handles=900), "1.2.3.4")
        self.hub.update(report("Ali", system(102, read=4_000_000, sent=2000, recv=4000), handles=950), "1.2.3.4")
        ali = self.hub.summary()[0]
        self.assertNotIn("disk_read", ali["history"][0])          # first report: nothing to compare yet
        self.assertEqual(ali["history"][1]["disk_read"], 2_000_000)
        self.assertEqual(ali["history"][1]["net"]["Wi-Fi"], [1000, 2000])
        self.assertEqual((ali["threads"], ali["handles"]), (8, 950))

    def test_old_agent_still_works(self):
        old = {"cpu_percent": 5, "ram_used_percent": 30}
        self.hub.update(report("Old", old), "1.2.3.4")
        self.hub.update(report("Old", old), "1.2.3.4")
        e = self.hub.summary()[0]
        self.assertEqual(sorted(e["history"][1]), ["cpu", "procs", "ram", "t"])
        self.assertEqual((e["threads"], e["handles"]), (8, None))  # threads still counted server-side


class SystemInfoTests(unittest.TestCase):
    def test_new_fields_present(self):
        s = get_system_info()
        for key in ("sampled_at", "uptime_sec", "cpu_model", "cpu_physical", "virtualization",
                    "ram_total", "ram_used", "ram_available", "disk_io", "drives", "net"):
            self.assertIn(key, s)
        self.assertTrue(s["cpu_model"])
        self.assertGreater(s["ram_total"], s["ram_available"])
        self.assertIn("cpu_percent", s)  # existing fields are untouched


if __name__ == "__main__":
    unittest.main()
