"""Unit tests for the detection rules (run: python -m unittest)."""
import unittest

from sentinelos import config
from sentinelos.detection import analyze, risk_level


def proc(pid=100, name="test.exe", path=r"c:\program files\app\test.exe", cpu=0.0,
         parent="explorer.exe", cmdline="", writes=0):
    return {"pid": pid, "ppid": 1, "name": name, "path": path, "cmdline": cmdline,
            "cpu_percent": cpu, "memory_mb": 10, "threads": 1, "writes_delta": writes,
            "parent_name": parent}


class FakeIocs:
    hashes, names, ips = set(), {"mimikatz.exe"}, {"10.6.6.6"}

    def match_process(self, p):
        return f"name {p['name']}" if p["name"] in self.names else ""


class FakeTrusted:
    def __init__(self, names):
        self.names = names

    def is_trusted(self, p):
        return p["name"] in self.names


class DetectionTests(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(risk_level(30), "LOW")
        self.assertEqual(risk_level(31), "MEDIUM")
        self.assertEqual(risk_level(100), "HIGH")
        self.assertEqual(risk_level(101), "CRITICAL")

    def test_normal_process_is_low(self):
        r = analyze([proc()], [], False)[0]
        self.assertEqual((r["score"], r["level"]), (0, "LOW"))

    def test_high_cpu_alone_is_not_an_alert(self):
        r = analyze([proc(cpu=99)], [], False)[0]
        self.assertEqual(r["level"], "LOW")  # avoids false positives

    def test_word_starting_powershell(self):
        p = proc(name="powershell.exe", path=r"c:\windows\system32\powershell.exe",
                 parent="WINWORD.EXE")
        r = analyze([p], [], False)[0]
        self.assertIn("suspicious_parent", r["reasons"])
        self.assertEqual(r["level"], "HIGH")  # alerts even from a trusted folder
        self.assertIn("T1059 Command and Scripting Interpreter", r["mitre"])

    def test_combined_indicators_reach_high(self):
        p = proc(name="evil.exe", path=r"c:\users\a\downloads\evil.exe", cpu=95, writes=500)
        conn = [{"pid": 100, "remote_ip": "1.2.3.4", "suspicious": True}]
        r = analyze([p], conn, True)[0]
        self.assertEqual(r["level"], "CRITICAL")  # 20+10+25+30+20+15 = 120
        self.assertEqual(r["score"], 120)

    def test_ioc_name_is_critical(self):
        r = analyze([proc(name="mimikatz.exe")], [], False, iocs=FakeIocs())[0]
        self.assertEqual(r["level"], "CRITICAL")

    def test_ioc_ip(self):
        conn = [{"pid": 100, "remote_ip": "10.6.6.6", "suspicious": False}]
        r = analyze([proc()], conn, False, iocs=FakeIocs())[0]
        self.assertIn("ioc_match", r["reasons"])

    def test_trusted_process_is_skipped(self):
        p = proc(name="mytool.exe", path=r"c:\users\a\downloads\mytool.exe", cpu=99)
        r = analyze([p], [], False, trusted=FakeTrusted({"mytool.exe"}))[0]
        self.assertEqual((r["score"], r["reasons"]), (0, ["trusted"]))

    def test_trusted_does_not_hide_ioc(self):
        r = analyze([proc(name="mimikatz.exe")], [], False, iocs=FakeIocs(),
                    trusted=FakeTrusted({"mimikatz.exe"}))[0]
        self.assertEqual(r["level"], "CRITICAL")

    def test_file_burst_blames_untrusted_writer(self):
        system = proc(pid=1, name="svchost.exe", path=r"c:\windows\svchost.exe", writes=900)
        bad = proc(pid=2, name="x.exe", path=r"c:\users\a\appdata\local\temp\x.exe", writes=300)
        result = {r["pid"]: r for r in analyze([system, bad], [], True)}
        self.assertIn("file_burst", result[2]["reasons"])
        self.assertNotIn("file_burst", result[1]["reasons"])


if __name__ == "__main__":
    unittest.main()
