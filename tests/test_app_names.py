"""Tests for friendly process names (run: python -m unittest)."""
import unittest

from sentinelos.app_names import app_name, is_system


class AppNameTests(unittest.TestCase):
    def test_known_office_apps(self):
        self.assertEqual(app_name("WINWORD.EXE"), "Microsoft Word")
        self.assertEqual(app_name("POWERPNT.EXE"), "Microsoft PowerPoint")
        self.assertEqual(app_name("chrome.exe"), "Google Chrome")

    def test_unknown_name_is_tidied(self):
        self.assertEqual(app_name("my_cool-tool.exe"), "My Cool Tool")

    def test_system_vs_user_process(self):
        svchost = {"name": "svchost.exe", "path": r"C:\Windows\System32\svchost.exe",
                   "username": "NT AUTHORITY\\SYSTEM"}
        word = {"name": "WINWORD.EXE", "username": r"LAPTOP\Zainab",
                "path": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"}
        notepad = {"name": "notepad.exe", "path": r"C:\Windows\System32\notepad.exe",
                   "username": r"LAPTOP\Zainab"}
        self.assertTrue(is_system(svchost))
        self.assertFalse(is_system(word))
        self.assertFalse(is_system(notepad))  # opened by the user, even though in C:\Windows


if __name__ == "__main__":
    unittest.main()
