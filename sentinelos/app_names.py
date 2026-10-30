"""Friendly names for processes, e.g. WINWORD.EXE -> "Microsoft Word".

On Windows every .exe carries a "File description" inside it (the same text
Task Manager shows). We read it with the Windows version API. If that is not
available we fall back to a small built-in list, then to a tidied file name.
"""
import os
import sys

KNOWN = {
    "winword.exe": "Microsoft Word", "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint", "outlook.exe": "Microsoft Outlook",
    "onenote.exe": "Microsoft OneNote", "msaccess.exe": "Microsoft Access",
    "chrome.exe": "Google Chrome", "msedge.exe": "Microsoft Edge", "firefox.exe": "Firefox",
    "code.exe": "Visual Studio Code", "explorer.exe": "File Explorer",
    "notepad.exe": "Notepad", "calc.exe": "Calculator", "mspaint.exe": "Paint",
    "taskmgr.exe": "Task Manager", "cmd.exe": "Command Prompt",
    "powershell.exe": "Windows PowerShell", "pwsh.exe": "PowerShell",
    "python.exe": "Python", "pythonw.exe": "Python", "python3": "Python",
    "whatsapp.exe": "WhatsApp", "teams.exe": "Microsoft Teams", "ms-teams.exe": "Microsoft Teams",
    "zoom.exe": "Zoom", "spotify.exe": "Spotify", "acrord32.exe": "Adobe Acrobat Reader",
    "vlc.exe": "VLC Media Player", "svchost.exe": "Windows Service Host",
    "searchhost.exe": "Windows Search", "msmpeng.exe": "Microsoft Defender Antivirus",
    "lsass.exe": "Local Security Authority", "winlogon.exe": "Windows Logon",
    "csrss.exe": "Client Server Runtime", "dwm.exe": "Desktop Window Manager",
    "services.exe": "Services and Controller", "smss.exe": "Session Manager",
    "system": "Windows Kernel (System)", "system idle process": "System Idle Process",
    "registry": "Windows Registry", "runtimebroker.exe": "Runtime Broker",
    "sihost.exe": "Shell Infrastructure Host", "taskhostw.exe": "Windows Task Host",
    "ctfmon.exe": "Text Input (CTF Loader)", "spoolsv.exe": "Print Spooler",
    "onedrive.exe": "Microsoft OneDrive", "git.exe": "Git",
}

_cache = {}


def _windows_description(path):
    """Read the 'FileDescription' text stored inside a Windows .exe."""
    import ctypes
    from ctypes import wintypes

    ver = ctypes.windll.version
    ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                        ctypes.c_void_p]
    ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                   ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
    size = ver.GetFileVersionInfoSizeW(path, None)
    if not size:
        return ""
    buf = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(path, 0, size, buf):
        return ""
    ptr, length = ctypes.c_void_p(), wintypes.UINT()
    languages = []
    if ver.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(ptr),
                          ctypes.byref(length)) and length.value >= 4:
        pair = ctypes.cast(ptr, ctypes.POINTER(wintypes.WORD * 2)).contents
        languages.append((pair[0], pair[1]))
    languages += [(0x0409, 0x04B0), (0x0409, 0x04E4), (0x0000, 0x04B0)]
    for lang, codepage in languages:
        key = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileDescription"
        if ver.VerQueryValueW(buf, key, ctypes.byref(ptr), ctypes.byref(length)) \
                and length.value and ptr.value:
            text = ctypes.wstring_at(ptr.value).strip()
            if text:
                return text
    return ""


def app_name(name, path=""):
    """Best human-readable name for a process."""
    key = (name.lower(), path.lower())
    if key not in _cache:
        friendly = ""
        if sys.platform == "win32" and path:
            try:
                friendly = _windows_description(path)
            except Exception:  # missing API or unreadable file: use fallbacks
                friendly = ""
        friendly = friendly or KNOWN.get(name.lower(), "")
        if not friendly:
            base = os.path.splitext(name)[0] if name.lower().endswith(".exe") else name
            friendly = base.replace("_", " ").replace("-", " ").strip().title() or name
        _cache[key] = friendly
    return _cache[key]


SYSTEM_USERS = {"system", "local service", "network service", "nt authority\\system",
                "nt authority\\local service", "nt authority\\network service", "root"}
SYSTEM_DIRS = (r"c:\windows", "/usr/lib", "/usr/sbin", "/sbin", "/lib")


def is_system(proc):
    """True for background OS processes (not apps the user opened)."""
    user = (proc.get("username") or "").lower()
    path = (proc.get("path") or "").lower()
    if not path or user in SYSTEM_USERS or user.split("\\")[-1] in SYSTEM_USERS:
        return True
    return path.startswith(SYSTEM_DIRS) and proc["name"].lower() not in {
        "explorer.exe", "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe",
        "powershell.exe", "taskmgr.exe"}
