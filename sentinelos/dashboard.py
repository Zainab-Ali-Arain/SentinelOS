"""Module 10: Dashboard - Tkinter desktop interface."""
import json
import time
import datetime
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from . import config, response
from .engine import SentinelEngine

COLORS = {"LOW": "#2e7d32", "MEDIUM": "#ef6c00", "HIGH": "#c62828", "CRITICAL": "#6a1b9a"}
BG, CARD, FG = "#1e1e2e", "#2a2a3d", "#e6e6f0"


class Dashboard:
    def __init__(self, root):
        self.root = root
        self.engine = SentinelEngine()
        self.engine.start()
        self.scanning = False

        root.title("SentinelOS - Mini EDR Dashboard")
        root.geometry("1150x700")
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._style()
        self._build_header()
        self._build_cards()
        self._build_tabs()
        self.status = tk.Label(root, text="Starting first scan...", bg=BG, fg="#9a9ab0",
                               anchor="w")
        self.status.pack(fill="x", padx=10, pady=(0, 6))
        self.schedule_scan(100)

    # ---------- layout ----------
    def _style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=FG,
                    rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background="#3a3a55", foreground=FG)
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background="#3a3a55", foreground=FG, padding=(12, 5))
        s.map("TNotebook.Tab", background=[("selected", "#5a5a8a")])

    def _build_header(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(bar, text="🛡  SentinelOS - Mini EDR", font=("Segoe UI", 18, "bold"),
                 bg=BG, fg=FG).pack(side="left")
        self.threat_label = tk.Label(bar, text="THREAT: ...", font=("Segoe UI", 13, "bold"),
                                     bg=COLORS["LOW"], fg="white", padx=12, pady=4)
        self.threat_label.pack(side="right")

    def _build_cards(self):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="x", padx=10, pady=4)
        self.cards = {}
        for key, title in [("procs", "Running Processes"), ("cpu", "CPU Usage"),
                           ("ram", "Memory Usage"), ("files", "Monitored Files"),
                           ("alerts", "Security Alerts"), ("high", "High-Risk Processes"),
                           ("top", "Highest-Risk Process")]:
            card = tk.Frame(frame, bg=CARD, padx=10, pady=8)
            card.pack(side="left", expand=True, fill="both", padx=3)
            tk.Label(card, text=title, bg=CARD, fg="#9a9ab0", font=("Segoe UI", 9)).pack(anchor="w")
            value = tk.Label(card, text="-", bg=CARD, fg=FG, font=("Segoe UI", 15, "bold"))
            value.pack(anchor="w")
            self.cards[key] = value

    def _table(self, parent, columns, widths):
        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col, w in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="w")
        for level, color in COLORS.items():
            tree.tag_configure(level, foreground=color if level == "LOW" else "white",
                               background=CARD if level == "LOW" else color)
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return tree

    def _buttons(self, parent, buttons):
        bar = tk.Frame(parent, bg=BG)
        bar.pack(fill="x", pady=4)
        for text, cmd in buttons:
            tk.Button(bar, text=text, command=cmd, bg="#3a3a55", fg=FG, relief="flat",
                      padx=10, activebackground="#5a5a8a").pack(side="left", padx=3)

    def _build_tabs(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=4)
        tabs = {}
        for name in ["Processes", "Alerts", "File Events", "Network", "Event Log"]:
            tabs[name] = tk.Frame(nb, bg=BG)
            nb.add(tabs[name], text=name)

        self.proc_tree = self._table(
            tabs["Processes"], ("PID", "Process", "CPU %", "Memory MB", "Threads", "Score",
                                "Risk", "Reasons"), (70, 180, 70, 90, 70, 60, 80, 400))
        self._buttons(tabs["Processes"], [("🔍 Investigate", self.investigate_selected),
                                          ("⛔ Terminate", self.terminate_selected)])

        self.alert_tree = self._table(
            tabs["Alerts"], ("ID", "Time", "Type", "Process", "PID", "Score", "Severity",
                             "Reasons", "Status"), (40, 140, 150, 160, 60, 50, 80, 300, 120))
        self._buttons(tabs["Alerts"], [("✔ Mark Reviewed (Ignore)", self.ignore_alert),
                                       ("🔍 Investigate", self.investigate_alert),
                                       ("⛔ Terminate Process", self.terminate_alert),
                                       ("📦 Quarantine Test File", self.quarantine)])

        self.file_tree = self._table(tabs["File Events"], ("Time", "Event", "Path"),
                                     (150, 110, 800))
        self.net_tree = self._table(
            tabs["Network"], ("PID", "Process", "Local", "Remote", "Port", "Status", "Flag"),
            (70, 160, 180, 200, 70, 110, 120))
        self.log_tree = self._table(
            tabs["Event Log"], ("Time", "Event", "Process", "PID", "Severity", "Details"),
            (140, 170, 140, 60, 80, 500))

    # ---------- scanning ----------
    def schedule_scan(self, delay=config.SCAN_INTERVAL_MS):
        self.root.after(delay, self._start_scan)

    def _start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        # Scanning takes ~1s, so do it in a worker thread to keep the UI responsive
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            state = self.engine.scan()
            self.root.after(0, self._update_ui, state)
        except Exception as exc:  # keep the dashboard alive on errors
            self.root.after(0, self.status.config, {"text": f"Scan error: {exc}"})
        finally:
            self.scanning = False
            self.root.after(0, self.schedule_scan)

    def _update_ui(self, state):
        sysinfo, procs = state["system"], state["processes"]
        alerts = self.engine.db.recent_alerts()
        high = state["risk_counts"]["HIGH"] + state["risk_counts"]["CRITICAL"]
        top = procs[0] if procs else None

        self.cards["procs"].config(text=len(procs))
        self.cards["cpu"].config(text=f"{sysinfo['cpu_percent']}%")
        self.cards["ram"].config(text=f"{sysinfo['ram_used_percent']}%")
        self.cards["files"].config(text=state["monitored_files"])
        self.cards["alerts"].config(text=len(alerts))
        self.cards["high"].config(text=high)
        self.cards["top"].config(text=f"{top['name'][:14]} ({top['score']})" if top else "-")
        level = state["threat_level"]
        self.threat_label.config(text=f"THREAT: {level}", bg=COLORS[level])

        self._fill(self.proc_tree, [
            ((p["pid"], p["name"], p["cpu_percent"], p["memory_mb"], p["threads"],
              p["score"], p["level"], ", ".join(p["reasons"])), p["level"]) for p in procs],
            keep_selection=True)
        self._fill(self.alert_tree, [
            ((a["id"], a["timestamp"], a["alert_type"], a["process"], a["pid"], a["score"],
              a["severity"], a["reasons"], a["status"]), a["severity"]) for a in alerts],
            keep_selection=True)
        self._fill(self.file_tree, [
            ((datetime.datetime.fromtimestamp(e["time"]).strftime("%H:%M:%S"), e["type"],
              e["path"] + (f" -> {e['dest']}" if e["dest"] else "")), "LOW")
            for e in reversed(state["file_events"])])
        self._fill(self.net_tree, [
            ((c["pid"], c["process"], c["local"], c["remote_ip"], c["remote_port"],
              c["status"], "SUSPICIOUS" if c["suspicious"] else ""),
             "HIGH" if c["suspicious"] else "LOW") for c in state["connections"]])
        self._fill(self.log_tree, [
            ((e["timestamp"], e["event_type"], e["process"], e["pid"], e["severity"],
              e["details"]), "MEDIUM" if e["severity"] == "MEDIUM" else "LOW")
            for e in self.engine.db.recent_events()])

        self.status.config(text=f"Last scan: {time.strftime('%H:%M:%S')}"
                                f"  |  Host: {sysinfo['hostname']}  |  OS: {sysinfo['os']}"
                                f"  |  Watching: {config.WATCH_DIR}")
        for a in state["new_alerts"]:
            if a["level"] in ("HIGH", "CRITICAL") and a["type"] == "PROCESS_ALERT":
                self.root.bell()
                messagebox.showwarning(
                    f"{a['level']} RISK ACTIVITY",
                    f"Process: {a['process']}\nPID: {a['pid']}\nRisk Score: {a['score']}\n"
                    f"Reasons: {', '.join(a['reasons'])}\n\nOpen the Alerts tab to respond.")

    def _fill(self, tree, rows, keep_selection=False):
        selected = [tree.item(i, "values")[0] for i in tree.selection()] if keep_selection else []
        tree.delete(*tree.get_children())
        for values, tag in rows:
            item = tree.insert("", "end", values=values, tags=(tag,))
            if str(values[0]) in selected:
                tree.selection_add(item)

    # ---------- responses ----------
    def _selected(self, tree):
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Select a row", "Please select a row first.")
            return None
        return tree.item(sel[0], "values")

    def _show_details(self, title, info):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("650x420")
        text = tk.Text(win, bg=CARD, fg=FG, font=("Consolas", 10), wrap="word")
        text.pack(fill="both", expand=True)
        for k, v in info.items():
            text.insert("end", f"{k:14}: {v}\n")
        text.config(state="disabled")

    def investigate_selected(self):
        row = self._selected(self.proc_tree)
        if row:
            self._investigate(int(row[0]))

    def _investigate(self, pid):
        info = response.investigate(pid)
        if info is None:
            messagebox.showinfo("Investigate", "That process has already ended.")
        else:
            self._show_details(f"Process {pid} details", info)

    def _terminate(self, pid, name):
        if not messagebox.askyesno("Confirm termination",
                                   f"Really terminate {name} (PID {pid})?\n\n"
                                   "Only do this for test processes you recognise."):
            return False
        ok, msg = response.terminate_process(pid)
        self.engine.db.add_event("RESPONSE_TERMINATE", name, pid,
                                 "INFO" if ok else "MEDIUM", msg)
        (messagebox.showinfo if ok else messagebox.showerror)("Terminate", msg)
        return ok

    def terminate_selected(self):
        row = self._selected(self.proc_tree)
        if row:
            self._terminate(int(row[0]), row[1])

    def ignore_alert(self):
        row = self._selected(self.alert_tree)
        if row:
            self.engine.db.set_alert_status(int(row[0]), "REVIEWED", "ignored by user")

    def investigate_alert(self):
        row = self._selected(self.alert_tree)
        if not row:
            return
        alert = self.engine.db.get_alert(int(row[0]))
        if alert["pid"]:
            self._investigate(alert["pid"])
        else:
            alert["details"] = json.loads(alert["details"] or "{}")
            self._show_details(f"Alert {alert['id']}", alert)
        self.engine.db.set_alert_status(alert["id"], "INVESTIGATED", "details viewed")

    def terminate_alert(self):
        row = self._selected(self.alert_tree)
        if not row:
            return
        alert = self.engine.db.get_alert(int(row[0]))
        if not alert["pid"]:
            messagebox.showinfo("Terminate", "This alert is not linked to a process.")
        elif self._terminate(alert["pid"], alert["process"]):
            self.engine.db.set_alert_status(alert["id"], "RESOLVED", "process terminated")

    def quarantine(self):
        path = filedialog.askopenfilename(initialdir=config.WATCH_DIR,
                                          title="Choose a test file to quarantine")
        if path and messagebox.askyesno("Confirm quarantine", f"Move this file?\n{path}"):
            ok, msg = response.quarantine_file(path)
            self.engine.db.add_event("RESPONSE_QUARANTINE", details=msg,
                                     severity="INFO" if ok else "MEDIUM")
            (messagebox.showinfo if ok else messagebox.showerror)("Quarantine", msg)

    def on_close(self):
        self.engine.stop()
        self.root.destroy()


def run():
    root = tk.Tk()
    Dashboard(root)
    root.mainloop()
