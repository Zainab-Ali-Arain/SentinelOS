"""Module 10: Dashboard - Tkinter desktop interface."""
import json
import time
import socket
import datetime
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from . import config, response
from .database import HOSTNAME
from .engine import SentinelEngine

COLORS = {"LOW": "#2e7d32", "MEDIUM": "#ef6c00", "HIGH": "#c62828", "CRITICAL": "#6a1b9a"}
BG, CARD, FG, MUTED = "#1e1e2e", "#2a2a3d", "#e6e6f0", "#9a9ab0"


def lan_ip():
    """This computer's address on the local network (no data is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class Dashboard:
    def __init__(self, root, server=False):
        self.root = root
        self.engine = SentinelEngine()
        self.engine.start()
        self.scanning = False
        self.collapsed = set()  # process-tree nodes the user closed

        self.server = None
        if server:
            from .remote import EndpointServer
            self.server = EndpointServer(self.engine.db)
            self.server.start()

        root.title("SentinelOS - Mini EDR Dashboard")
        root.geometry("1250x740")
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._style()
        self._build_header()
        self._build_cards()
        self._build_tabs()
        self.status = tk.Label(root, text="Starting first scan...", bg=BG, fg=MUTED, anchor="w")
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
        if self.server:
            tk.Label(bar, text=f"Server ON  |  agents connect to: {lan_ip()}  "
                               f"(port {config.SERVER_PORT})",
                     bg="#1b5e20", fg="white", padx=10, pady=4).pack(side="right", padx=8)

    def _build_cards(self):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="x", padx=10, pady=4)
        self.cards = {}
        cards = [("procs", "Running Processes"), ("cpu", "CPU Usage"),
                 ("ram", "Memory Usage"), ("files", "Monitored Files"),
                 ("alerts", "Security Alerts"), ("high", "High-Risk Processes"),
                 ("top", "Highest-Risk Process")]
        if self.server:
            cards.append(("endpoints", "Endpoints Online"))
        for key, title in cards:
            card = tk.Frame(frame, bg=CARD, padx=10, pady=8)
            card.pack(side="left", expand=True, fill="both", padx=3)
            tk.Label(card, text=title, bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
            value = tk.Label(card, text="-", bg=CARD, fg=FG, font=("Segoe UI", 15, "bold"))
            value.pack(anchor="w")
            self.cards[key] = value

    def _table(self, parent, columns, widths, tree_mode=False):
        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns,
                            show="tree headings" if tree_mode else "headings")
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
        names = ["Processes", "Process Tree", "Alerts"]
        names += ["Endpoints"] if self.server else []
        names += ["File Events", "Network", "Event Log"]
        tabs = {}
        for name in names:
            tabs[name] = tk.Frame(nb, bg=BG)
            nb.add(tabs[name], text=name)

        self.proc_tree = self._table(
            tabs["Processes"], ("PID", "Process", "Parent", "CPU %", "Memory MB", "Threads",
                                "Score", "Risk", "Reasons"),
            (70, 170, 140, 70, 90, 65, 60, 80, 400))
        self._buttons(tabs["Processes"], [("🔍 Investigate", self.investigate_selected),
                                          ("⛔ Terminate", self.terminate_selected),
                                          ("✅ Mark as Trusted", self.trust_selected),
                                          ("📋 Manage Trusted List", self.manage_trusted)])

        self.ptree = self._table(tabs["Process Tree"], ("PID", "CPU %", "Score", "Risk"),
                                 (80, 80, 70, 90), tree_mode=True)
        self.ptree.heading("#0", text="Process (children are indented under their parent)")
        self.ptree.column("#0", width=520)
        self.ptree.bind("<<TreeviewClose>>",
                        lambda e: self.collapsed.add(self.ptree.focus()))
        self.ptree.bind("<<TreeviewOpen>>",
                        lambda e: self.collapsed.discard(self.ptree.focus()))

        self.alert_tree = self._table(
            tabs["Alerts"], ("ID", "Time", "Endpoint", "Type", "Process", "PID", "Score",
                             "Severity", "Reasons", "MITRE ATT&CK", "Status"),
            (40, 135, 110, 140, 130, 55, 50, 75, 250, 230, 100))
        self._buttons(tabs["Alerts"], [("✔ Mark Reviewed (Ignore)", self.ignore_alert),
                                       ("🔍 Investigate", self.investigate_alert),
                                       ("⛔ Terminate Process", self.terminate_alert),
                                       ("📦 Quarantine Test File", self.quarantine),
                                       ("💾 Export Alerts CSV", lambda: self.export("alerts"))])

        if self.server:
            self.endpoint_tree = self._table(
                tabs["Endpoints"], ("Endpoint", "IP", "Status", "Last Seen", "Threat",
                                    "Processes", "CPU %", "RAM %", "OS"),
                (160, 120, 80, 90, 90, 80, 70, 70, 250))
            self._buttons(tabs["Endpoints"],
                          [("🔍 View Endpoint Processes", self.view_endpoint)])

        self.file_tree = self._table(tabs["File Events"], ("Time", "Event", "Path"),
                                     (150, 110, 800))
        self.net_tree = self._table(
            tabs["Network"], ("PID", "Process", "Local", "Remote", "Port", "Status", "Flag"),
            (70, 160, 180, 200, 70, 110, 120))
        self.log_tree = self._table(
            tabs["Event Log"], ("Time", "Endpoint", "Event", "Process", "PID", "Severity",
                                "Details"), (135, 110, 160, 130, 60, 75, 500))
        self._buttons(tabs["Event Log"],
                      [("💾 Export Event Log CSV", lambda: self.export("events"))])

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
            ((p["pid"], p["name"], p["parent_name"], p["cpu_percent"], p["memory_mb"],
              p["threads"], p["score"], p["level"],
              ", ".join(p["reasons"] + p["notes"])), p["level"]) for p in procs],
            keep_selection=True)
        self._fill_process_tree(procs)
        self._fill(self.alert_tree, [
            ((a["id"], a["timestamp"], a["endpoint"], a["alert_type"], a["process"], a["pid"],
              a["score"], a["severity"], a["reasons"], a["mitre"], a["status"]), a["severity"])
            for a in alerts], keep_selection=True)
        self._fill(self.file_tree, [
            ((datetime.datetime.fromtimestamp(e["time"]).strftime("%H:%M:%S"), e["type"],
              e["path"] + (f" -> {e['dest']}" if e["dest"] else "")), "LOW")
            for e in reversed(state["file_events"])])
        self._fill(self.net_tree, [
            ((c["pid"], c["process"], c["local"], c["remote_ip"], c["remote_port"],
              c["status"], "SUSPICIOUS" if c["suspicious"] else ""),
             "HIGH" if c["suspicious"] else "LOW") for c in state["connections"]])
        self._fill(self.log_tree, [
            ((e["timestamp"], e["endpoint"], e["event_type"], e["process"], e["pid"],
              e["severity"], e["details"]), "MEDIUM" if e["severity"] == "MEDIUM" else "LOW")
            for e in self.engine.db.recent_events()])

        new_alerts = list(state["new_alerts"])
        if self.server:
            endpoints = self.server.snapshot()
            self.cards["endpoints"].config(
                text=f"{sum(e['online'] for e in endpoints)} / {len(endpoints)}")
            self._fill(self.endpoint_tree, [
                ((e["hostname"], e["ip"], "ONLINE" if e["online"] else "OFFLINE",
                  time.strftime("%H:%M:%S", time.localtime(e["last_seen"])), e["threat_level"],
                  e["process_count"], e["system"]["cpu_percent"],
                  e["system"]["ram_used_percent"], e["system"]["os"]),
                 e["threat_level"] if e["online"] else "LOW") for e in endpoints],
                keep_selection=True)
            new_alerts += self.server.take_alerts()

        self.status.config(text=f"Last scan: {time.strftime('%H:%M:%S')}  |  Host: {HOSTNAME}"
                                f"  |  OS: {sysinfo['os']}  |  Watching: {config.WATCH_DIR}")
        for a in new_alerts:
            if a["type"] == "PROCESS_ALERT":
                self._toast(a)

    def _fill(self, tree, rows, keep_selection=False):
        selected = [tree.item(i, "values")[0] for i in tree.selection()] if keep_selection else []
        tree.delete(*tree.get_children())
        for values, tag in rows:
            item = tree.insert("", "end", values=values, tags=(tag,))
            if str(values[0]) in selected:
                tree.selection_add(item)

    def _fill_process_tree(self, procs):
        """Show processes as a parent -> child tree (uses PID and PPID)."""
        selected = self.ptree.selection()
        self.ptree.delete(*self.ptree.get_children())
        by_pid = {p["pid"]: p for p in procs}
        children = {}
        for p in procs:
            parent = p["ppid"] if p["ppid"] in by_pid and p["ppid"] != p["pid"] else None
            children.setdefault(parent, []).append(p)

        def add(parent_iid, proc):
            iid = str(proc["pid"])
            self.ptree.insert(parent_iid, "end", iid=iid, text=proc["name"],
                              open=iid not in self.collapsed, tags=(proc["level"],),
                              values=(proc["pid"], proc["cpu_percent"], proc["score"],
                                      proc["level"]))
            for child in sorted(children.get(proc["pid"], []), key=lambda c: c["pid"]):
                add(iid, child)

        for root_proc in sorted(children.get(None, []), key=lambda c: c["pid"]):
            add("", root_proc)
        keep = [i for i in selected if self.ptree.exists(i)]
        if keep:
            self.ptree.selection_set(keep)

    def _toast(self, a):
        """Non-blocking alert popup (closes itself after 15 seconds)."""
        self.root.bell()
        win = tk.Toplevel(self.root, bg=COLORS.get(a["level"], COLORS["HIGH"]))
        win.title(f"{a['level']} RISK ACTIVITY")
        win.attributes("-topmost", True)
        text = (f"{a['level']} RISK ACTIVITY\n\nEndpoint: {a.get('endpoint', HOSTNAME)}\n"
                f"Process: {a['process']}\nPID: {a['pid']}\nRisk Score: {a['score']}\n"
                f"Reasons: {', '.join(a['reasons'])}\n"
                f"MITRE: {', '.join(a.get('mitre', [])) or '-'}\n\n"
                f"Open the Alerts tab to respond.")
        tk.Label(win, text=text, bg=win["bg"], fg="white", justify="left",
                 font=("Segoe UI", 10), padx=16, pady=12, wraplength=420).pack()
        tk.Button(win, text="OK", command=win.destroy, padx=20).pack(pady=(0, 10))
        win.after(15000, lambda: win.winfo_exists() and win.destroy())

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
        win.geometry("700x440")
        text = tk.Text(win, bg=CARD, fg=FG, font=("Consolas", 10), wrap="word")
        text.pack(fill="both", expand=True)
        for k, v in info.items():
            text.insert("end", f"{k:14}: {v}\n")
        text.config(state="disabled")

    def _find_process(self, pid):
        return next((p for p in self.engine.state.get("processes", []) if p["pid"] == pid), None)

    def investigate_selected(self):
        row = self._selected(self.proc_tree)
        if row:
            self._investigate(int(row[0]))

    def _investigate(self, pid):
        info = response.investigate(pid)
        if info is None:
            messagebox.showinfo("Investigate", "That process has already ended.")
            return
        proc = self._find_process(pid)
        if proc:
            info["Risk"] = f"{proc['level']} (score {proc['score']})"
            info["Reasons"] = ", ".join(proc["reasons"] + proc["notes"])
            info["MITRE ATT&CK"] = ", ".join(proc["mitre"]) or "-"
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

    def trust_selected(self):
        row = self._selected(self.proc_tree)
        if not row:
            return
        proc = self._find_process(int(row[0]))
        if not proc:
            return
        key = self.engine.trusted.key(proc)
        if messagebox.askyesno("Mark as trusted",
                               f"Never flag this program again?\n\n{key}\n\n"
                               "(IoC matches are still detected.)"):
            self.engine.trusted.add(proc)
            self.engine.db.add_event("TRUSTED_ADDED", proc["name"], proc["pid"], details=key)

    def manage_trusted(self):
        win = tk.Toplevel(self.root, bg=BG)
        win.title("Trusted programs")
        win.geometry("650x350")
        box = tk.Listbox(win, bg=CARD, fg=FG, font=("Consolas", 10))
        box.pack(fill="both", expand=True, padx=8, pady=8)
        for item in sorted(self.engine.trusted.items):
            box.insert("end", item)

        def remove():
            for i in reversed(box.curselection()):
                self.engine.trusted.remove(box.get(i))
                self.engine.db.add_event("TRUSTED_REMOVED", details=box.get(i))
                box.delete(i)
        self._buttons(win, [("🗑 Remove selected", remove)])

    def ignore_alert(self):
        row = self._selected(self.alert_tree)
        if row:
            self.engine.db.set_alert_status(int(row[0]), "REVIEWED", "ignored by user")

    def investigate_alert(self):
        row = self._selected(self.alert_tree)
        if not row:
            return
        alert = self.engine.db.get_alert(int(row[0]))
        if alert["pid"] and alert["endpoint"] == HOSTNAME:
            self._investigate(alert["pid"])
        else:  # file alerts, or alerts from another endpoint: show stored details
            alert["details"] = json.loads(alert["details"] or "{}")
            self._show_details(f"Alert {alert['id']}", alert)
        self.engine.db.set_alert_status(alert["id"], "INVESTIGATED", "details viewed")

    def terminate_alert(self):
        row = self._selected(self.alert_tree)
        if not row:
            return
        alert = self.engine.db.get_alert(int(row[0]))
        if alert["endpoint"] != HOSTNAME:
            messagebox.showinfo("Terminate", f"This alert came from {alert['endpoint']}.\n"
                                "Remote responses are disabled for safety - respond on "
                                "that computer.")
        elif not alert["pid"]:
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

    def export(self, table):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile=f"sentinelos_{table}_{time.strftime('%Y%m%d_%H%M')}.csv")
        if path:
            count = self.engine.db.export_csv(path, table)
            messagebox.showinfo("Export", f"Saved {count} rows to\n{path}")

    def view_endpoint(self):
        row = self._selected(self.endpoint_tree)
        if not row:
            return
        ep = next((e for e in self.server.snapshot() if e["hostname"] == row[0]), None)
        if not ep:
            return
        win = tk.Toplevel(self.root, bg=BG)
        win.title(f"{ep['hostname']} - top processes")
        win.geometry("950x450")
        tree = self._table(win, ("PID", "Process", "Parent", "CPU %", "Memory MB", "Score",
                                 "Risk", "Reasons"), (70, 170, 140, 70, 90, 60, 80, 300))
        for p in ep["top_processes"]:
            tree.insert("", "end", tags=(p["level"],), values=(
                p["pid"], p["name"], p["parent_name"], p["cpu_percent"], p["memory_mb"],
                p["score"], p["level"], ", ".join(p["reasons"])))

    def on_close(self):
        self.engine.stop()
        if self.server:
            self.server.stop()
        self.root.destroy()


def run(server=False):
    root = tk.Tk()
    Dashboard(root, server=server)
    root.mainloop()
