import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import re
import os
import threading
from collections import defaultdict
from datetime import datetime


# ─── Detection Config ────────────────────────────────────────────────────────

FAILED_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+ ssh2"),
    re.compile(r"Invalid user (\S+) from ([\d.]+)"),
    re.compile(r"authentication failure.*rhost=([\d.]+).*user=(\S+)"),
    re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+)"),
]

SUCCESS_PATTERNS = [
    re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"),
    re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.:a-fA-F]+)"),
]

TIMESTAMP_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)

BRUTE_THRESHOLD = 5  # default


# ─── Log Parser ──────────────────────────────────────────────────────────────

def parse_log(filepath, threshold=BRUTE_THRESHOLD, progress_cb=None):
    failed_attempts = defaultdict(list)     # ip -> [(user, timestamp), ...]
    successful_logins = []
    total_lines = 0
    parsed_lines = 0

    # count lines first
    with open(filepath, "r", errors="replace") as f:
        lines = f.readlines()
    total_lines = len(lines)

    for i, line in enumerate(lines):
        if progress_cb and i % 500 == 0:
            progress_cb(i, total_lines)

        ts_match = TIMESTAMP_PATTERN.search(line)
        timestamp = ts_match.group(1) if ts_match else "unknown"

        matched_failed = False
        for pattern in FAILED_PATTERNS:
            m = pattern.search(line)
            if m:
                groups = m.groups()
                if len(groups) == 2:
                    # figure out which is ip and which is user
                    g0, g1 = groups
                    if re.match(r"[\d.]+", g0) and not re.match(r"[\d.]+", g1):
                        ip, user = g0, g1
                    else:
                        user, ip = g0, g1
                    failed_attempts[ip].append({"user": user, "timestamp": timestamp, "line": line.strip()})
                    matched_failed = True
                    break

        if not matched_failed:
            for pattern in SUCCESS_PATTERNS:
                m = pattern.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    successful_logins.append({"user": user, "ip": ip, "timestamp": timestamp, "line": line.strip()})
                    break

        parsed_lines += 1

    if progress_cb:
        progress_cb(total_lines, total_lines)

    # classify attackers
    attackers = {}
    for ip, attempts in failed_attempts.items():
        count = len(attempts)
        attackers[ip] = {
            "count": count,
            "attempts": attempts,
            "is_brute_force": count >= threshold,
            "users_tried": list({a["user"] for a in attempts}),
            "first_seen": attempts[0]["timestamp"] if attempts else "?",
            "last_seen": attempts[-1]["timestamp"] if attempts else "?",
        }

    return {
        "attackers": attackers,
        "successful_logins": successful_logins,
        "total_failed": sum(len(v) for v in failed_attempts.values()),
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
    }


# ─── GUI ─────────────────────────────────────────────────────────────────────

DARK_BG      = "#0d1117"
PANEL_BG     = "#161b22"
CARD_BG      = "#1c2128"
BORDER       = "#30363d"
GREEN        = "#3fb950"
RED          = "#f85149"
YELLOW       = "#d29922"
BLUE         = "#58a6ff"
PURPLE       = "#bc8cff"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
FONT_MONO    = ("Consolas", 10)
FONT_UI      = ("Segoe UI", 10)
FONT_TITLE   = ("Segoe UI", 14, "bold")
FONT_SMALL   = ("Segoe UI", 9)


class SSHDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SSH Brute Force Detector")
        self.geometry("1100x720")
        self.configure(bg=DARK_BG)
        self.minsize(900, 600)
        self.resizable(True, True)

        self.log_path = tk.StringVar()
        self.threshold = tk.IntVar(value=5)
        self.results = None

        self._build_ui()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=PANEL_BG, bd=0)
        header.pack(fill="x")
        tk.Frame(header, bg=BORDER, height=1).pack(fill="x", side="bottom")

        inner_header = tk.Frame(header, bg=PANEL_BG, padx=20, pady=14)
        inner_header.pack(fill="x")

        shield = tk.Label(inner_header, text="⚔", font=("Segoe UI", 22), fg=BLUE, bg=PANEL_BG)
        shield.pack(side="left", padx=(0, 10))
        tk.Label(inner_header, text="SSH Brute Force Detector", font=FONT_TITLE, fg=TEXT_PRIMARY, bg=PANEL_BG).pack(side="left")
        tk.Label(inner_header, text="v1.0", font=FONT_SMALL, fg=TEXT_MUTED, bg=PANEL_BG).pack(side="left", padx=(8, 0), anchor="s", pady=(0, 3))

        # Controls bar
        ctrl_bar = tk.Frame(self, bg=CARD_BG, padx=16, pady=12)
        ctrl_bar.pack(fill="x")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # File picker
        tk.Label(ctrl_bar, text="Log File:", font=FONT_UI, fg=TEXT_MUTED, bg=CARD_BG).pack(side="left")
        path_entry = tk.Entry(ctrl_bar, textvariable=self.log_path, width=42,
                              bg="#0d1117", fg=TEXT_PRIMARY, insertbackground=BLUE,
                              relief="flat", font=FONT_MONO, bd=0,
                              highlightthickness=1, highlightcolor=BLUE, highlightbackground=BORDER)
        path_entry.pack(side="left", padx=(8, 4), ipady=4)
        tk.Button(ctrl_bar, text="Browse", command=self._browse,
                  bg=PANEL_BG, fg=BLUE, relief="flat", font=FONT_UI,
                  activebackground=BORDER, activeforeground=BLUE,
                  cursor="hand2", bd=0, padx=10, pady=4).pack(side="left", padx=(0, 16))

        # Threshold
        tk.Label(ctrl_bar, text="Threshold:", font=FONT_UI, fg=TEXT_MUTED, bg=CARD_BG).pack(side="left")
        threshold_spin = tk.Spinbox(ctrl_bar, from_=1, to=9999, textvariable=self.threshold,
                                     width=5, bg=DARK_BG, fg=TEXT_PRIMARY, relief="flat",
                                     font=FONT_UI, buttonbackground=PANEL_BG,
                                     highlightthickness=1, highlightbackground=BORDER, bd=0)
        threshold_spin.pack(side="left", padx=(6, 16), ipady=3)

        # Scan button
        self.scan_btn = tk.Button(ctrl_bar, text="▶  Analyze", command=self._start_scan,
                                   bg=GREEN, fg="#0d1117", relief="flat",
                                   font=("Segoe UI", 10, "bold"), activebackground="#2ea043",
                                   activeforeground="#0d1117", cursor="hand2",
                                   bd=0, padx=16, pady=5)
        self.scan_btn.pack(side="left")

        # Export button
        self.export_btn = tk.Button(ctrl_bar, text="↓  Export", command=self._export,
                                     bg=PANEL_BG, fg=TEXT_MUTED, relief="flat",
                                     font=FONT_UI, activebackground=BORDER, activeforeground=TEXT_PRIMARY,
                                     cursor="hand2", bd=0, padx=12, pady=5,
                                     state="disabled")
        self.export_btn.pack(side="left", padx=(8, 0))

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(self, variable=self.progress_var, maximum=100,
                                         mode="determinate", style="Green.Horizontal.TProgressbar")
        self._style_progress()

        # Status bar
        self.status_var = tk.StringVar(value="Ready — load a log file to begin.")
        status_bar = tk.Frame(self, bg=PANEL_BG)
        status_bar.pack(fill="x", side="bottom")
        tk.Frame(status_bar, bg=BORDER, height=1).pack(fill="x")
        tk.Label(status_bar, textvariable=self.status_var, font=FONT_SMALL,
                 fg=TEXT_MUTED, bg=PANEL_BG, anchor="w", padx=16, pady=6).pack(fill="x")

        # Main pane
        main = tk.Frame(self, bg=DARK_BG)
        main.pack(fill="both", expand=True, padx=16, pady=12)

        # Stat cards row
        self.cards_frame = tk.Frame(main, bg=DARK_BG)
        self.cards_frame.pack(fill="x", pady=(0, 12))
        self._build_stat_cards()

        # Notebook (tabs)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.TNotebook", background=DARK_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab", background=PANEL_BG, foreground=TEXT_MUTED,
                        padding=[14, 6], font=FONT_UI, borderwidth=0)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", CARD_BG)],
                  foreground=[("selected", TEXT_PRIMARY)])

        self.notebook = ttk.Notebook(main, style="Dark.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        # Tab 1 — Attackers
        self.tab_attackers = tk.Frame(self.notebook, bg=CARD_BG)
        self.notebook.add(self.tab_attackers, text=" 🔴  Attackers ")

        # Tab 2 — All Failed
        self.tab_failed = tk.Frame(self.notebook, bg=CARD_BG)
        self.notebook.add(self.tab_failed, text=" 🟡  Failed Logins ")

        # Tab 3 — Successful
        self.tab_success = tk.Frame(self.notebook, bg=CARD_BG)
        self.notebook.add(self.tab_success, text=" 🟢  Successful Logins ")

        # Tab 4 — Raw Log
        self.tab_raw = tk.Frame(self.notebook, bg=CARD_BG)
        self.notebook.add(self.tab_raw, text=" 📄  Raw Log ")

        self._build_attackers_tab()
        self._build_failed_tab()
        self._build_success_tab()
        self._build_raw_tab()

    def _style_progress(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Green.Horizontal.TProgressbar",
                        troughcolor=PANEL_BG, background=GREEN,
                        darkcolor=GREEN, lightcolor=GREEN, bordercolor=PANEL_BG)

    def _build_stat_cards(self):
        self.stat_labels = {}
        cards_data = [
            ("total_lines",   "Lines Parsed",    "📋", BLUE),
            ("total_failed",  "Failed Attempts", "🔴", RED),
            ("attackers",     "Unique IPs",       "🌐", YELLOW),
            ("brute_force",   "Brute Forced",    "⚡", PURPLE),
            ("successful",    "Successful Logins","✅", GREEN),
        ]
        for key, label, icon, color in cards_data:
            card = tk.Frame(self.cards_frame, bg=CARD_BG, padx=16, pady=12,
                            highlightthickness=1, highlightbackground=BORDER)
            card.pack(side="left", fill="x", expand=True, padx=(0, 8))
            tk.Label(card, text=icon, font=("Segoe UI", 18), bg=CARD_BG, fg=color).pack(anchor="w")
            val_lbl = tk.Label(card, text="—", font=("Segoe UI", 22, "bold"), fg=color, bg=CARD_BG)
            val_lbl.pack(anchor="w")
            tk.Label(card, text=label, font=FONT_SMALL, fg=TEXT_MUTED, bg=CARD_BG).pack(anchor="w")
            self.stat_labels[key] = val_lbl

    # ── Tabs ──────────────────────────────────────────────────────────────────

    def _build_attackers_tab(self):
        top = tk.Frame(self.tab_attackers, bg=CARD_BG, padx=8, pady=6)
        top.pack(fill="x")
        tk.Label(top, text="Filter:", font=FONT_UI, fg=TEXT_MUTED, bg=CARD_BG).pack(side="left")
        self.attacker_filter = tk.StringVar()
        self.attacker_filter.trace_add("write", lambda *a: self._filter_attackers())
        filt = tk.Entry(top, textvariable=self.attacker_filter, width=20,
                        bg=DARK_BG, fg=TEXT_PRIMARY, insertbackground=BLUE,
                        relief="flat", font=FONT_MONO, bd=0,
                        highlightthickness=1, highlightcolor=BLUE, highlightbackground=BORDER)
        filt.pack(side="left", padx=(6, 0), ipady=3)

        cols = ("ip", "count", "brute_force", "users_tried", "first_seen", "last_seen")
        self.tree_attackers = self._make_tree(self.tab_attackers, cols,
            ("IP Address", "Failures", "Brute Force?", "Usernames Tried", "First Seen", "Last Seen"),
            (130, 70, 100, 300, 130, 130))
        self.tree_attackers.bind("<Double-1>", self._show_attacker_detail)

    def _build_failed_tab(self):
        cols = ("timestamp", "ip", "user", "line")
        self.tree_failed = self._make_tree(self.tab_failed, cols,
            ("Timestamp", "IP Address", "Username", "Log Line"),
            (130, 130, 120, 500))

    def _build_success_tab(self):
        cols = ("timestamp", "ip", "user", "line")
        self.tree_success = self._make_tree(self.tab_success, cols,
            ("Timestamp", "IP Address", "Username", "Log Line"),
            (130, 130, 120, 500))

    def _build_raw_tab(self):
        frame = tk.Frame(self.tab_raw, bg=CARD_BG)
        frame.pack(fill="both", expand=True, padx=8, pady=8)
        self.raw_text = tk.Text(frame, bg=DARK_BG, fg=TEXT_PRIMARY, font=FONT_MONO,
                                 relief="flat", bd=0, insertbackground=BLUE,
                                 selectbackground=BORDER, wrap="none")
        scrolly = tk.Scrollbar(frame, orient="vertical", command=self.raw_text.yview,
                                bg=PANEL_BG, troughcolor=DARK_BG, activebackground=BORDER)
        scrollx = tk.Scrollbar(frame, orient="horizontal", command=self.raw_text.xview,
                                bg=PANEL_BG, troughcolor=DARK_BG, activebackground=BORDER)
        self.raw_text.configure(yscrollcommand=scrolly.set, xscrollcommand=scrollx.set)
        scrollx.pack(side="bottom", fill="x")
        scrolly.pack(side="right", fill="y")
        self.raw_text.pack(fill="both", expand=True)

        # Tag highlighting
        self.raw_text.tag_configure("failed",  foreground=RED)
        self.raw_text.tag_configure("success", foreground=GREEN)
        self.raw_text.tag_configure("normal",  foreground=TEXT_MUTED)

    def _make_tree(self, parent, cols, headings, widths):
        style = ttk.Style()
        style.configure("Dark.Treeview",
                        background=DARK_BG, foreground=TEXT_PRIMARY,
                        fieldbackground=DARK_BG, rowheight=24,
                        borderwidth=0, font=FONT_MONO)
        style.configure("Dark.Treeview.Heading",
                        background=PANEL_BG, foreground=TEXT_MUTED,
                        borderwidth=0, font=("Segoe UI", 9, "bold"))
        style.map("Dark.Treeview",
                  background=[("selected", BORDER)],
                  foreground=[("selected", TEXT_PRIMARY)])

        frame = tk.Frame(parent, bg=CARD_BG)
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        tree = ttk.Treeview(frame, columns=cols, show="headings", style="Dark.Treeview")
        for col, heading, width in zip(cols, headings, widths):
            tree.heading(col, text=heading, command=lambda c=col, t=tree: self._sort_tree(t, c, False))
            tree.column(col, width=width, minwidth=40)

        scrolly = tk.Scrollbar(frame, orient="vertical", command=tree.yview,
                                bg=PANEL_BG, troughcolor=DARK_BG, activebackground=BORDER)
        scrollx = tk.Scrollbar(frame, orient="horizontal", command=tree.xview,
                                bg=PANEL_BG, troughcolor=DARK_BG, activebackground=BORDER)
        tree.configure(yscrollcommand=scrolly.set, xscrollcommand=scrollx.set)
        scrollx.pack(side="bottom", fill="x")
        scrolly.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select Auth Log",
            filetypes=[("Log Files", "*.log *.txt auth.log syslog *"), ("All Files", "*.*")]
        )
        if path:
            self.log_path.set(path)

    def _start_scan(self):
        path = self.log_path.get().strip()
        if not path:
            messagebox.showwarning("No File", "Please select a log file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Not Found", f"File not found:\n{path}")
            return

        self.scan_btn.configure(state="disabled", text="Analyzing…")
        self.export_btn.configure(state="disabled")
        self.progress.pack(fill="x", before=self.notebook.master)
        self.progress_var.set(0)
        self.status_var.set("Parsing log file…")
        self._clear_all()

        def worker():
            try:
                result = parse_log(
                    path,
                    threshold=self.threshold.get(),
                    progress_cb=self._progress_cb
                )
                self.after(0, self._render_results, result)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, self._reset_btn)

        threading.Thread(target=worker, daemon=True).start()

    def _progress_cb(self, done, total):
        pct = (done / total * 100) if total else 0
        self.after(0, lambda: self.progress_var.set(pct))
        self.after(0, lambda: self.status_var.set(f"Parsing… {done:,} / {total:,} lines"))

    def _render_results(self, result):
        self.results = result
        attackers = result["attackers"]
        brute_ips = [ip for ip, d in attackers.items() if d["is_brute_force"]]

        # Stat cards
        self.stat_labels["total_lines"].config(text=f"{result['total_lines']:,}")
        self.stat_labels["total_failed"].config(text=f"{result['total_failed']:,}")
        self.stat_labels["attackers"].config(text=f"{len(attackers):,}")
        self.stat_labels["brute_force"].config(text=f"{len(brute_ips):,}")
        self.stat_labels["successful"].config(text=f"{len(result['successful_logins']):,}")

        # Attackers tree
        for ip, data in sorted(attackers.items(), key=lambda x: -x[1]["count"]):
            bf_label = "⚡ YES" if data["is_brute_force"] else "No"
            tag = "brute" if data["is_brute_force"] else ""
            self.tree_attackers.insert("", "end",
                values=(ip, data["count"], bf_label,
                        ", ".join(data["users_tried"][:8]),
                        data["first_seen"], data["last_seen"]),
                tags=(tag,))

        self.tree_attackers.tag_configure("brute", foreground=RED)

        # Failed logins tree
        for ip, data in attackers.items():
            for attempt in data["attempts"]:
                self.tree_failed.insert("", "end",
                    values=(attempt["timestamp"], ip, attempt["user"], attempt["line"]))

        # Successful logins tree
        for login in result["successful_logins"]:
            self.tree_success.insert("", "end",
                values=(login["timestamp"], login["ip"], login["user"], login["line"]))

        # Raw log with color
        path = self.log_path.get()
        self.raw_text.configure(state="normal")
        with open(path, "r", errors="replace") as f:
            for line in f:
                if any(p.search(line) for p in FAILED_PATTERNS):
                    tag = "failed"
                elif any(p.search(line) for p in SUCCESS_PATTERNS):
                    tag = "success"
                else:
                    tag = "normal"
                self.raw_text.insert("end", line, tag)
        self.raw_text.configure(state="disabled")

        self.progress.pack_forget()
        self.status_var.set(
            f"Done — {result['total_lines']:,} lines parsed | "
            f"{result['total_failed']:,} failed attempts | "
            f"{len(brute_ips)} brute-force IPs detected"
        )
        self.export_btn.configure(state="normal")
        self._reset_btn()

    def _clear_all(self):
        for tree in (self.tree_attackers, self.tree_failed, self.tree_success):
            tree.delete(*tree.get_children())
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", "end")
        self.raw_text.configure(state="disabled")

    def _reset_btn(self):
        self.scan_btn.configure(state="normal", text="▶  Analyze")

    def _filter_attackers(self):
        if not self.results:
            return
        query = self.attacker_filter.get().lower()
        for item in self.tree_attackers.get_children():
            vals = self.tree_attackers.item(item, "values")
            visible = query in " ".join(str(v).lower() for v in vals)
            if not visible:
                self.tree_attackers.detach(item)
            else:
                self.tree_attackers.reattach(item, "", "end")

    def _sort_tree(self, tree, col, reverse):
        data = [(tree.set(k, col), k) for k in tree.get_children("")]
        try:
            data.sort(key=lambda x: int(x[0]), reverse=reverse)
        except ValueError:
            data.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for i, (_, k) in enumerate(data):
            tree.move(k, "", i)
        tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

    def _show_attacker_detail(self, event):
        tree = self.tree_attackers
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        ip = vals[0]
        if not self.results or ip not in self.results["attackers"]:
            return
        data = self.results["attackers"][ip]

        win = tk.Toplevel(self, bg=DARK_BG)
        win.title(f"Detail — {ip}")
        win.geometry("720x480")
        win.configure(bg=DARK_BG)

        tk.Label(win, text=f"🔍  {ip}", font=FONT_TITLE, fg=RED if data["is_brute_force"] else YELLOW,
                 bg=DARK_BG).pack(padx=20, pady=(16, 4), anchor="w")
        info = (f"Total failures: {data['count']}   |   "
                f"Brute force: {'YES ⚡' if data['is_brute_force'] else 'No'}   |   "
                f"Usernames tried: {len(data['users_tried'])}")
        tk.Label(win, text=info, font=FONT_UI, fg=TEXT_MUTED, bg=DARK_BG).pack(padx=20, anchor="w")

        txt = tk.Text(win, bg=PANEL_BG, fg=TEXT_PRIMARY, font=FONT_MONO,
                      relief="flat", bd=0, padx=10, pady=10)
        txt.pack(fill="both", expand=True, padx=16, pady=12)
        for a in data["attempts"]:
            txt.insert("end", f"{a['timestamp']}  user={a['user']}\n  {a['line']}\n\n")
        txt.configure(state="disabled")

    def _export(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("CSV", "*.csv")]
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                f.write("SSH BRUTE FORCE DETECTION REPORT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Log file: {self.log_path.get()}\n")
                f.write(f"Threshold: {self.threshold.get()} attempts\n")
                f.write("=" * 60 + "\n\n")

                r = self.results
                f.write(f"Total lines parsed : {r['total_lines']:,}\n")
                f.write(f"Total failed logins: {r['total_failed']:,}\n")
                f.write(f"Unique IPs flagged : {len(r['attackers']):,}\n")
                brute = [ip for ip, d in r['attackers'].items() if d['is_brute_force']]
                f.write(f"Brute force IPs    : {len(brute)}\n")
                f.write(f"Successful logins  : {len(r['successful_logins'])}\n\n")

                f.write("=== BRUTE FORCE ATTACKERS ===\n")
                for ip in sorted(brute, key=lambda x: -r['attackers'][x]['count']):
                    d = r['attackers'][ip]
                    f.write(f"\nIP: {ip}  |  Attempts: {d['count']}  |  "
                            f"First: {d['first_seen']}  |  Last: {d['last_seen']}\n")
                    f.write(f"  Usernames tried: {', '.join(d['users_tried'])}\n")

                f.write("\n=== SUCCESSFUL LOGINS ===\n")
                for s in r['successful_logins']:
                    f.write(f"  {s['timestamp']}  user={s['user']}  ip={s['ip']}\n")

            messagebox.showinfo("Exported", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


if __name__ == "__main__":
    app = SSHDetectorApp()
    app.mainloop()
