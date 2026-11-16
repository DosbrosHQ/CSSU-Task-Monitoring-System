"""
CSSU Indicators Monitoring
Desktop application: Tkinter + SQLite + Matplotlib + xlwt (.xls export)

Run:
    python -m pip install -r requirements.txt
    python cssu_monitor.py

Default first-run administrator:
    Username: admin
    Password: ChangeMe123!

IMPORTANT:
- Change the default admin password immediately.
- Use staff codes/usernames rather than patient names or other patient-identifying data.
- This starter application is intended for a local, single-workstation deployment.
  For simultaneous multi-workstation use, deploy a shared server/database with IT/security review.
"""
import os
import sqlite3
import hashlib
import secrets
import hmac
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, date
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "cssu_monitor.db"
STATUSES = ("Completed", "Ongoing", "Pending", "Unresolved", "Cancelled")
PRIORITIES = ("Low", "Normal", "High", "Urgent")


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                     bytes.fromhex(salt_hex), 240_000).hex()
        return hmac.compare_digest(actual, digest_hex)
    except Exception:
        return False


class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.setup()

    def setup(self):
        c = self.conn.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','staff')),
            password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS categories(
            id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS task_options(
            id INTEGER PRIMARY KEY, category_id INTEGER NOT NULL,
            task_name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
            indicator_type TEXT NOT NULL DEFAULT 'regular', notes TEXT DEFAULT '',
            FOREIGN KEY(category_id) REFERENCES categories(id)
        );
        CREATE TABLE IF NOT EXISTS task_logs(
            id INTEGER PRIMARY KEY, staff_id INTEGER NOT NULL, task_date TEXT NOT NULL,
            category_id INTEGER, task_option_id INTEGER, task_title TEXT NOT NULL,
            quantity REAL DEFAULT 0, status TEXT NOT NULL, priority TEXT NOT NULL,
            start_time TEXT, end_time TEXT, details TEXT, issue TEXT,
            endorsement TEXT, endorsed_to TEXT, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(staff_id) REFERENCES users(id),
            FOREIGN KEY(category_id) REFERENCES categories(id),
            FOREIGN KEY(task_option_id) REFERENCES task_options(id)
        );
        CREATE TABLE IF NOT EXISTS delegated_tasks(
            id INTEGER PRIMARY KEY, title TEXT NOT NULL, category_id INTEGER,
            assigned_to INTEGER NOT NULL, assigned_by INTEGER NOT NULL,
            assigned_date TEXT NOT NULL, due_date TEXT, priority TEXT NOT NULL DEFAULT 'Normal',
            instructions TEXT, status TEXT NOT NULL DEFAULT 'Assigned', completion_note TEXT,
            started_at TEXT, completed_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            FOREIGN KEY(category_id) REFERENCES categories(id),
            FOREIGN KEY(assigned_to) REFERENCES users(id),
            FOREIGN KEY(assigned_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL,
            record_type TEXT, record_id INTEGER, timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        self.conn.commit()
        if not self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            self.conn.execute(
                "INSERT INTO users(username,full_name,role,password_hash,created_at) VALUES(?,?,?,?,?)",
                ("admin", "CSSU Administrator", "admin", hash_password("ChangeMe123!"),
                 datetime.now().isoformat(timespec="seconds")))
        # Keep the uploaded category/indicator library synchronized on startup.
        # Admin indicators are available only to administrator accounts.
        defaults = {
            "Strategic Functions": [
                ("Attended Information Dissemination", "admin", "Attended the dissemination of information in the conducted monthly meeting of non-clinical nursing units per semester"),
                ("Attended Strategic Monitoring", "regular", "Attended the scheduled monthly strategic monitoring for non-clinical nursing units and cascaded relevant information during the area monthly meetings within the prescribed timeline."),
            ],
            "Core Functions": [
                ("Attended Information Dissemination", "regular", "Attended the dissemination of information in the conducted monthly meeting of Nurse supervisor per semester"),
                ("Attend LDI", "regular", "Attending in at least one (1) Leadership Development Initiative (LDI) per semester, with complete documentation properly filed."),
                ("Create and Submit Monthly Inventory", "regular", "Creation and submission of duly signed monthly inventory reports within the set deadlines, with no identified errors."),
                ("Preparation and Release of Supplies", "regular", "Ensure 100% accuracy in the preparation and release of all available medical supplies requested via Medix System and RIS forms, with no recorded discrepancies"),
                ("Reproduction of Forms", "regular", "Ensure the reproduction of hospital-coded forms within the given timeline."),
                ("Consolidation of NBB attachments", "regular", "Ensure timely and accurate (100%) consolidation of NBB attachments, with no identified discrepancies, within the given timeframe"),
                ("Request through Wish System", "regular", "Maintain 100% accuracy in the requisition and collection of medical supplies requested through the WISH system, with zero recorded discrepancies."),
                ("Participation in NPIS Phase 2", "regular", "Participation in the implementation of NPIS Phase 2 in the unit within the given timeline"),
                ("Sterilization for Medical Instruments", "regular", "Sterilization procedures for all medical instruments were completed within the defined timeframe in accordance with established standards."),
                ("Monitor Reported Incidents", "admin", "100% monitoring and documentation of all identified reportable incidents were completed within the specified timeframe."),
                ("Incidents Reported", "admin", "All identified reportable incidents are documented within the prescribed timeframe"),
                ("Attend Nurse Supervisors Meeting", "admin", "Attended all the monthly meetings of the Nurse Supervisors conducted by the Nursing Service Division within the semester."),
                ("PPMP Consolidation", "admin", "Consolidation and submission of duly signed Indicative PPMP of the Nursing Service Division for 2027 within the prescribed timeline"),
                ("Standard Registry for Medical Supplies", "admin", "Creation and submission of approved standardized registry for medical supplies within the prescribed timeline."),
                ("Submit Documents for RFAs", "admin", "Ensuring the timely compliance and submission of all required documents for RFAs within the given timeline"),
                ("Monitor Compliance of staff in NPIS Phase 2", "admin", "Monitoring of staff compliance in the implementation of NPIS Phase 2 in the unit within the prescribed period"),
                ("Monitor Inventory Reports", "admin", "Monitoring of submitted duly signed inventory reports within the given timeline."),
                ("Monitor Signed Monthly Schedule", "admin", "Monitoring of submitted of duly signed monthly schedules for the non-clinical nursing units within the semester."),
                ("Monitor Reproduction of Froms", "admin", "Monitoring the accuracy and complete reproduction of controlled hospital forms throughout the semester"),
                ("Monitor Entries on WISH Systems", "admin", "Monitoring the completeness and quality of medical supplies collected through the WISH system"),
                ("Monitor Supplies on Medix and RIS", "admin", "Monitoring the completeness of requested medical supplies through Medix System and RIS form and released with no recorded discrepancies"),
                ("Monitor Staff Involvement in LDI", "admin", "Participation in and monitoring staff involvement in at least one (1) Leadership Development Initiative (LDI) per semester with complete documentation on file"),
                ("Submit Monthly Schedule", "admin", "Prepared and submitted duly signed monthly schedules for the units within the prescribed timeline."),
                ("Submit Signed NBB", "admin", "Submission of duly signed documents and monitoring of at least one (1) NBB fund replenishment within the semester."),
            ],
            "Support Functions": [
                ("Monitor Submitted Documents", "admin", "Monitoring of staff adherence to the submission of all mandatory statutory and regulatory documents with no corrections required within the given period."),
                ("Submitted Precise Documents", "regular", "Submission of mandatory statutory and regulatory documents was completed within the semester with no corrections needed."),
            ],
        }
        # Migrate databases created by earlier versions of the application.
        option_columns = {r[1] for r in self.conn.execute("PRAGMA table_info(task_options)").fetchall()}
        if "indicator_type" not in option_columns:
            self.conn.execute("ALTER TABLE task_options ADD COLUMN indicator_type TEXT NOT NULL DEFAULT 'regular'")
        if "notes" not in option_columns:
            self.conn.execute("ALTER TABLE task_options ADD COLUMN notes TEXT DEFAULT ''")

        legacy_categories = ["Receiving and Decontamination", "Preparation and Packaging", "Sterilization",
                             "Storage and Distribution", "Quality and Safety", "Other CSSU Activities"]
        for legacy in legacy_categories:
            self.conn.execute("UPDATE categories SET active=0 WHERE name=?", (legacy,))

        for category_name, indicators in defaults.items():
            row = self.conn.execute("SELECT id FROM categories WHERE name=?", (category_name,)).fetchone()
            if row:
                cid = row["id"]
                self.conn.execute("UPDATE categories SET active=1 WHERE id=?", (cid,))
            else:
                cur = self.conn.execute("INSERT INTO categories(name) VALUES(?)", (category_name,))
                cid = cur.lastrowid
            for indicator_name, indicator_type, indicator_notes in indicators:
                existing = self.conn.execute(
                    "SELECT id FROM task_options WHERE category_id=? AND task_name=?",
                    (cid, indicator_name)).fetchone()
                if existing:
                    self.conn.execute(
                        "UPDATE task_options SET active=1, indicator_type=?, "
                        "notes=CASE WHEN COALESCE(notes,'')='' THEN ? ELSE notes END WHERE id=?",
                        (indicator_type, indicator_notes, existing["id"]))
                else:
                    self.conn.execute(
                        "INSERT INTO task_options(category_id,task_name,indicator_type,notes) VALUES(?,?,?,?)",
                        (cid, indicator_name, indicator_type, indicator_notes))
        self.conn.commit()

    def audit(self, user_id, action, record_type=None, record_id=None):
        self.conn.execute("INSERT INTO audit_log(user_id,action,record_type,record_id,timestamp) VALUES(?,?,?,?,?)",
                          (user_id, action, record_type, record_id, datetime.now().isoformat(timespec="seconds")))
        self.conn.commit()

    def rows(self, sql, params=()):
        return self.conn.execute(sql, params).fetchall()

    def close(self):
        self.conn.close()


class CSSUApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CSSU Indicators Monitoring")
        self.geometry("1280x800")
        self.minsize(1050, 680)
        self.db = Database()
        self.user = None
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.style.configure("Header.TLabel", font=("Arial", 19, "bold"), foreground="#17365D")
        self.style.configure("Sub.TLabel", font=("Arial", 10), foreground="#526477")
        self.style.configure("Treeview", rowheight=27, font=("Arial", 9))
        self.style.configure("Treeview.Heading", font=("Arial", 9, "bold"))
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.show_login()

    def on_close(self):
        self.db.close()
        self.destroy()

    def clear(self):
        for w in self.winfo_children():
            w.destroy()

    def show_login(self):
        self.clear()
        outer = ttk.Frame(self, padding=35)
        outer.place(relx=.5, rely=.48, anchor="center")
        ttk.Label(outer, text="CSSU", style="Header.TLabel").pack(pady=(0, 3))
        ttk.Label(outer, text="INDICATORS MONITORING", font=("Arial", 11, "bold")).pack()
        ttk.Label(outer, text="Daily output • Endorsement • Monthly appraisal", style="Sub.TLabel").pack(pady=(4, 22))
        form = ttk.Frame(outer, padding=22, relief="ridge")
        form.pack(fill="x")
        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="w", pady=7)
        self.login_user = ttk.Entry(form, width=32)
        self.login_user.grid(row=0, column=1, pady=7, padx=10)
        ttk.Label(form, text="Password").grid(row=1, column=0, sticky="w", pady=7)
        self.login_pass = ttk.Entry(form, width=32, show="•")
        self.login_pass.grid(row=1, column=1, pady=7, padx=10)
        ttk.Button(form, text="Sign in", command=self.login).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(14, 3))
        self.login_pass.bind("<Return>", lambda e: self.login())
        self.login_user.focus_set()

    def login(self):
        username, password = self.login_user.get().strip(), self.login_pass.get()
        row = self.db.conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            messagebox.showerror("Sign in failed", "Username or password is incorrect.")
            return
        self.user = dict(row)
        self.db.audit(row["id"], "Signed in")
        self.show_main()

    def show_main(self):
        self.clear()
        top = ttk.Frame(self, padding=(18, 13))
        top.pack(fill="x")
        ttk.Label(top, text="CSSU Indicators Monitoring", style="Header.TLabel").pack(side="left")
        ttk.Label(top, text=f"{self.user['full_name']}  |  {self.user['role'].upper()}",
                  style="Sub.TLabel").pack(side="right", padx=12)
        bar = ttk.Frame(self, padding=(15, 0, 15, 8))
        bar.pack(fill="x")
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.dashboard_tab = ttk.Frame(self.tabs, padding=12)
        self.entry_tab = ttk.Frame(self.tabs, padding=12)
        self.history_tab = ttk.Frame(self.tabs, padding=12)
        self.assignments_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.assignments_tab, text="My Assignments" if self.user["role"] == "staff" else "Delegated Tasks")
        self.tabs.add(self.entry_tab, text="Indicator Entry")
        self.tabs.add(self.history_tab, text="Indicator Records")
        if self.user["role"] == "admin":
            self.admin_tab = ttk.Frame(self.tabs, padding=12)
            self.tabs.add(self.admin_tab, text="Administration")
            self.build_admin()
        self.build_dashboard()
        self.build_assignments()
        self.build_entry()
        self.build_history()
        ttk.Button(bar, text="Change Password", command=self.change_password).pack(side="right")
        ttk.Button(bar, text="Sign out", command=self.logout).pack(side="right", padx=7)

    def logout(self):
        self.db.audit(self.user["id"], "Signed out")
        self.user = None
        self.show_login()

    def change_password(self):
        win = tk.Toplevel(self)
        win.title("Change Password")
        win.transient(self)
        win.grab_set()
        f = ttk.Frame(win, padding=18); f.pack()
        entries = []
        for i, label in enumerate(("Current password", "New password", "Confirm new password")):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", pady=6)
            e = ttk.Entry(f, show="•", width=28); e.grid(row=i, column=1, padx=8, pady=6); entries.append(e)
        def save():
            old, new, confirm = [e.get() for e in entries]
            if not verify_password(old, self.user["password_hash"]):
                messagebox.showerror("Error", "Current password is incorrect.", parent=win); return
            if len(new) < 10 or new != confirm:
                messagebox.showerror("Error", "New passwords must match and contain at least 10 characters.", parent=win); return
            new_hash = hash_password(new)
            self.db.conn.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, self.user["id"]))
            self.db.conn.commit()
            self.user["password_hash"] = new_hash
            self.db.audit(self.user["id"], "Changed password")
            messagebox.showinfo("Saved", "Password updated.", parent=win); win.destroy()
        ttk.Button(f, text="Save password", command=save).grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)

    def build_dashboard(self):
        for w in self.dashboard_tab.winfo_children(): w.destroy()
        head = ttk.Frame(self.dashboard_tab); head.pack(fill="x")
        ttk.Label(head, text="Unit and Staff Dashboard", font=("Arial", 15, "bold")).pack(side="left")
        ttk.Label(head, text="Month (YYYY-MM):").pack(side="left", padx=(25, 5))
        self.dash_month = tk.StringVar(value=date.today().strftime("%Y-%m"))
        ttk.Entry(head, textvariable=self.dash_month, width=10).pack(side="left")
        ttk.Button(head, text="Refresh", command=self.refresh_dashboard).pack(side="left", padx=6)
        self.kpi_frame = ttk.Frame(self.dashboard_tab); self.kpi_frame.pack(fill="x", pady=15)
        self.chart_frame = ttk.Frame(self.dashboard_tab); self.chart_frame.pack(fill="both", expand=True)
        self.refresh_dashboard()

    def refresh_dashboard(self):
        month = self.dash_month.get().strip()
        if len(month) != 7 or month[4] != "-":
            messagebox.showwarning("Invalid month", "Use YYYY-MM format."); return
        params = [month + "%"]
        where = "WHERE l.task_date LIKE ?"
        if self.user["role"] != "admin":
            where += " AND l.staff_id=?"; params.append(self.user["id"])
        rows = self.db.rows(f"SELECT l.*,u.full_name FROM task_logs l JOIN users u ON u.id=l.staff_id {where}", params)
        total = len(rows)
        completed = sum(r["status"] == "Completed" for r in rows)
        unresolved = sum(r["status"] in ("Unresolved", "Pending") for r in rows)
        ongoing = sum(r["status"] == "Ongoing" for r in rows)
        for w in self.kpi_frame.winfo_children(): w.destroy()
        if self.user["role"] == "admin":
            open_assignments = self.db.conn.execute("SELECT COUNT(*) FROM delegated_tasks WHERE status IN ('Assigned','In Progress')").fetchone()[0]
        else:
            open_assignments = self.db.conn.execute("SELECT COUNT(*) FROM delegated_tasks WHERE assigned_to=? AND status IN ('Assigned','In Progress')", (self.user["id"],)).fetchone()[0]
        cards = [("Total indicators logged", total), ("Completed", completed), ("Ongoing", ongoing),
                 ("Pending / unresolved", unresolved), ("Open delegated tasks", open_assignments)]
        for label, value in cards:
            card = ttk.LabelFrame(self.kpi_frame, text=label, padding=14); card.pack(side="left", fill="x", expand=True, padx=5)
            ttk.Label(card, text=str(value), font=("Arial", 22, "bold")).pack()
        for w in self.chart_frame.winfo_children(): w.destroy()
        try:
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            fig = Figure(figsize=(9, 4.4), dpi=95)
            ax1 = fig.add_subplot(121)
            status_counts = {s: sum(r["status"] == s for r in rows) for s in STATUSES}
            labels = [k for k,v in status_counts.items() if v]
            values = [v for v in status_counts.values() if v]
            if values: ax1.pie(values, labels=labels, autopct="%1.0f%%", startangle=90)
            else: ax1.text(.5,.5,"No indicator data",ha="center",va="center")
            ax1.set_title("Indicator status")
            ax2 = fig.add_subplot(122)
            staff_counts = {}
            for r in rows: staff_counts[r["full_name"]] = staff_counts.get(r["full_name"], 0) + 1
            if staff_counts:
                names = list(staff_counts.keys())[:12]
                vals = [staff_counts[n] for n in names]
                ax2.barh(names[::-1], vals[::-1])
            else: ax2.text(.5,.5,"No indicator data",ha="center",va="center")
            ax2.set_title("Indicators logged by staff")
            fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)
        except ImportError:
            ttk.Label(self.chart_frame, text="Install matplotlib to display charts: pip install matplotlib").pack()
        summary = ttk.Label(self.dashboard_tab,
            text="Counts reflect encoded tasks, not a validated productivity score. Review workload, task complexity, quality and staffing context before appraisal.",
            foreground="#76521B", wraplength=1000)
        summary.pack(anchor="w", pady=(8, 0))

    def build_assignments(self):
        for w in self.assignments_tab.winfo_children():
            w.destroy()
        top = ttk.Frame(self.assignments_tab); top.pack(fill="x", pady=(0, 8))
        title = "All Delegated Tasks" if self.user["role"] == "admin" else "Tasks Assigned to Me"
        ttk.Label(top, text=title, font=("Arial", 15, "bold")).pack(side="left")
        ttk.Button(top, text="Refresh", command=self.refresh_assignments).pack(side="right")
        ttk.Label(self.assignments_tab,
            text="Staff: select an assignment and update progress or submit completion notes. Administrators can review all delegated tasks.",
            foreground="#526477", wraplength=1050).pack(anchor="w", pady=(0, 8))
        cols=("id","title","staff","assigned","due","priority","status")
        self.assignment_tree=ttk.Treeview(self.assignments_tab,columns=cols,show="headings",height=13)
        headings={"id":"ID","title":"Task","staff":"Assigned To","assigned":"Assigned Date","due":"Due Date","priority":"Priority","status":"Status"}
        widths={"id":55,"title":340,"staff":190,"assigned":110,"due":110,"priority":90,"status":130}
        for c in cols:
            self.assignment_tree.heading(c,text=headings[c]); self.assignment_tree.column(c,width=widths[c],anchor="w")
        self.assignment_tree.pack(fill="both",expand=True)
        actions=ttk.Frame(self.assignments_tab); actions.pack(fill="x",pady=8)
        if self.user["role"] == "staff":
            ttk.Button(actions,text="Update Selected Assignment",command=self.update_assignment).pack(side="right")
        else:
            ttk.Label(actions,text="Create assignments under Administration → Task Delegation.",foreground="#526477").pack(side="left")
        self.refresh_assignments()

    def refresh_assignments(self):
        if not hasattr(self,"assignment_tree"): return
        for item in self.assignment_tree.get_children(): self.assignment_tree.delete(item)
        sql="SELECT d.*,u.full_name AS staff_name FROM delegated_tasks d JOIN users u ON u.id=d.assigned_to"
        params=[]
        if self.user["role"] != "admin":
            sql += " WHERE d.assigned_to=?"; params.append(self.user["id"])
        sql += " ORDER BY CASE d.status WHEN 'Assigned' THEN 0 WHEN 'In Progress' THEN 1 ELSE 2 END, COALESCE(d.due_date,'9999-12-31'), d.id DESC"
        for r in self.db.rows(sql,params):
            self.assignment_tree.insert("","end",iid=str(r["id"]),values=(r["id"],r["title"],r["staff_name"],r["assigned_date"],r["due_date"] or "",r["priority"],r["status"]))

    def update_assignment(self):
        selected=self.assignment_tree.selection()
        if not selected:
            messagebox.showwarning("Select assignment","Select an assigned task first."); return
        task_id=int(selected[0])
        row=self.db.conn.execute("SELECT * FROM delegated_tasks WHERE id=? AND assigned_to=?",(task_id,self.user["id"])).fetchone()
        if not row:
            messagebox.showerror("Not allowed","You can only update tasks assigned to your account."); return
        win=tk.Toplevel(self); win.title("Update Assigned Task"); win.transient(self); win.grab_set()
        f=ttk.Frame(win,padding=16); f.pack(fill="both",expand=True)
        ttk.Label(f,text=row["title"],font=("Arial",12,"bold"),wraplength=520).pack(anchor="w",pady=(0,8))
        if row["due_date"]: ttk.Label(f,text=f"Due date: {row['due_date']}").pack(anchor="w")
        if row["instructions"]: ttk.Label(f,text=f"Notes: {row['instructions']}",wraplength=520).pack(anchor="w",pady=6)
        status=tk.StringVar(value=row["status"])
        ttk.Label(f,text="Progress status").pack(anchor="w",pady=(8,2))
        ttk.Combobox(f,textvariable=status,values=("Assigned","In Progress","Completed","Unable to Complete"),state="readonly",width=28).pack(anchor="w")
        ttk.Label(f,text="Completion note / issue / handover (required when completing or unable to complete)").pack(anchor="w",pady=(10,2))
        note=tk.Text(f,height=5,width=66,wrap="word"); note.pack(fill="both",expand=True); note.insert("1.0",row["completion_note"] or "")
        def save():
            new_status=status.get(); completion_note=note.get("1.0","end").strip()
            if new_status in ("Completed","Unable to Complete") and not completion_note:
                messagebox.showwarning("Note required","Enter a completion note or explain why the task could not be completed.",parent=win); return
            now=datetime.now().isoformat(timespec="seconds"); started=row["started_at"]; completed=row["completed_at"]
            if new_status=="In Progress" and not started: started=now
            if new_status=="Completed": completed=now
            else: completed=None
            self.db.conn.execute("UPDATE delegated_tasks SET status=?,completion_note=?,started_at=?,completed_at=?,updated_at=? WHERE id=? AND assigned_to=?",
                (new_status,completion_note,started,completed,now,task_id,self.user["id"]))
            self.db.conn.commit(); self.db.audit(self.user["id"],f"Updated delegated task: {new_status}","delegated_task",task_id)
            win.destroy(); self.refresh_assignments(); self.refresh_dashboard()
            messagebox.showinfo("Assignment updated","Your progress has been saved.")
        ttk.Button(f,text="Save Progress",command=save).pack(anchor="e",pady=(10,0))

    def build_delegation_admin(self):
        f=self.delegation_admin
        ttk.Label(f,text="Delegate a task to a staff member",font=("Arial",12,"bold")).pack(anchor="w")
        form=ttk.Frame(f); form.pack(fill="x",pady=10)
        self.del_staff_var=tk.StringVar(); self.del_indicator_var=tk.StringVar()
        self.del_category_var=tk.StringVar(value="No category"); self.del_due_var=tk.StringVar(value=date.today().isoformat())
        self.del_priority_var=tk.StringVar(value="Normal")
        staff=self.db.rows("SELECT id,full_name FROM users WHERE role='staff' AND active=1 ORDER BY full_name")
        self.delegate_staff_map={r["full_name"]:r["id"] for r in staff}
        ttk.Label(form,text="Assign to").grid(row=0,column=0,sticky="w",padx=5,pady=3)
        self.delegate_staff_combo=ttk.Combobox(form,textvariable=self.del_staff_var,values=list(self.delegate_staff_map),state="readonly",width=32)
        self.delegate_staff_combo.grid(row=1,column=0,sticky="ew",padx=5,pady=3)
        if staff: self.del_staff_var.set(staff[0]["full_name"])
        cats=self.db.rows("SELECT id,name FROM categories WHERE active=1 ORDER BY name")
        self.delegate_category_map={"No category":None}; self.delegate_category_map.update({r["name"]:r["id"] for r in cats})
        ttk.Label(form,text="Category (optional)").grid(row=2,column=0,sticky="w",padx=5,pady=3)
        self.delegate_category_combo=ttk.Combobox(form,textvariable=self.del_category_var,values=list(self.delegate_category_map),state="readonly",width=32)
        self.delegate_category_combo.grid(row=3,column=0,sticky="ew",padx=5,pady=3)
        self.delegate_category_combo.bind("<<ComboboxSelected>>",lambda e:self.refresh_delegation_indicators())
        ttk.Label(form,text="Indicator").grid(row=0,column=1,sticky="w",padx=5,pady=3)
        self.delegate_indicator_combo=ttk.Combobox(form,textvariable=self.del_indicator_var,state="readonly",width=42)
        self.delegate_indicator_combo.grid(row=1,column=1,sticky="ew",padx=5,pady=3)
        self.delegate_indicator_combo.bind("<<ComboboxSelected>>", self.update_delegation_notes)
        self.refresh_delegation_indicators()
        ttk.Label(form,text="Due date (YYYY-MM-DD)").grid(row=2,column=1,sticky="w",padx=5,pady=3)
        ttk.Entry(form,textvariable=self.del_due_var,width=42).grid(row=3,column=1,sticky="ew",padx=5,pady=3)
        ttk.Label(form,text="Priority").grid(row=4,column=0,sticky="w",padx=5,pady=3)
        ttk.Combobox(form,textvariable=self.del_priority_var,values=PRIORITIES,state="readonly",width=32).grid(row=5,column=0,sticky="ew",padx=5,pady=3)
        form.columnconfigure(0,weight=1); form.columnconfigure(1,weight=1)
        ttk.Label(f,text="Notes").pack(anchor="w",pady=(6,2))
        self.del_instructions=tk.Text(f,height=4,wrap="word"); self.del_instructions.pack(fill="x")
        ttk.Button(f,text="Delegate Indicator",command=self.create_delegated_task).pack(anchor="e",pady=8)
        ttk.Label(f,text="Assignments appear in the staff member's My Assignments tab and open-task dashboard count.",foreground="#526477",wraplength=1000).pack(anchor="w")
        ttk.Label(f,text="Existing delegations (select one to delete)",font=("Arial",10,"bold")).pack(anchor="w",pady=(12,4))
        self.delegation_tree=ttk.Treeview(f,columns=("id","indicator","staff","assigned","status"),show="headings",height=7)
        for col,label,width in (("id","ID",50),("indicator","Indicator",360),("staff","Assigned to",200),("assigned","Assigned date",120),("status","Status",130)):
            self.delegation_tree.heading(col,text=label); self.delegation_tree.column(col,width=width,anchor="w")
        self.delegation_tree.pack(fill="both",expand=True)
        ttk.Button(f,text="Delete selected delegation",command=self.delete_delegation).pack(anchor="e",pady=6)
        self.refresh_delegation_admin()

    def refresh_delegation_admin(self):
        if not hasattr(self, "delegation_tree"):
            return
        for item in self.delegation_tree.get_children():
            self.delegation_tree.delete(item)
        rows = self.db.rows(
            "SELECT d.id,d.title,u.full_name,d.assigned_date,d.status "
            "FROM delegated_tasks d JOIN users u ON u.id=d.assigned_to ORDER BY d.id DESC")
        for r in rows:
            self.delegation_tree.insert("", "end", iid=str(r["id"]),
                values=(r["id"], r["title"], r["full_name"], r["assigned_date"], r["status"]))

    def delete_delegation(self):
        sel = self.delegation_tree.selection()
        if not sel:
            messagebox.showwarning("Select delegation", "Select a delegation first.")
            return
        delegation_id = int(sel[0])
        row = self.db.conn.execute("SELECT title FROM delegated_tasks WHERE id=?", (delegation_id,)).fetchone()
        if not row:
            return
        if not messagebox.askyesno("Confirm deletion",
                f"Permanently delete delegation '{row['title']}'? This cannot be undone."):
            return
        self.db.conn.execute("DELETE FROM delegated_tasks WHERE id=?", (delegation_id,))
        self.db.conn.commit()
        self.db.audit(self.user["id"], "Deleted delegation", "delegated_task", delegation_id)
        self.refresh_delegation_admin()
        self.refresh_assignments()
        self.refresh_dashboard()

    def refresh_delegation_indicators(self):
        if not hasattr(self, "delegate_indicator_combo"):
            return
        category_id = self.delegate_category_map.get(self.del_category_var.get())
        if category_id:
            rows = self.db.rows(
                "SELECT id,task_name,notes FROM task_options WHERE category_id=? AND active=1 AND indicator_type='regular' ORDER BY task_name",
                (category_id,))
        else:
            rows = self.db.rows(
                "SELECT id,task_name,notes FROM task_options WHERE active=1 AND indicator_type='regular' ORDER BY task_name")
        self.delegate_indicator_map = {r["task_name"]: r["id"] for r in rows}
        self.delegate_indicator_notes = {r["task_name"]: (r["notes"] or "") for r in rows}
        self.delegate_indicator_combo["values"] = list(self.delegate_indicator_map)
        if self.del_indicator_var.get() not in self.delegate_indicator_map:
            self.del_indicator_var.set(rows[0]["task_name"] if rows else "")
        self.update_delegation_notes()

    def update_delegation_notes(self, event=None):
        if not hasattr(self, "del_instructions"):
            return
        note = getattr(self, "delegate_indicator_notes", {}).get(self.del_indicator_var.get(), "")
        self.del_instructions.delete("1.0", "end")
        if note:
            self.del_instructions.insert("1.0", note)

    def create_delegated_task(self):
        staff_id=self.delegate_staff_map.get(self.del_staff_var.get()); title=self.del_indicator_var.get().strip()
        due_date=self.del_due_var.get().strip(); category_id=self.delegate_category_map.get(self.del_category_var.get())
        if not staff_id:
            messagebox.showerror("Select staff","Select an active staff account."); return
        if not title:
            messagebox.showerror("Missing indicator","Select an indicator."); return
        if due_date:
            try: datetime.strptime(due_date,"%Y-%m-%d")
            except ValueError:
                messagebox.showerror("Invalid due date","Use YYYY-MM-DD for the due date."); return
        now=datetime.now().isoformat(timespec="seconds")
        cur=self.db.conn.execute("""INSERT INTO delegated_tasks
            (title,category_id,assigned_to,assigned_by,assigned_date,due_date,priority,instructions,status,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?, 'Assigned',?,?)""",
            (title,category_id,staff_id,self.user["id"],date.today().isoformat(),due_date or None,
             self.del_priority_var.get(),self.del_instructions.get("1.0","end").strip(),now,now))
        self.db.conn.commit(); self.db.audit(self.user["id"],"Delegated task","delegated_task",cur.lastrowid)
        self.del_indicator_var.set(""); self.del_instructions.delete("1.0","end")
        self.refresh_assignments(); self.refresh_dashboard(); self.refresh_delegation_admin()
        messagebox.showinfo("Indicator delegated",f"Task assigned successfully to {self.del_staff_var.get()}.")

    def build_entry(self):
        for w in self.entry_tab.winfo_children(): w.destroy()
        ttk.Label(self.entry_tab, text="Record Daily Activity", font=("Arial", 15, "bold")).pack(anchor="w", pady=(0, 10))
        form = ttk.Frame(self.entry_tab); form.pack(fill="both", expand=True)
        self.e_date = tk.StringVar(value=date.today().isoformat())
        self.e_category = tk.StringVar()
        self.e_task = tk.StringVar()
        self.e_status = tk.StringVar(value="Completed")
        self.e_priority = tk.StringVar(value="Normal")
        self.e_quantity = tk.StringVar(value="1")
        self.e_start = tk.StringVar()
        self.e_end = tk.StringVar()
        self.e_endorsed_to = tk.StringVar()
        fields = [
            ("Date (YYYY-MM-DD)", self.e_date), ("Category", self.e_category),
            ("Indicator", self.e_task), ("Status", self.e_status),
            ("Priority", self.e_priority), ("Quantity / units", self.e_quantity),
            ("Start time (optional)", self.e_start), ("End time (optional)", self.e_end),
            ("Endorsed to (optional)", self.e_endorsed_to)
        ]
        self.category_map = {}
        self.task_map = {}
        for i, (label, var) in enumerate(fields):
            r, c = divmod(i, 2)
            cell = ttk.Frame(form); cell.grid(row=r, column=c, sticky="ew", padx=8, pady=6)
            ttk.Label(cell, text=label).pack(anchor="w")
            if label == "Category":
                self.cat_combo = ttk.Combobox(cell, textvariable=var, state="readonly")
                self.cat_combo.pack(fill="x"); self.cat_combo.bind("<<ComboboxSelected>>", self.update_task_options)
            elif label == "Indicator":
                self.task_combo = ttk.Combobox(cell, textvariable=var, state="readonly")
                self.task_combo.pack(fill="x")
                self.task_combo.bind("<<ComboboxSelected>>", self.update_indicator_notes)
            elif label == "Status":
                ttk.Combobox(cell, textvariable=var, values=STATUSES, state="readonly").pack(fill="x")
            elif label == "Priority":
                ttk.Combobox(cell, textvariable=var, values=PRIORITIES, state="readonly").pack(fill="x")
            else:
                ttk.Entry(cell, textvariable=var).pack(fill="x")
        form.columnconfigure(0, weight=1); form.columnconfigure(1, weight=1)
        notes = ttk.Frame(form); notes.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=8, pady=6)
        ttk.Label(notes, text="Notes").pack(anchor="w")
        self.e_details = tk.Text(notes, height=4, wrap="word"); self.e_details.pack(fill="x")
        ttk.Label(notes, text="Issue / reason not completed").pack(anchor="w", pady=(8,0))
        self.e_issue = tk.Text(notes, height=3, wrap="word"); self.e_issue.pack(fill="x")
        ttk.Label(notes, text="Endorsement / next action").pack(anchor="w", pady=(8,0))
        self.e_endorse = tk.Text(notes, height=3, wrap="word"); self.e_endorse.pack(fill="x")
        ttk.Button(notes, text="Save Indicator Record", command=self.save_task).pack(anchor="e", pady=10)
        self.load_entry_options()

    def load_entry_options(self):
        cats = self.db.rows("SELECT * FROM categories WHERE active=1 ORDER BY name")
        self.category_map = {r["name"]: r["id"] for r in cats}
        self.cat_combo["values"] = list(self.category_map)
        if cats:
            self.e_category.set(cats[0]["name"]); self.update_task_options()

    def update_task_options(self, event=None):
        cid = self.category_map.get(self.e_category.get())
        rows = self.db.rows("SELECT id,task_name,notes FROM task_options WHERE category_id=? AND active=1 AND indicator_type='regular' ORDER BY task_name", (cid,)) if cid else []
        self.task_map = {r["task_name"]: r["id"] for r in rows}
        self.task_combo["values"] = list(self.task_map)
        self.e_task.set(rows[0]["task_name"] if rows else "")

    def update_indicator_notes(self, event=None):
        """Populate the Notes field with the selected indicator's default description."""
        if not hasattr(self, "e_details"):
            return
        description = getattr(self, "task_notes_map", {}).get(self.e_task.get(), "")
        self.e_details.delete("1.0", "end")
        if description:
            self.e_details.insert("1.0", description)

    def save_task(self):
        try:
            datetime.strptime(self.e_date.get().strip(), "%Y-%m-%d")
            qty = float(self.e_quantity.get())
            if qty < 0: raise ValueError()
        except ValueError:
            messagebox.showerror("Invalid entry", "Enter a valid date (YYYY-MM-DD) and non-negative quantity."); return
        title = self.e_task.get().strip()
        if not title:
            messagebox.showerror("Missing indicator", "Choose a indicator."); return
        status = self.e_status.get()
        issue = self.e_issue.get("1.0", "end").strip()
        endorsement = self.e_endorse.get("1.0", "end").strip()
        if status in ("Pending", "Unresolved", "Ongoing") and not (issue or endorsement):
            if not messagebox.askyesno("Confirm", "This indicator is not completed. Save without an issue or endorsement note?"): return
        now = datetime.now().isoformat(timespec="seconds")
        cur = self.db.conn.execute("""INSERT INTO task_logs
        (staff_id,task_date,category_id,task_option_id,task_title,quantity,status,priority,start_time,end_time,
         details,issue,endorsement,endorsed_to,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (self.user["id"], self.e_date.get().strip(), self.category_map.get(self.e_category.get()),
         self.task_map.get(title), title, qty, status, self.e_priority.get(), self.e_start.get().strip(),
         self.e_end.get().strip(), self.e_details.get("1.0","end").strip(), issue, endorsement,
         self.e_endorsed_to.get().strip(), now, now))
        self.db.conn.commit(); self.db.audit(self.user["id"], "Created indicator record", "task", cur.lastrowid)
        messagebox.showinfo("Saved", "Indicator record saved.")
        self.e_details.delete("1.0","end"); self.e_issue.delete("1.0","end"); self.e_endorse.delete("1.0","end")
        self.e_quantity.set("1"); self.e_start.set(""); self.e_end.set(""); self.e_endorsed_to.set("")
        self.refresh_history(); self.refresh_dashboard()

    def build_history(self):
        for w in self.history_tab.winfo_children(): w.destroy()
        top = ttk.Frame(self.history_tab); top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Indicator Records", font=("Arial", 15, "bold")).pack(side="left")
        ttk.Label(top, text="Month (YYYY-MM)").pack(side="left", padx=(20,5))
        self.hist_month = tk.StringVar(value=date.today().strftime("%Y-%m"))
        ttk.Entry(top, textvariable=self.hist_month, width=10).pack(side="left")
        ttk.Button(top, text="Filter", command=self.refresh_history).pack(side="left", padx=5)
        ttk.Button(top, text="Export .xls", command=self.export_xls).pack(side="right")
        ttk.Button(top, text="Update selected status / endorsement", command=self.update_selected).pack(side="right", padx=6)
        cols = ("id","date","staff","task","status","priority","qty","endorsed_to")
        self.tree = ttk.Treeview(self.history_tab, columns=cols, show="headings")
        headings = {"id":"ID","date":"Date","staff":"Staff","task":"Indicator","status":"Status",
                    "priority":"Priority","qty":"Qty","endorsed_to":"Endorsed to"}
        widths = {"id":50,"date":95,"staff":160,"task":300,"status":110,"priority":85,"qty":60,"endorsed_to":140}
        for col in cols:
            self.tree.heading(col, text=headings[col]); self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.refresh_history()

    def filtered_rows(self):
        month = self.hist_month.get().strip()
        if len(month) != 7:
            return []
        sql = """SELECT l.*,u.full_name FROM task_logs l JOIN users u ON u.id=l.staff_id
                 WHERE l.task_date LIKE ?"""
        params = [month + "%"]
        if self.user["role"] != "admin":
            sql += " AND l.staff_id=?"; params.append(self.user["id"])
        sql += " ORDER BY l.task_date DESC,l.id DESC"
        return self.db.rows(sql, params)

    def refresh_history(self):
        if not hasattr(self, "tree"): return
        for item in self.tree.get_children(): self.tree.delete(item)
        for r in self.filtered_rows():
            self.tree.insert("", "end", iid=str(r["id"]), values=(r["id"],r["task_date"],r["full_name"],
                r["task_title"],r["status"],r["priority"],r["quantity"],r["endorsed_to"] or ""))

    def update_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select record", "Select a indicator record first."); return
        task_id = int(sel[0])
        row = self.db.conn.execute("SELECT * FROM task_logs WHERE id=?", (task_id,)).fetchone()
        if self.user["role"] != "admin" and row["staff_id"] != self.user["id"]:
            messagebox.showerror("Not allowed", "You can only update your own indicator records."); return
        win = tk.Toplevel(self); win.title("Update task status / endorsement"); win.transient(self); win.grab_set()
        f = ttk.Frame(win, padding=15); f.pack(fill="both", expand=True)
        status = tk.StringVar(value=row["status"]); to = tk.StringVar(value=row["endorsed_to"] or "")
        ttk.Label(f, text=f"{row['task_date']} — {row['task_title']}", wraplength=450).pack(anchor="w", pady=5)
        ttk.Label(f, text="Status").pack(anchor="w")
        ttk.Combobox(f, textvariable=status, values=STATUSES, state="readonly").pack(fill="x", pady=4)
        ttk.Label(f, text="Endorsed to").pack(anchor="w")
        ttk.Entry(f, textvariable=to).pack(fill="x", pady=4)
        ttk.Label(f, text="Endorsement / next action").pack(anchor="w")
        note = tk.Text(f, height=5, wrap="word"); note.pack(fill="both", expand=True, pady=4)
        note.insert("1.0", row["endorsement"] or "")
        def save():
            self.db.conn.execute("UPDATE task_logs SET status=?,endorsed_to=?,endorsement=?,updated_at=? WHERE id=?",
                (status.get(),to.get().strip(),note.get("1.0","end").strip(),datetime.now().isoformat(timespec="seconds"),task_id))
            self.db.conn.commit(); self.db.audit(self.user["id"], "Updated indicator record", "task", task_id)
            win.destroy(); self.refresh_history(); self.refresh_dashboard()
        ttk.Button(f, text="Save changes", command=save).pack(anchor="e", pady=7)

    def export_xls(self):
        try:
            import xlwt
        except ImportError:
            messagebox.showerror("Missing package", "Install xlwt first: pip install xlwt"); return
        rows = self.filtered_rows()
        if not rows:
            messagebox.showinfo("No data", "There are no records for this month/filter."); return
        path = filedialog.asksaveasfilename(defaultextension=".xls",
            initialfile=f"CSSU_Indicators_Output_{self.hist_month.get()}.xls",
            filetypes=[("Excel 97-2003 workbook","*.xls")])
        if not path: return
        wb = xlwt.Workbook(encoding="utf-8"); ws = wb.add_sheet("Indicator Output")
        headers = ["Record ID","Date","Staff","Category","Indicator","Quantity","Status","Priority",
                   "Start time","End time","Details","Issue","Endorsement","Endorsed to","Last updated"]
        header_style = xlwt.easyxf("font: bold on; pattern: pattern solid, fore_colour ice_blue;")
        for c,h in enumerate(headers): ws.write(0,c,h,header_style)
        for ri,r in enumerate(rows,1):
            values = [r["id"],r["task_date"],r["full_name"],self.category_name(r["category_id"]),
                r["task_title"],r["quantity"],r["status"],r["priority"],r["start_time"] or "",
                r["end_time"] or "",r["details"] or "",r["issue"] or "",r["endorsement"] or "",
                r["endorsed_to"] or "",r["updated_at"]]
            for ci,v in enumerate(values): ws.write(ri,ci,v if v is not None else "")
        widths = [12,14,24,30,38,12,15,12,14,14,45,45,45,22,22]
        for i,width in enumerate(widths): ws.col(i).width = 256 * width
        wb.save(path); self.db.audit(self.user["id"], "Exported monthly XLS")
        messagebox.showinfo("Export complete", f"Exported {len(rows)} records to:\n{path}")

    def category_name(self, cid):
        if cid is None: return ""
        r = self.db.conn.execute("SELECT name FROM categories WHERE id=?", (cid,)).fetchone()
        return r["name"] if r else ""

    def build_admin(self):
        for w in self.admin_tab.winfo_children(): w.destroy()
        nb = ttk.Notebook(self.admin_tab); nb.pack(fill="both", expand=True)
        self.staff_admin = ttk.Frame(nb, padding=10)
        self.category_admin = ttk.Frame(nb, padding=10)
        self.task_admin = ttk.Frame(nb, padding=10)
        self.delegation_admin = ttk.Frame(nb, padding=10)
        nb.add(self.staff_admin, text="Staff Accounts")
        nb.add(self.category_admin, text="Categories")
        nb.add(self.task_admin, text="Indicators")
        nb.add(self.delegation_admin, text="Task Delegation")
        self.build_staff_admin(); self.build_category_admin(); self.build_task_admin(); self.build_delegation_admin()

    def build_staff_admin(self):
        f = self.staff_admin
        ttk.Label(f, text="Staff and administrator accounts", font=("Arial", 12, "bold")).pack(anchor="w")
        form = ttk.Frame(f); form.pack(fill="x", pady=8)
        self.a_username=tk.StringVar(); self.a_name=tk.StringVar(); self.a_role=tk.StringVar(value="staff")
        for i,(label,var) in enumerate((("Username",self.a_username),("Full name",self.a_name),("Role",self.a_role))):
            ttk.Label(form,text=label).grid(row=0,column=i,sticky="w",padx=4)
            if label=="Role": ttk.Combobox(form,textvariable=var,values=("staff","admin"),state="readonly",width=14).grid(row=1,column=i,padx=4)
            else: ttk.Entry(form,textvariable=var,width=24).grid(row=1,column=i,padx=4)
        ttk.Button(form,text="Add account (temporary password)",command=self.add_staff).grid(row=1,column=3,padx=8)
        ttk.Label(f,text="New accounts receive the temporary password: TempPass123!  Staff should change it after first sign-in.",
                  foreground="#8A5200").pack(anchor="w",pady=4)
        self.staff_tree=ttk.Treeview(f,columns=("id","username","name","role","active"),show="headings",height=12)
        for c,h,w in (("id","ID",50),("username","Username",160),("name","Full name",260),("role","Role",100),("active","Active",80)):
            self.staff_tree.heading(c,text=h); self.staff_tree.column(c,width=w)
        self.staff_tree.pack(fill="both",expand=True,pady=8)
        actions=ttk.Frame(f); actions.pack(fill="x")
        ttk.Button(actions,text="Activate / deactivate selected account",command=self.toggle_staff).pack(side="left")
        ttk.Button(actions,text="Delete selected staff",command=self.delete_staff).pack(side="right")
        self.refresh_staff()

    def add_staff(self):
        u,n,r=self.a_username.get().strip(),self.a_name.get().strip(),self.a_role.get()
        if not u or not n: messagebox.showerror("Missing data","Enter username and full name."); return
        try:
            self.db.conn.execute("INSERT INTO users(username,full_name,role,password_hash,created_at) VALUES(?,?,?,?,?)",
                (u,n,r,hash_password("TempPass123!"),datetime.now().isoformat(timespec="seconds")))
            self.db.conn.commit(); self.db.audit(self.user["id"],"Created user","user")
            self.a_username.set(""); self.a_name.set(""); self.refresh_staff()
        except sqlite3.IntegrityError: messagebox.showerror("Duplicate username","That username already exists.")

    def refresh_staff(self):
        if not hasattr(self,"staff_tree"): return
        for x in self.staff_tree.get_children(): self.staff_tree.delete(x)
        for r in self.db.rows("SELECT id,username,full_name,role,active FROM users ORDER BY full_name"):
            self.staff_tree.insert("","end",iid=str(r["id"]),values=(r["id"],r["username"],r["full_name"],r["role"],"Yes" if r["active"] else "No"))

    def toggle_staff(self):
        sel=self.staff_tree.selection()
        if not sel: return
        uid=int(sel[0])
        if uid==self.user["id"]: messagebox.showwarning("Not allowed","You cannot deactivate your own account."); return
        row=self.db.conn.execute("SELECT active FROM users WHERE id=?",(uid,)).fetchone()
        self.db.conn.execute("UPDATE users SET active=? WHERE id=?",(0 if row["active"] else 1,uid)); self.db.conn.commit()
        self.db.audit(self.user["id"],"Changed user active state","user",uid); self.refresh_staff()
        if hasattr(self,"delegate_staff_combo"):
            self.delegate_staff_map={r["full_name"]:r["id"] for r in self.db.rows("SELECT id,full_name FROM users WHERE role='staff' AND active=1 ORDER BY full_name")}
            self.delegate_staff_combo["values"]=list(self.delegate_staff_map)

    def delete_staff(self):
        sel = self.staff_tree.selection()
        if not sel:
            messagebox.showwarning("Select staff", "Select a staff account first.")
            return
        uid = int(sel[0])
        if uid == self.user["id"]:
            messagebox.showwarning("Not allowed", "You cannot delete your own account.")
            return
        row = self.db.conn.execute("SELECT full_name FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            return
        if not messagebox.askyesno("Confirm deletion",
                f"Delete staff account '{row['full_name']}'? If it has historical records or delegations, it will be deactivated instead."):
            return
        refs = self.db.conn.execute(
            "SELECT (SELECT COUNT(*) FROM task_logs WHERE staff_id=?) + "
            "(SELECT COUNT(*) FROM delegated_tasks WHERE assigned_to=? OR assigned_by=?) + "
            "(SELECT COUNT(*) FROM audit_log WHERE user_id=?)",
            (uid, uid, uid, uid)).fetchone()[0]
        if refs:
            self.db.conn.execute("UPDATE users SET active=0 WHERE id=?", (uid,))
            action = "Deactivated staff account with historical references"
        else:
            self.db.conn.execute("DELETE FROM users WHERE id=?", (uid,))
            action = "Deleted staff account"
        self.db.conn.commit()
        self.db.audit(self.user["id"], action, "user", uid)
        self.refresh_staff()
        if hasattr(self, "delegate_staff_combo"):
            self.delegate_staff_map = {r["full_name"]: r["id"] for r in self.db.rows(
                "SELECT id,full_name FROM users WHERE role='staff' AND active=1 ORDER BY full_name")}
            self.delegate_staff_combo["values"] = list(self.delegate_staff_map)
        messagebox.showinfo("Staff management", "Staff account deleted." if not refs else
                            "Staff account has historical records/delegations and was deactivated.")

    def build_category_admin(self):
        f=self.category_admin
        ttk.Label(f,text="Add or delete indicator categories",font=("Arial",12,"bold")).pack(anchor="w")
        line=ttk.Frame(f); line.pack(fill="x",pady=8)
        self.new_category=tk.StringVar()
        ttk.Entry(line,textvariable=self.new_category,width=40).pack(side="left")
        ttk.Button(line,text="Add category",command=self.add_category).pack(side="left",padx=7)
        self.cat_tree=ttk.Treeview(f,columns=("id","name","active"),show="headings",height=14)
        for c,h,w in (("id","ID",60),("name","Category",400),("active","Active",100)):
            self.cat_tree.heading(c,text=h); self.cat_tree.column(c,width=w)
        self.cat_tree.pack(fill="both",expand=True,pady=8)
        actions=ttk.Frame(f); actions.pack(fill="x")
        ttk.Button(actions,text="Activate / deactivate selected",command=self.toggle_category).pack(side="left")
        ttk.Button(actions,text="Delete selected category",command=self.delete_category).pack(side="right")
        self.refresh_categories()

    def add_category(self):
        name=self.new_category.get().strip()
        if not name: return
        try:
            self.db.conn.execute("INSERT INTO categories(name) VALUES(?)",(name,)); self.db.conn.commit()
            self.db.audit(self.user["id"],"Added category","category"); self.new_category.set(""); self.refresh_categories()
        except sqlite3.IntegrityError: messagebox.showerror("Duplicate","Category already exists.")

    def refresh_categories(self):
        if not hasattr(self,"cat_tree"): return
        for x in self.cat_tree.get_children(): self.cat_tree.delete(x)
        for r in self.db.rows("SELECT * FROM categories ORDER BY name"):
            self.cat_tree.insert("","end",iid=str(r["id"]),values=(r["id"],r["name"],"Yes" if r["active"] else "No"))

    def toggle_category(self):
        sel=self.cat_tree.selection()
        if not sel:return
        cid=int(sel[0]); row=self.db.conn.execute("SELECT active FROM categories WHERE id=?",(cid,)).fetchone()
        self.db.conn.execute("UPDATE categories SET active=? WHERE id=?",(0 if row["active"] else 1,cid)); self.db.conn.commit()
        self.db.audit(self.user["id"],"Changed category active state","category",cid); self.refresh_categories()

    def delete_category(self):
        sel = self.cat_tree.selection()
        if not sel:
            messagebox.showwarning("Select category", "Select a category first.")
            return
        cid = int(sel[0])
        row = self.db.conn.execute("SELECT name FROM categories WHERE id=?", (cid,)).fetchone()
        if not row:
            return
        if not messagebox.askyesno("Confirm deletion",
                f"Delete category '{row['name']}' and its indicators? Records already using it will be preserved; the category will be deactivated instead."):
            return
        refs = self.db.conn.execute(
            "SELECT (SELECT COUNT(*) FROM task_logs WHERE category_id=?) + "
            "(SELECT COUNT(*) FROM delegated_tasks WHERE category_id=?)", (cid, cid)).fetchone()[0]
        option_refs = self.db.conn.execute(
            "SELECT COUNT(*) FROM task_logs WHERE task_option_id IN "
            "(SELECT id FROM task_options WHERE category_id=?)", (cid,)).fetchone()[0]
        if refs or option_refs:
            self.db.conn.execute("UPDATE categories SET active=0 WHERE id=?", (cid,))
            self.db.conn.execute("UPDATE task_options SET active=0 WHERE category_id=?", (cid,))
            action = "Deactivated category and indicators with historical references"
        else:
            self.db.conn.execute("DELETE FROM task_options WHERE category_id=?", (cid,))
            self.db.conn.execute("DELETE FROM categories WHERE id=?", (cid,))
            action = "Deleted category and indicators"
        self.db.conn.commit()
        self.db.audit(self.user["id"], action, "category", cid)
        self.refresh_categories()
        self.refresh_task_admin()
        self.load_entry_options()
        messagebox.showinfo("Category management", "Category and indicators deleted." if not (refs or option_refs)
                            else "Category is in use by existing records and was deactivated to preserve history.")

    def build_task_admin(self):
        f=self.task_admin
        ttk.Label(f,text="Manage indicators",font=("Arial",12,"bold")).pack(anchor="w")
        line=ttk.Frame(f); line.pack(fill="x",pady=8)
        self.task_cat_var=tk.StringVar(); self.task_new_var=tk.StringVar()
        self.task_type_var=tk.StringVar(value="regular")
        self.task_cat_combo=ttk.Combobox(line,textvariable=self.task_cat_var,state="readonly",width=30)
        self.task_cat_combo.pack(side="left",padx=(0,6)); self.task_cat_combo.bind("<<ComboboxSelected>>",lambda e:self.refresh_task_admin())
        ttk.Entry(line,textvariable=self.task_new_var,width=34).pack(side="left",padx=5)
        ttk.Combobox(line,textvariable=self.task_type_var,values=("regular","admin"),state="readonly",width=12).pack(side="left",padx=5)
        ttk.Button(line,text="Add indicator",command=self.add_task_option).pack(side="left",padx=5)
        self.task_tree=ttk.Treeview(f,columns=("id","task","type","active"),show="headings",height=11)
        for c,h,w in (("id","ID",50),("task","Indicator",390),("type","Visibility",110),("active","Active",75)):
            self.task_tree.heading(c,text=h); self.task_tree.column(c,width=w)
        self.task_tree.bind("<<TreeviewSelect>>", self.load_admin_indicator_notes)
        self.task_tree.pack(fill="both",expand=True,pady=8)
        actions=ttk.Frame(f); actions.pack(fill="x")
        ttk.Button(actions,text="Activate / deactivate selected",command=self.toggle_task_option).pack(side="left")
        ttk.Button(actions,text="Delete selected indicator",command=self.delete_indicator).pack(side="right")
        notes_frame=ttk.LabelFrame(f,text="Indicator Notes / Description",padding=6)
        notes_frame.pack(fill="x",pady=(8,0))
        self.admin_indicator_notes=tk.Text(notes_frame,height=3,wrap="word")
        self.admin_indicator_notes.pack(fill="x")
        ttk.Button(notes_frame,text="Save Notes",command=self.save_admin_indicator_notes).pack(anchor="e",pady=(4,0))
        self.refresh_task_admin()
        self.refresh_delegation_indicators()

    def refresh_task_admin(self):
        cats=self.db.rows("SELECT id,name FROM categories ORDER BY name")
        self.admin_cat_map={r["name"]:r["id"] for r in cats}
        self.task_cat_combo["values"]=list(self.admin_cat_map)
        if not self.task_cat_var.get() and cats:self.task_cat_var.set(cats[0]["name"])
        if not hasattr(self,"task_tree"):return
        for x in self.task_tree.get_children():self.task_tree.delete(x)
        cid=self.admin_cat_map.get(self.task_cat_var.get())
        if cid:
            for r in self.db.rows("SELECT * FROM task_options WHERE category_id=? ORDER BY task_name",(cid,)):
                self.task_tree.insert("","end",iid=str(r["id"]),values=(r["id"],r["task_name"],r["indicator_type"].title(),"Yes" if r["active"] else "No"))

    def add_task_option(self):
        cid=self.admin_cat_map.get(self.task_cat_var.get()); name=self.task_new_var.get().strip()
        if not cid or not name:return
        self.db.conn.execute("INSERT INTO task_options(category_id,task_name,indicator_type) VALUES(?,?,?)",(cid,name,self.task_type_var.get()))
        self.db.conn.commit(); self.db.audit(self.user["id"],"Added indicator","task_option")
        self.task_new_var.set(""); self.refresh_task_admin()

    def load_admin_indicator_notes(self, event=None):
        if not hasattr(self, "admin_indicator_notes"):
            return
        sel = self.task_tree.selection()
        self.admin_indicator_notes.delete("1.0", "end")
        if sel:
            row = self.db.conn.execute("SELECT notes FROM task_options WHERE id=?", (int(sel[0]),)).fetchone()
            if row and row["notes"]:
                self.admin_indicator_notes.insert("1.0", row["notes"])

    def save_admin_indicator_notes(self):
        sel = self.task_tree.selection()
        if not sel:
            messagebox.showwarning("Select indicator", "Select an indicator first.")
            return
        indicator_id = int(sel[0])
        notes = self.admin_indicator_notes.get("1.0", "end").strip()
        self.db.conn.execute("UPDATE task_options SET notes=? WHERE id=?", (notes, indicator_id))
        self.db.conn.commit()
        self.db.audit(self.user["id"], "Updated indicator notes", "indicator", indicator_id)
        self.refresh_task_admin()
        messagebox.showinfo("Saved", "Indicator Notes saved.")

    def delete_indicator(self):
        sel = self.task_tree.selection()
        if not sel:
            messagebox.showwarning("Select indicator", "Select an indicator first.")
            return
        indicator_id = int(sel[0])
        row = self.db.conn.execute("SELECT task_name FROM task_options WHERE id=?", (indicator_id,)).fetchone()
        if not row:
            return
        if not messagebox.askyesno("Confirm deletion",
                f"Delete indicator '{row['task_name']}'? Existing records using it will be preserved; the indicator will be deactivated instead."):
            return
        refs = self.db.conn.execute(
            "SELECT COUNT(*) FROM task_logs WHERE task_option_id=?", (indicator_id,)).fetchone()[0]
        if refs:
            self.db.conn.execute("UPDATE task_options SET active=0 WHERE id=?", (indicator_id,))
            action = "Deactivated indicator with historical references"
        else:
            self.db.conn.execute("DELETE FROM task_options WHERE id=?", (indicator_id,))
            action = "Deleted indicator"
        self.db.conn.commit()
        self.db.audit(self.user["id"], action, "indicator", indicator_id)
        self.refresh_task_admin()
        self.load_entry_options()
        messagebox.showinfo("Indicator management", "Indicator deleted." if not refs else
                            "Indicator has existing records and was deactivated to preserve history.")

    def toggle_task_option(self):
        sel=self.task_tree.selection()
        if not sel:return
        tid=int(sel[0]); row=self.db.conn.execute("SELECT active FROM task_options WHERE id=?",(tid,)).fetchone()
        self.db.conn.execute("UPDATE task_options SET active=? WHERE id=?",(0 if row["active"] else 1,tid)); self.db.conn.commit()
        self.db.audit(self.user["id"],"Changed indicator active state","task_option",tid); self.refresh_task_admin()
        self.load_entry_options()


if __name__ == "__main__":
    app = CSSUApp()
    app.mainloop()
