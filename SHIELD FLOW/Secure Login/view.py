# shieldflow.py
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import sqlite3
import hashlib
import random
import smtplib
from email.message import EmailMessage
from cryptography.fernet import Fernet
import os
import imaplib
import email
from email.header import decode_header
import threading
import platform
import time
import requests
import webbrowser

# Optional desktop notifications
try:
    from plyer import notification
except Exception:
    notification = None

DB_NAME = "userdata.db"

# Keep your original Fernet key (used to encrypt stored Gmail credentials)
FERNET_KEY = b'XVQ32B9pJ1YV1cP2hLgu_bJ6L75w1kutNbI5gX3c4Cw='
cipher = Fernet(FERNET_KEY)

# ---------- (Underlying) External API Key — kept but not shown in UI ----------
VIRUSTOTAL_API_KEY = "d27d59e184443d177776d7b7404e597744660dc0c2f6301c823877163701069f"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSES_URL = "https://www.virustotal.com/api/v3/analyses"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# ---------- SOUND HELPERS ----------
def play_success_sound():
    """Play professional success sound - only on login"""
    def _play():
        try:
            system = platform.system()
            if system == "Darwin":  # macOS
                os.system('afplay /System/Library/Sounds/Hero.aiff &')
            elif system == "Windows":
                import winsound
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except:
            pass
    threading.Thread(target=_play, daemon=True).start()

def play_click_sound():
    """Play professional click sound for navigation"""
    def _play():
        try:
            system = platform.system()
            if system == "Darwin":  # macOS
                os.system('afplay /System/Library/Sounds/Tink.aiff &')
            elif system == "Windows":
                import winsound
                winsound.MessageBeep(winsound.MB_OK)
        except:
            pass
    threading.Thread(target=_play, daemon=True).start()

# ---------- DB HELPERS ----------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS userdata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS email_config (
        id INTEGER PRIMARY KEY,
        email_enc BLOB NOT NULL,
        app_pass_enc BLOB NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def get_user_count():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM userdata")
    (count,) = cur.fetchone()
    conn.close()
    return count

def create_user(username: str, password: str):
    if not username or not password:
        raise ValueError("username and password must be provided")
    username = username.strip()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO userdata (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
    finally:
        conn.close()

def verify_user(username: str, password: str) -> bool:
    if not username or not password:
        return False
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM userdata WHERE username = ? AND password = ?", (username.strip(), hashed))
    result = cur.fetchone()
    conn.close()
    return result is not None

def save_email_config(email_addr: str, app_pass: str):
    email_enc = cipher.encrypt(email_addr.encode())
    app_pass_enc = cipher.encrypt(app_pass.encode())
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO email_config (id, email_enc, app_pass_enc) VALUES (1, ?, ?)", (email_enc, app_pass_enc))
    conn.commit()
    conn.close()

def load_email_config():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT email_enc, app_pass_enc FROM email_config WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        return None, None
    try:
        email_addr = cipher.decrypt(row[0]).decode()
        app_pass = cipher.decrypt(row[1]).decode()
        return email_addr, app_pass
    except Exception:
        return None, None

# ---------- ALERT HELPERS ----------
def log_alert(title: str, message: str):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("INSERT INTO alerts (created_at, title, message) VALUES (datetime('now','localtime'), ?, ?)", (title, message))
    conn.commit()
    conn.close()

def get_all_alerts():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT created_at, title, message FROM alerts ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def push_notification(title: str, message: str):
    if notification:
        try:
            notification.notify(title=title, message=message, timeout=5)
        except Exception:
            pass

# ---------- EMAIL OTP HELPER ----------
# I preserved the OTP email HTML exactly as you provided previously.
def send_otp_email(from_email: str, app_password: str, to_email: str, otp: int):
    msg = EmailMessage()
    msg["Subject"] = "ShieldFlow Security - Verification Code"
    msg["From"] = f"ShieldFlow Security <{from_email}>"
    msg["To"] = to_email
    html_body = f""" 
    <html>
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 20px;">
    <tr>
    <td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <!-- Header -->
    <tr>
    <td style="background-color: #000000; padding: 40px 40px 30px 40px; text-align: center;">
    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">ShieldFlow</h1>
    <p style="margin: 8px 0 0 0; color: #999999; font-size: 13px; font-weight: 500; letter-spacing: 0.5px; text-transform: uppercase;">Security Platform</p>
    </td>
    </tr>
    <!-- Content -->
    <tr>
    <td style="padding: 50px 40px 40px 40px;">
    <h2 style="margin: 0 0 20px 0; color: #000000; font-size: 22px; font-weight: 600;">Account Verification</h2>
    <p style="margin: 0 0 30px 0; color: #666666; font-size: 15px; line-height: 24px;">
    You have requested to verify your ShieldFlow account. Please use the verification code below to complete your registration.
    </p>
    <!-- OTP Box -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin: 0 0 35px 0;">
    <tr>
    <td align="center" style="background-color: #f8f8f8; border: 2px solid #e5e5e5; border-radius: 8px; padding: 30px;">
    <p style="margin: 0 0 10px 0; color: #999999; font-size: 11px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase;">Verification Code</p>
    <p style="margin: 0; color: #000000; font-size: 36px; font-weight: 700; letter-spacing: 8px; font-family: 'Courier New', monospace;">{otp}</p>
    </td>
    </tr>
    </table>
    <p style="margin: 0 0 15px 0; color: #666666; font-size: 14px; line-height: 22px;">
    This code will expire in <strong style="color: #000000;">10 minutes</strong>. If you did not request this code, please ignore this email.
    </p>
    <!-- Security Notice -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0 0 0; border-top: 1px solid #e5e5e5; padding-top: 25px;">
    <tr>
    <td>
    <p style="margin: 0 0 8px 0; color: #000000; font-size: 13px; font-weight: 600;">Security Notice</p>
    <p style="margin: 0; color: #999999; font-size: 12px; line-height: 18px;">
    • Never share this code with anyone<br>
    • ShieldFlow will never ask for your code via email or phone<br>
    • If you receive suspicious emails, report them immediately
    </p>
    </td>
    </tr>
    </table>
    </td>
    </tr>
    <!-- Footer -->
    <tr>
    <td style="background-color: #f8f8f8; padding: 30px 40px; border-top: 1px solid #e5e5e5;">
    <p style="margin: 0 0 8px 0; color: #999999; font-size: 12px; line-height: 18px;"> This is an automated message from ShieldFlow Security Platform. Please do not reply to this email. </p>
    <p style="margin: 0; color: #cccccc; font-size: 11px;"> © 2025 ShieldFlow. All rights reserved. </p>
    </td>
    </tr>
    </table>
    </td>
    </tr>
    </table>
    </body>
    </html>
    """
    msg.add_alternative(html_body, subtype="html")
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as server:
        server.starttls()
        server.login(from_email, app_password)
        server.send_message(msg)

# ---------- MALWARE DETECTION HELPERS (local heuristics & external API kept) ----------
def scan_file_for_malware(file_path):
    """ Enhanced malware detection based on file characteristics
    Returns: (is_suspicious, reason, risk_level, file_hash)
    """
    try:
        if not os.path.exists(file_path):
            return (False, "File not found", "ERROR", "")
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1].lower()

        # Calculate file hash
        with open(file_path, 'rb') as f:
            file_content = f.read()
        file_hash = hashlib.sha256(file_content).hexdigest()

        suspicious_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.js', '.jar', '.app', '.dmg', '.pkg', '.scr', '.pif', '.com']
        suspicious_keywords = ['virus', 'trojan', 'malware', 'hack', 'crack', 'keygen', 'ransomware', 'worm', 'backdoor', 'rootkit']

        # Check 1: Suspicious extensions
        if file_ext in suspicious_extensions:
            # Check for suspicious keywords in filename
            file_name_lower = file_name.lower()
            for keyword in suspicious_keywords:
                if keyword in file_name_lower:
                    return (True, f"High-risk executable with suspicious keyword '{keyword}' in filename", "HIGH", file_hash)
            # Executable files are medium risk
            return (True, f"Executable file type detected: {file_ext}", "MEDIUM", file_hash)

        # Check 2: Suspicious file names
        file_name_lower = file_name.lower()
        for keyword in suspicious_keywords:
            if keyword in file_name_lower:
                return (True, f"Suspicious keyword '{keyword}' detected in filename", "MEDIUM", file_hash)

        # Check 3: Hidden files with suspicious patterns
        if file_name.startswith('.') and len(file_name) > 1:
            if file_ext in suspicious_extensions:
                return (True, "Hidden executable file detected", "HIGH", file_hash)

        # Check 4: Unusually large files (over 500MB)
        if file_size > 500 * 1024 * 1024:
            return (True, f"Unusually large file: {file_size / (1024*1024):.1f} MB", "MEDIUM", file_hash)

        # Check 5: Double extensions (e.g., file.pdf.exe)
        parts = file_name.split('.')
        if len(parts) > 2:
            second_ext = '.' + parts[-2].lower()
            if second_ext in ['.pdf', '.doc', '.jpg', '.png', '.txt'] and file_ext in suspicious_extensions:
                return (True, "Double extension detected - file may be disguised", "HIGH", file_hash)

        return (False, "No threats detected - file appears safe", "SAFE", file_hash)
    except PermissionError:
        return (False, "Permission denied - unable to scan file", "ERROR", "")
    except Exception as e:
        return (False, f"Error scanning file: {str(e)}", "ERROR", "")

def scan_directory(directory_path, progress_callback=None):
    """ Scan entire directory for malware
    Returns: list of (file_path, is_suspicious, reason, risk_level, file_hash)
    """
    results = []
    file_count = 0
    try:
        for root, dirs, files in os.walk(directory_path):
            # Skip system directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['System', 'Library', 'Windows']]
            for file in files:
                # Skip system files
                if file.startswith('.DS_Store') or file.startswith('._'):
                    continue
                file_path = os.path.join(root, file)
                file_count += 1
                if progress_callback:
                    progress_callback(file_count, file_path)
                try:
                    is_suspicious, reason, risk_level, file_hash = scan_file_for_malware(file_path)
                    if is_suspicious:
                        results.append((file_path, is_suspicious, reason, risk_level, file_hash))
                except Exception:
                    continue
        return results
    except Exception as e:
        print(f"Error scanning directory: {e}")
        return results

def fetch_gmail_alerts_imap(email_user, app_password, max_results=10):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_user, app_password)
        mail.select("inbox")
        status, data = mail.search(None, '(OR SUBJECT "security alert" SUBJECT "login" SUBJECT "verification code")')
        mail_ids = data[0].split()
        alerts = []
        for num in mail_ids[-max_results:]:
            status, msg_data = mail.fetch(num, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else "utf-8")
            from_ = msg.get("From")
            snippet = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        snippet = part.get_payload(decode=True).decode()
                        break
            else:
                snippet = msg.get_payload(decode=True).decode()
            alerts.append((subject, from_, snippet[:200]))
            log_alert(subject, snippet[:200])
        mail.logout()
        return alerts
    except Exception as e:
        print("Error fetching Gmail alerts:", e)
        return []

# ---------- External-analysis helpers (kept but UI wording changed) ----------
def vt_upload_file(file_path):
    """Upload file to external analysis API and return analysis id or (False, error)"""
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            resp = requests.post(VT_UPLOAD_URL, headers=VT_HEADERS, files=files, timeout=60)
        if resp.status_code in (200, 201):
            data = resp.json()
            analysis_id = data.get("data", {}).get("id")
            return True, analysis_id
        else:
            return False, f"Upload failed: {resp.status_code} {resp.text}"
    except Exception as e:
        return False, str(e)

def vt_get_analysis(analysis_id):
    """Get analysis result from external API given analysis id"""
    try:
        url = f"{VT_ANALYSES_URL}/{analysis_id}"
        resp = requests.get(url, headers=VT_HEADERS, timeout=30)
        if resp.status_code == 200:
            return True, resp.json()
        else:
            return False, f"Analysis fetch failed: {resp.status_code} {resp.text}"
    except Exception as e:
        return False, str(e)

def vt_get_file_report_by_hash(file_hash):
    """Get file report by SHA256 hash (if external API already analyzed it)"""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        resp = requests.get(url, headers=VT_HEADERS, timeout=30)
        if resp.status_code == 200:
            return True, resp.json()
        else:
            return False, f"Report fetch failed: {resp.status_code} {resp.text}"
    except Exception as e:
        return False, str(e)

# ---------- Improved Malware Scanner widget (UI) - with ShieldFlow wording ----------
class ImprovedMalwareScanner(tk.Frame):
    """A widget for the Malware Scanner page — improved UI and clearer output.
       All user-visible references now say 'ShieldFlow' instead of the external API name.
    """
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, bg="#0b0b0b", *args, **kwargs)
        self.parent = parent
        self.file_path = None
        self.file_hash = None
        self.permalink = None
        self.build_ui()

    def build_ui(self):
        header = tk.Frame(self, bg="#0b0b0b")
        header.pack(fill="x", pady=(0,12))
        tk.Label(header, text="Malware Scanner", bg="#0b0b0b", fg="#ffffff", font=("Helvetica", 18, "bold")).pack(anchor="w")
        tk.Label(header, text="Quick local scan or deep scan via ShieldFlow analysis.", bg="#0b0b0b", fg="#bfbfbf", font=("Helvetica", 10)).pack(anchor="w")

        controls = tk.Frame(self, bg="#0b0b0b")
        controls.pack(fill="x", pady=(6,12))

        self.select_btn = ttk.Button(controls, text="Choose File", command=self.choose_file)
        self.select_btn.grid(row=0, column=0, padx=(0,8))

        self.local_btn = ttk.Button(controls, text="Run Local Scan", command=self.run_local_scan)
        self.local_btn.grid(row=0, column=1, padx=(0,8))

        # Button text changed to ShieldFlow naming
        self.vt_btn = ttk.Button(controls, text="Upload & Scan (ShieldFlow)", command=self.start_vt_scan)
        self.vt_btn.grid(row=0, column=2, padx=(0,8))

        status_frame = tk.Frame(self, bg="#0b0b0b")
        status_frame.pack(fill="x", pady=(6,12))
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(fill="x", side="left", expand=True, padx=(0,8))
        self.status_label = tk.Label(status_frame, text="Idle", bg="#0b0b0b", fg="#d0d0d0", font=("Helvetica", 9))
        self.status_label.pack(side="right")

        self.card = tk.Frame(self, bg="#111111", highlightthickness=1, highlightbackground="#222222")
        self.card.pack(fill="both", expand=True, pady=(10,0))

        self.card_header = tk.Frame(self.card, bg="#111111")
        self.card_header.pack(fill="x", padx=12, pady=(12,0))
        self.filename_label = tk.Label(self.card_header, text="No file selected", bg="#111111", fg="#ffffff", font=("Helvetica", 12, "bold"))
        self.filename_label.pack(anchor="w")
        self.hash_label = tk.Label(self.card_header, text="SHA256: -", bg="#111111", fg="#bdbdbd", font=("Helvetica", 8))
        self.hash_label.pack(anchor="w", pady=(4,8))

        tag_frame = tk.Frame(self.card, bg="#111111")
        tag_frame.pack(fill="x", padx=12)
        self.risk_var = tk.StringVar(value="Unknown")
        self.risk_label = tk.Label(tag_frame, textvariable=self.risk_var, bg="#333333", fg="#ffffff", padx=8, pady=4, font=("Helvetica", 9, "bold"))
        self.risk_label.pack(anchor="w")

        body_frame = tk.Frame(self.card, bg="#0f0f0f")
        body_frame.pack(fill="both", expand=True, padx=12, pady=12)

        self.vendors_box = tk.Listbox(body_frame, bg="#0f0f0f", fg="#e6e6e6", height=8, bd=0, highlightthickness=0, selectbackground="#333333")
        self.vendors_box.pack(fill="both", expand=True, side="left")

        vendor_scroll = ttk.Scrollbar(body_frame, orient="vertical", command=self.vendors_box.yview)
        vendor_scroll.pack(side="right", fill="y")
        self.vendors_box.config(yscrollcommand=vendor_scroll.set)

        footer = tk.Frame(self.card, bg="#111111")
        footer.pack(fill="x", padx=12, pady=(0,12))
        # Button label changed to ShieldFlow wording
        self.permalink_btn = ttk.Button(footer, text="Open ShieldFlow Report", command=self.open_permalink, state='disabled')
        self.permalink_btn.pack(side="left")
        self.clear_btn = ttk.Button(footer, text="Clear", command=self.clear)
        self.clear_btn.pack(side="right")

    def choose_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self.file_path = path
        # get or compute sha256
        try:
            _, _, file_hash = scan_file_for_malware(path)
            if file_hash:
                self.file_hash = file_hash
            else:
                with open(path, 'rb') as f:
                    self.file_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            with open(path, 'rb') as f:
                self.file_hash = hashlib.sha256(f.read()).hexdigest()

        self.filename_label.config(text=os.path.basename(path))
        self.hash_label.config(text=f"SHA256: {self.file_hash}")
        self.risk_var.set("Ready")
        self.status_label.config(text="File selected")
        self.vendors_box.delete(0, tk.END)
        self.permalink_btn.config(state='disabled')

    def run_local_scan(self):
        if not self.file_path:
            messagebox.showwarning("No file", "Please choose a file first.")
            return
        self.status_label.config(text="Running local heuristic...")
        self.progress.start()
        def _scan():
            is_suspicious, reason, risk_level, file_hash = scan_file_for_malware(self.file_path)
            self.progress.stop()
            self.status_label.config(text="Local scan complete")
            self.vendors_box.delete(0, tk.END)
            self.vendors_box.insert(tk.END, f"Local check: {risk_level} - {reason}")
            self.update_risk_tag(risk_level)
            if is_suspicious:
                log_alert("Local Malware Detected", f"{os.path.basename(self.file_path)} - {reason}")
                push_notification("ShieldFlow Alert – Local Detection", f"{os.path.basename(self.file_path)} flagged as {risk_level}")
        threading.Thread(target=_scan, daemon=True).start()

    def start_vt_scan(self):
        if not self.file_path:
            messagebox.showwarning("No file", "Please choose a file first.")
            return
        threading.Thread(target=self.vt_scan_flow, daemon=True).start()

    def vt_scan_flow(self):
        self.progress.start()
        self.status_label.config(text="Checking ShieldFlow cached report...")
        ok, resp = vt_get_file_report_by_hash(self.file_hash)
        if ok:
            try:
                attrs = resp.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results = attrs.get("last_analysis_results", {})
                perma = resp.get("data", {}).get("links", {}).get("self", None)
                self.display_vt_results(stats, results, perma)
                self.progress.stop()
                self.status_label.config(text="ShieldFlow report loaded")
                log_alert("ShieldFlow Report Found", f"{os.path.basename(self.file_path)} - {stats}")
                return
            except Exception as e:
                self.status_label.config(text="Error reading cached report; uploading file...")

        # Upload
        self.status_label.config(text="Uploading file for ShieldFlow analysis...")
        ok, upload_result = vt_upload_file(self.file_path)
        if not ok:
            self.progress.stop()
            self.status_label.config(text="Upload failed")
            messagebox.showerror("Upload Error", str(upload_result))
            return
        analysis_id = upload_result
        self.status_label.config(text="Uploaded — waiting for ShieldFlow analysis to complete...")

        start = time.time()
        timeout = 180
        while True:
            ok, analysis = vt_get_analysis(analysis_id)
            if not ok:
                self.progress.stop()
                self.status_label.config(text="Error fetching analysis")
                messagebox.showerror("Analysis Error", str(analysis))
                return
            status = analysis.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                ok2, file_report = vt_get_file_report_by_hash(self.file_hash)
                if ok2:
                    attrs = file_report.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    results = attrs.get("last_analysis_results", {})
                    perma = file_report.get("data", {}).get("links", {}).get("self", None)
                    self.display_vt_results(stats, results, perma)
                    self.progress.stop()
                    self.status_label.config(text="Analysis complete")
                    if any(v.get('category') in ('malicious','suspicious') for v in results.values()):
                        log_alert("ShieldFlow Detection", f"{os.path.basename(self.file_path)} flagged by vendors")
                        push_notification("ShieldFlow Alert – Detection", f"{os.path.basename(self.file_path)} flagged by vendors")
                    else:
                        log_alert("ShieldFlow Scan Complete - Clean", f"{os.path.basename(self.file_path)} - clean")
                    return
                else:
                    self.progress.stop()
                    self.status_label.config(text="Analysis complete (no report) — try later")
                    messagebox.showinfo("ShieldFlow", "Analysis finished but report not available yet.")
                    return
            if time.time() - start > timeout:
                self.progress.stop()
                self.status_label.config(text="Analysis timed out")
                messagebox.showwarning("Timeout", "ShieldFlow analysis did not finish in time. Check later.")
                return
            time.sleep(3)

    def display_vt_results(self, stats, results, permalink):
        def _update():
            self.vendors_box.delete(0, tk.END)
            detections = []
            for vendor, info in sorted(results.items(), key=lambda x: x[0].lower()):
                cat = info.get('category')
                res = info.get('result')
                display = f"{vendor}: {cat} - {res if res else '-'}"
                self.vendors_box.insert(tk.END, display)
                if cat in ('malicious','suspicious'):
                    detections.append(vendor)
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            if malicious_count > 0:
                self.update_risk_tag('HIGH')
            elif suspicious_count > 0:
                self.update_risk_tag('MEDIUM')
            else:
                self.update_risk_tag('LOW')
            if permalink:
                self.permalink = permalink
                self.permalink_btn.config(state='normal')
            else:
                self.permalink = None
                self.permalink_btn.config(state='disabled')
            summary = f"Summary - malicious: {malicious_count}, suspicious: {suspicious_count}"
            self.vendors_box.insert(0, summary)
            try:
                self.vendors_box.selection_clear(0, tk.END)
                self.vendors_box.selection_set(0)
            except Exception:
                pass
        self.after(0, _update)

    def update_risk_tag(self, level):
        color_map = {'HIGH': '#b22222', 'MEDIUM': '#ff8c00', 'LOW': '#2e8b57', 'SAFE': '#2e8b57', 'ERROR': '#666666', 'Unknown': '#4b4b4b'}
        text_map = {'HIGH': 'High Risk', 'MEDIUM': 'Medium Risk', 'LOW': 'Low Risk', 'SAFE': 'Safe', 'ERROR': 'Error', 'Unknown': 'Unknown'}
        color = color_map.get(level, '#4b4b4b')
        text = text_map.get(level, level)
        self.risk_var.set(text)
        self.risk_label.config(bg=color)

    def open_permalink(self):
        if getattr(self, 'permalink', None):
            webbrowser.open(self.permalink)

    def clear(self):
        self.file_path = None
        self.file_hash = None
        self.filename_label.config(text='No file selected')
        self.hash_label.config(text='SHA256: -')
        self.vendors_box.delete(0, tk.END)
        self.risk_var.set('Unknown')
        self.risk_label.config(bg='#333333')
        self.status_label.config(text='Idle')
        self.permalink_btn.config(state='disabled')

# ---------- TKINTER APP (original UI preserved) ----------
class ShieldFlowLoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ShieldFlow Security Platform")
        self.root.geometry("900x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#000000")
        self.pending_email = None
        self.pending_app_pass = None
        self.pending_username = None
        self.pending_password = None
        self.current_otp = None
        self.current_user = None

        # Rate limiting
        self.last_register_attempt = 0
        self.last_login_attempt = 0
        self.last_otp_attempt = 0

        init_db()
        if get_user_count() == 0:
            self.build_first_time_register_ui()
        else:
            self.build_login_ui()

    def styled_entry(self, parent, width):
        """Professional minimal entry field"""
        entry = tk.Entry(parent, width=width, bg="#1a1a1a", fg="#ffffff", insertbackground="#ffffff", relief="flat", font=("Helvetica", 11), bd=0, highlightthickness=0)
        return entry

    def styled_button(self, parent, text, command, width=20):
        """Professional minimal button with rounded corners"""
        frame = tk.Frame(parent, bg="#ffffff", highlightthickness=0)
        btn = tk.Button(frame, text=text, command=command, bg="#ffffff", fg="#000000", font=("Helvetica", 10, "bold"), relief="flat", activebackground="#cccccc", activeforeground="#000000", width=width, padx=15, pady=10, bd=0, cursor="hand2", borderwidth=0, highlightthickness=0)
        btn.pack(padx=1, pady=1)
        def on_enter(e):
            btn.config(bg="#e0e0e0")
            frame.config(bg="#e0e0e0")
        def on_leave(e):
            btn.config(bg="#ffffff")
            frame.config(bg="#ffffff")
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return frame

    def secondary_button(self, parent, text, command, width=20):
        frame = tk.Frame(parent, bg="#1a1a1a", highlightthickness=1, highlightbackground="#333333")
        btn = tk.Button(frame, text=text, command=command, bg="#1a1a1a", fg="#000000", font=("Helvetica", 10, "bold"), relief="flat", activebackground="#2a2a2a", activeforeground="#000000", width=width, padx=15, pady=10, bd=0, cursor="hand2")
        btn.pack(padx=1, pady=1)
        def on_enter(e):
            btn.config(bg="#2a2a2a")
            frame.config(bg="#2a2a2a")
        def on_leave(e):
            btn.config(bg="#1a1a1a")
            frame.config(bg="#1a1a1a")
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return frame

    # ---------- REGISTRATION ----------
    def build_first_time_register_ui(self):
        container = tk.Frame(self.root, bg="#000000")
        container.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(container, text="ShieldFlow", bg="#000000", fg="#ffffff", font=("Helvetica", 32, "bold")).pack(pady=(0, 5))
        tk.Label(container, text="Security Platform", bg="#000000", fg="#666666", font=("Helvetica", 12)).pack(pady=(0, 40))
        tk.Label(container, text="Initialize Account", bg="#000000", fg="#ffffff", font=("Helvetica", 11, "bold")).pack(pady=(0, 20))
        tk.Label(container, text="Gmail Address", bg="#000000", fg="#999999", font=("Helvetica", 9)).pack(anchor="w", pady=(0, 5))
        self.email_entry = self.styled_entry(container, width=35)
        self.email_entry.pack(pady=(0, 15))
        tk.Label(container, text="Gmail App Password", bg="#000000", fg="#999999", font=("Helvetica", 9)).pack(anchor="w", pady=(0, 5))
        self.email_app_pass_entry = self.styled_entry(container, width=35)
        self.email_app_pass_entry.config(show="•")
        self.email_app_pass_entry.pack(pady=(0, 15))
        tk.Label(container, text="Username", bg="#000000", fg="#999999", font=("Helvetica", 9)).pack(anchor="w", pady=(0, 5))
        self.setup_username_entry = self.styled_entry(container, width=35)
        self.setup_username_entry.pack(pady=(0, 15))
        tk.Label(container, text="Password", bg="#000000", fg="#999999", font=("Helvetica", 9)).pack(anchor="w", pady=(0, 5))
        self.setup_password_entry = self.styled_entry(container, width=35)
        self.setup_password_entry.config(show="•")
        self.setup_password_entry.pack(pady=(0, 15))
        tk.Label(container, text="Confirm Password", bg="#000000", fg="#999999", font=("Helvetica", 9)).pack(anchor="w", pady=(0, 5))
        self.setup_confirm_entry = self.styled_entry(container, width=35)
        self.setup_confirm_entry.config(show="•")
        self.setup_confirm_entry.pack(pady=(0, 20))
        self.styled_button(container, text="Continue", command=self.handle_send_otp, width=35).pack(pady=(10, 5))
        tk.Label(container, text="Note: Credentials cannot be recovered if lost", bg="#000000", fg="#666666", font=("Helvetica", 8)).pack(pady=(10, 0))

    def handle_send_otp(self):
        import time
        current_time = time.time()
        if current_time - self.last_register_attempt < 6:
            remaining = int(6 - (current_time - self.last_register_attempt))
            messagebox.showwarning("Please Wait", f"Please wait {remaining} seconds before trying again.")
            return
        email_addr = self.email_entry.get().strip()
        app_pass = self.email_app_pass_entry.get().strip()
        username = self.setup_username_entry.get().strip()
        password = self.setup_password_entry.get().strip()
        confirm = self.setup_confirm_entry.get().strip()
        if not email_addr or not app_pass or not username or not password or not confirm:
            messagebox.showerror("Error", "All fields are required.")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        self.last_register_attempt = current_time
        otp = random.randint(100000, 999999)
        self.current_otp = str(otp)
        self.pending_email = email_addr
        self.pending_app_pass = app_pass
        self.pending_username = username
        self.pending_password = password
        try:
            send_otp_email(email_addr, app_pass, email_addr, otp)
        except Exception as e:
            messagebox.showerror("Email Error", f"Failed to send OTP.\n{e}")
            self.current_otp = None
            self.pending_email = None
            self.pending_app_pass = None
            self.pending_username = None
            self.pending_password = None
            return
        log_alert("OTP Sent", f"OTP sent to {email_addr} for account setup.")
        push_notification("ShieldFlow Alert – OTP Sent", f"OTP sent to {email_addr}.")
        self.show_otp_window()

    def show_otp_window(self):
        self.otp_window = tk.Toplevel(self.root)
        self.otp_window.title("Verification")
        self.otp_window.geometry("400x250")
        self.otp_window.configure(bg="#000000")
        self.otp_window.resizable(False, False)
        container = tk.Frame(self.otp_window, bg="#000000")
        container.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(container, text="Email Verification", bg="#000000", fg="#ffffff", font=("Helvetica", 14, "bold")).pack(pady=(0, 10))
        tk.Label(container, text="Enter the 6-digit code sent to your email", bg="#000000", fg="#999999", font=("Helvetica", 10)).pack(pady=(0, 20))
        self.otp_entry = self.styled_entry(container, width=20)
        self.otp_entry.config(font=("Helvetica", 16), justify="center")
        self.otp_entry.pack(pady=(0, 20))
        self.styled_button(container, text="Verify", command=self.handle_verify_otp, width=20).pack()

    def handle_verify_otp(self):
        import time
        current_time = time.time()
        if current_time - self.last_otp_attempt < 6:
            remaining = int(6 - (current_time - self.last_otp_attempt))
            messagebox.showwarning("Please Wait", f"Please wait {remaining} seconds before trying again.")
            return
        self.last_otp_attempt = current_time
        entered = self.otp_entry.get().strip()
        if not self.current_otp or entered != self.current_otp:
            messagebox.showerror("Error", "Invalid OTP.")
            return
        try:
            create_user(self.pending_username, self.pending_password)
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "That username already exists.")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create user: {e}")
            return
        save_email_config(self.pending_email, self.pending_app_pass)
        log_alert("Account Created", f"New account created for {self.pending_username}")
        push_notification("ShieldFlow Alert – Account Created", f"Account created for {self.pending_username}.")
        messagebox.showinfo("Success", "Account created successfully.")
        self.current_otp = None
        self.pending_email = None
        self.pending_app_pass = None
        self.pending_username = None
        self.pending_password = None
        try:
            self.otp_window.destroy()
        except Exception:
            pass
        self.build_login_ui()

    # ---------- LOGIN ----------
    def build_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        container = tk.Frame(self.root, bg="#000000")
        container.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(container, text="ShieldFlow", bg="#000000", fg="#ffffff", font=("Helvetica", 32, "bold")).pack(pady=(0, 5))
        tk.Label(container, text="Security Platform", bg="#000000", fg="#666666", font=("Helvetica", 12)).pack(pady=(0, 50))
        tk.Label(container, text="Username", bg="#000000", fg="#999999", font=("Helvetica", 9)).pack(anchor="w", pady=(0, 5))
        self.login_username_entry = self.styled_entry(container, width=30)
        self.login_username_entry.pack(pady=(0, 20))
        tk.Label(container, text="Password", bg="#000000", fg="#999999", font=("Helvetica", 9)).pack(anchor="w", pady=(0, 5))
        self.login_password_entry = self.styled_entry(container, width=30)
        self.login_password_entry.config(show="•")
        self.login_password_entry.pack(pady=(0, 30))
        self.styled_button(container, text="Sign In", command=self.handle_login, width=30).pack()

    def handle_login(self):
        import time
        current_time = time.time()
        if current_time - self.last_login_attempt < 6:
            remaining = int(6 - (current_time - self.last_login_attempt))
            messagebox.showwarning("Please Wait", f"Please wait {remaining} seconds before trying again.")
            return
        username = self.login_username_entry.get().strip()
        password = self.login_password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Enter both username and password.")
            return
        self.last_login_attempt = current_time
        ok = verify_user(username, password)
        if ok:
            log_alert("Login Success", f"User {username} logged in successfully.")
            push_notification("ShieldFlow Alert – Login Success", f"User {username} logged in.")
            self.current_user = username
            play_success_sound()
            # Show loading animation before dashboard
            self.show_login_animation()
        else:
            log_alert("Login Failed", f"Failed login attempt for username: {username}")
            push_notification("ShieldFlow Alert – Login Failed", f"Failed login for {username}")
            messagebox.showerror("Authentication Failed", "Invalid credentials.")

    def show_login_animation(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        anim_frame = tk.Frame(self.root, bg="#000000")
        anim_frame.pack(fill="both", expand=True)
        center = tk.Frame(anim_frame, bg="#000000")
        center.place(relx=0.5, rely=0.5, anchor="center")
        success_label = tk.Label(center, text="✓ Authentication Successful", bg="#000000", fg="#ffffff", font=("Helvetica", 18, "bold"))
        success_label.pack(pady=(0, 20))
        loading_label = tk.Label(center, text="Loading dashboard...", bg="#000000", fg="#999999", font=("Helvetica", 11))
        loading_label.pack(pady=(0, 30))
        dots_label = tk.Label(center, text="", bg="#000000", fg="#ffffff", font=("Helvetica", 20))
        dots_label.pack()
        def animate_dots(count=0):
            if count < 15:
                dots = "●" * ((count % 3) + 1) + "○" * (2 - (count % 3))
                dots_label.config(text=dots)
                self.root.after(100, lambda: animate_dots(count + 1))
            else:
                self.build_dashboard()
        animate_dots()

    # ---------- DASHBOARD WITH SIDEBAR ----------
    def build_dashboard(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.sidebar = tk.Frame(self.root, bg="#0a0a0a", width=200)
        self.sidebar.pack(side="left", fill="y")
        logo_frame = tk.Frame(self.sidebar, bg="#0a0a0a")
        logo_frame.pack(pady=30, padx=20)
        tk.Label(logo_frame, text="ShieldFlow", bg="#0a0a0a", fg="#ffffff", font=("Helvetica", 16, "bold")).pack()
        tk.Frame(self.sidebar, bg="#1a1a1a", height=1).pack(fill="x", padx=20, pady=20)
        self.nav_buttons = {}
        self.create_nav_button("Overview", lambda: self.show_page("overview"))
        self.create_nav_button("Malware Scanner", lambda: self.show_page("malware"))
        self.create_nav_button("Local Alerts", lambda: self.show_page("local_alerts"))
        self.create_nav_button("Gmail Monitor", lambda: self.show_page("gmail"))
        self.create_nav_button("Settings", lambda: self.show_page("settings"))
        tk.Frame(self.sidebar, bg="#0a0a0a", height=1).pack(side="bottom", fill="x", pady=20)
        logout_btn = self.secondary_button(self.sidebar, text="Sign Out", command=self.handle_logout, width=15)
        logout_btn.pack(side="bottom", pady=10)
        self.content_area = tk.Frame(self.root, bg="#000000")
        self.content_area.pack(side="right", fill="both", expand=True)
        self.current_page = None
        self.show_page("overview")

    def create_nav_button(self, text, command):
        frame = tk.Frame(self.sidebar, bg="#0a0a0a")
        frame.pack(fill="x", padx=8, pady=3)
        btn = tk.Button(frame, text=text, command=command, bg="#0a0a0a", fg="#999999", font=("Helvetica", 10, "bold"), relief="flat", activebackground="#1a1a1a", activeforeground="#000000", width=18, anchor="w", padx=20, pady=12, bd=0, cursor="hand2")
        btn.pack(fill="x", padx=1, pady=1)
        def on_enter(e):
            if self.current_page != text:
                btn.config(bg="#1a1a1a", fg="#000000")
                frame.config(bg="#1a1a1a")
        def on_leave(e):
            if self.current_page != text:
                btn.config(bg="#0a0a0a", fg="#999999")
                frame.config(bg="#0a0a0a")
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        self.nav_buttons[text] = (btn, frame)
        return btn

    def update_nav_active(self, active_page):
        for page, (btn, frame) in self.nav_buttons.items():
            if page == active_page:
                btn.config(bg="#1a1a1a", fg="#000000")
                frame.config(bg="#1a1a1a")
            else:
                btn.config(bg="#0a0a0a", fg="#999999")
                frame.config(bg="#0a0a0a")

    def show_page(self, page_name):
        play_click_sound()
        for widget in self.content_area.winfo_children():
            widget.destroy()
        if page_name == "overview":
            self.current_page = "Overview"
            self.update_nav_active("Overview")
            self.show_overview_page()
        elif page_name == "malware":
            self.current_page = "Malware Scanner"
            self.update_nav_active("Malware Scanner")
            self.show_malware_page()
        elif page_name == "local_alerts":
            self.current_page = "Local Alerts"
            self.update_nav_active("Local Alerts")
            self.show_local_alerts_page()
        elif page_name == "gmail":
            self.current_page = "Gmail Monitor"
            self.update_nav_active("Gmail Monitor")
            self.show_gmail_page()
        elif page_name == "settings":
            self.current_page = "Settings"
            self.update_nav_active("Settings")
            self.show_settings_page()

    def show_overview_page(self):
        container = tk.Frame(self.content_area, bg="#000000")
        container.pack(fill="both", expand=True, padx=40, pady=40)
        header = tk.Frame(container, bg="#000000")
        header.pack(fill="x", pady=(0, 30))
        tk.Label(header, text=f"Welcome, {self.current_user}", bg="#000000", fg="#ffffff", font=("Helvetica", 24, "bold")).pack(anchor="w")
        tk.Label(header, text="Security Operations Center", bg="#000000", fg="#666666", font=("Helvetica", 11)).pack(anchor="w", pady=(5, 0))
        stats_frame = tk.Frame(container, bg="#000000")
        stats_frame.pack(fill="x", pady=20)
        alerts = get_all_alerts()
        alert_count = len(alerts)
        self.create_stat_card(stats_frame, "Total Alerts", str(alert_count), 0, 0)
        self.create_stat_card(stats_frame, "Account Status", "Active", 0, 1)
        self.create_stat_card(stats_frame, "Security Level", "High", 0, 2)
        tk.Label(container, text="Quick Actions", bg="#000000", fg="#ffffff", font=("Helvetica", 14, "bold")).pack(anchor="w", pady=(30, 15))
        actions_frame = tk.Frame(container, bg="#000000")
        actions_frame.pack(fill="x")
        self.secondary_button(actions_frame, text="Malware Scanner", command=lambda: self.show_page("malware"), width=20).grid(row=0, column=0, padx=(0, 10))
        self.secondary_button(actions_frame, text="View Local Alerts", command=lambda: self.show_page("local_alerts"), width=20).grid(row=0, column=1, padx=(0, 10))
        self.secondary_button(actions_frame, text="Check Gmail", command=lambda: self.show_page("gmail"), width=20).grid(row=0, column=2)

    def create_stat_card(self, parent, label, value, row, col):
        card = tk.Frame(parent, bg="#0a0a0a", highlightbackground="#1a1a1a", highlightthickness=1)
        card.grid(row=row, column=col, padx=(0, 15) if col < 2 else 0, sticky="ew")
        parent.grid_columnconfigure(col, weight=1)
        tk.Label(card, text=value, bg="#0a0a0a", fg="#ffffff", font=("Helvetica", 24, "bold")).pack(pady=(20, 5), padx=30)
        tk.Label(card, text=label, bg="#0a0a0a", fg="#666666", font=("Helvetica", 10)).pack(pady=(0, 20), padx=30)

    def show_local_alerts_page(self):
        container = tk.Frame(self.content_area, bg="#000000")
        container.pack(fill="both", expand=True, padx=40, pady=40)
        tk.Label(container, text="Local Alerts", bg="#000000", fg="#ffffff", font=("Helvetica", 20, "bold")).pack(anchor="w", pady=(0, 20))
        alerts = get_all_alerts()
        if not alerts:
            tk.Label(container, text="No alerts found", bg="#000000", fg="#666666", font=("Helvetica", 11)).pack(pady=50)
            return
        canvas = tk.Canvas(container, bg="#000000", highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#000000")
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        for created_at, title, msg in alerts:
            alert_card = tk.Frame(scrollable_frame, bg="#0a0a0a", highlightbackground="#1a1a1a", highlightthickness=1)
            alert_card.pack(fill="x", pady=(0, 10))
            tk.Label(alert_card, text=title, bg="#0a0a0a", fg="#ffffff", font=("Helvetica", 11, "bold"), anchor="w").pack(anchor="w", padx=20, pady=(15, 5))
            tk.Label(alert_card, text=msg, bg="#0a0a0a", fg="#999999", font=("Helvetica", 9), anchor="w", wraplength=500, justify="left").pack(anchor="w", padx=20, pady=(0, 5))
            tk.Label(alert_card, text=created_at, bg="#0a0a0a", fg="#666666", font=("Helvetica", 8), anchor="w").pack(anchor="w", padx=20, pady=(0, 15))
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def show_gmail_page(self):
        container = tk.Frame(self.content_area, bg="#000000")
        container.pack(fill="both", expand=True, padx=40, pady=40)
        tk.Label(container, text="Gmail Security Monitor", bg="#000000", fg="#ffffff", font=("Helvetica", 20, "bold")).pack(anchor="w", pady=(0, 10))
        tk.Label(container, text="Monitor security-related emails from your Gmail account", bg="#000000", fg="#666666", font=("Helvetica", 10)).pack(anchor="w", pady=(0, 30))
        self.styled_button(container, text="Scan Gmail for Security Alerts", command=self.handle_check_gmail_alerts, width=30).pack(anchor="w")
        tk.Label(container, text="This will search for emails containing security keywords\nand add them to your local alerts.", bg="#000000", fg="#666666", font=("Helvetica", 9), justify="left").pack(anchor="w", pady=(20, 0))

    def show_settings_page(self):
        container = tk.Frame(self.content_area, bg="#000000")
        container.pack(fill="both", expand=True, padx=40, pady=40)
        tk.Label(container, text="Settings", bg="#000000", fg="#ffffff", font=("Helvetica", 20, "bold")).pack(anchor="w", pady=(0, 30))
        info_frame = tk.Frame(container, bg="#0a0a0a", highlightbackground="#1a1a1a", highlightthickness=1)
        info_frame.pack(fill="x", pady=(0, 20))
        tk.Label(info_frame, text="Account Information", bg="#0a0a0a", fg="#ffffff", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=20, pady=(20, 15))
        info_container = tk.Frame(info_frame, bg="#0a0a0a")
        info_container.pack(anchor="w", padx=20, pady=(0, 20))
        tk.Label(info_container, text="Username:", bg="#0a0a0a", fg="#666666", font=("Helvetica", 9)).grid(row=0, column=0, sticky="w", pady=5)
        tk.Label(info_container, text=self.current_user, bg="#0a0a0a", fg="#ffffff", font=("Helvetica", 9)).grid(row=0, column=1, sticky="w", padx=(10, 0), pady=5)
        email_addr, _ = load_email_config()
        tk.Label(info_container, text="Gmail:", bg="#0a0a0a", fg="#666666", font=("Helvetica", 9)).grid(row=1, column=0, sticky="w", pady=5)
        tk.Label(info_container, text=email_addr if email_addr else "Not configured", bg="#0a0a0a", fg="#ffffff", font=("Helvetica", 9)).grid(row=1, column=1, sticky="w", padx=(10, 0), pady=5)
        notice_frame = tk.Frame(container, bg="#0a0a0a", highlightbackground="#1a1a1a", highlightthickness=1)
        notice_frame.pack(fill="x")
        tk.Label(notice_frame, text="Security Notice", bg="#0a0a0a", fg="#ffffff", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=20, pady=(20, 10))
        tk.Label(notice_frame, text="• Credentials are encrypted and stored locally\n• No password recovery available\n• Keep your credentials secure", bg="#0a0a0a", fg="#999999", font=("Helvetica", 9), justify="left").pack(anchor="w", padx=20, pady=(0, 20))

    # ---------- MALWARE PAGE: embed ImprovedMalwareScanner ----------
    def show_malware_page(self):
        container = tk.Frame(self.content_area, bg="#000000")
        container.pack(fill="both", expand=True, padx=40, pady=40)
        # place the improved scanner inside the malware page content area
        scanner = ImprovedMalwareScanner(container)
        scanner.pack(fill="both", expand=True)

    def handle_check_gmail_alerts(self):
        email_addr, app_pass = load_email_config()
        if not email_addr or not app_pass:
            messagebox.showerror("Error", "Gmail credentials not found.")
            return
        loading_win = tk.Toplevel(self.root)
        loading_win.title("Scanning")
        loading_win.geometry("300x100")
        loading_win.configure(bg="#000000")
        loading_win.resizable(False, False)
        tk.Label(loading_win, text="Scanning Gmail...", bg="#000000", fg="#ffffff", font=("Helvetica", 11)).pack(expand=True)
        loading_win.update()
        alerts = fetch_gmail_alerts_imap(email_addr, app_pass)
        loading_win.destroy()
        if not alerts:
            messagebox.showinfo("Scan Complete", "No new security alerts found in Gmail.")
        else:
            messagebox.showinfo("Scan Complete", f"Found {len(alerts)} security-related emails.\nCheck Local Alerts to view them.")

    def handle_logout(self):
        play_click_sound()
        self.show_logout_animation()

    def show_logout_animation(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        anim_frame = tk.Frame(self.root, bg="#000000")
        anim_frame.pack(fill="both", expand=True)
        center = tk.Frame(anim_frame, bg="#000000")
        center.place(relx=0.5, rely=0.5, anchor="center")
        logout_label = tk.Label(center, text="Signing Out", bg="#000000", fg="#ffffff", font=("Helvetica", 18, "bold"))
        logout_label.pack(pady=(0, 20))
        subtext_label = tk.Label(center, text="Securing your session...", bg="#000000", fg="#999999", font=("Helvetica", 11))
        subtext_label.pack(pady=(0, 30))
        dots_label = tk.Label(center, text="", bg="#000000", fg="#ffffff", font=("Helvetica", 20))
        dots_label.pack()
        def animate_dots(count=0):
            if count < 12:
                dots = "●" * ((count % 3) + 1) + "○" * (2 - (count % 3))
                dots_label.config(text=dots)
                self.root.after(200, lambda: animate_dots(count + 1))
            else:
                self.current_user = None
                self.build_login_ui()
        animate_dots()

# ---------- RUN APP ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = ShieldFlowLoginApp(root)
    root.mainloop()
