# phishing_detection.py
# Full script: detection helpers + improved Tkinter GUI (drop-in)
# Requirements (optional): joblib, tldextract, python-whois, requests, pillow, pandas

import os
import joblib
import socket
import ssl
import tldextract
import whois
import requests
from datetime import datetime
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import webbrowser
from PIL import Image, ImageTk

# --------- Config ----------
MODEL_FILENAME = "rf_model.joblib"
VT_API_KEY = os.environ.get("VT_API_KEY", "")
BANNER_FILENAME = "banner.png"
# ---------------------------

# --- Utility functions (feature extraction, SSL, WHOIS, VT) ---
def extract_simple_features(url: str):
    u = url.strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        u = "http://" + u
    host = u.split("//")[-1].split("/")[0]
    features = {}
    features["url"] = u
    features["host"] = host
    features["url_length"] = len(u)
    features["has_at"] = int("@" in u)
    features["has_https"] = int(u.startswith("https://"))
    host_label = host.split(":")[0]
    features["num_subdomain"] = max(0, host_label.count(".") - 1)
    features["has_ip"] = int(all(ch.isdigit() or ch == "." for ch in host_label))
    features["has_hyphen"] = int("-" in host_label)
    suspicious_words = [
        "login", "verify", "update", "secure", "bank", "account", "paypal", "signin", "confirm"
    ]
    matched = [w for w in suspicious_words if w in u.lower()]
    features["suspicious_words"] = int(bool(matched))
    features["matched_suspicious_words"] = matched
    features["double_slash"] = u[8:].count("//") if len(u) > 8 else 0
    return features

def check_ssl(host: str, port: int = 443, timeout: float = 5.0):
    host_only = host.split("//")[-1].split("/")[0].split(":")[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host_only, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host_only) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                days = None
                valid = False
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    except Exception:
                        try:
                            exp = datetime.fromisoformat(not_after)
                        except Exception:
                            exp = None
                    if exp:
                        days = (exp - datetime.utcnow()).days
                        valid = days >= 0
                return True, valid, days, None
    except Exception as e:
        return False, False, None, str(e)

def domain_age_days(url_or_domain: str):
    try:
        ext = tldextract.extract(url_or_domain)
        reg = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or None
        if not reg:
            reg = (url_or_domain.split("//")[-1].split("/")[0]).split(":")[0]
        w = whois.whois(reg)
        creation = getattr(w, "creation_date", None) or getattr(w, "created", None)
        if creation is None:
            return None, "no creation date"
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, str):
            try:
                creation = datetime.fromisoformat(creation)
            except Exception:
                try:
                    creation = datetime.strptime(creation, "%Y-%m-%d")
                except Exception:
                    return None, f"unparsed creation_date string: {creation}"
        if isinstance(creation, datetime):
            return (datetime.utcnow() - creation).days, None
        return None, f"unknown creation_date type: {type(creation)}"
    except Exception as e:
        return None, str(e)

def virustotal_report(url: str):
    """Synchronous VirusTotal call — caller should run this inside a background thread."""
    if not VT_API_KEY:
        return None
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
        if r.status_code not in (200, 201):
            return {"error": f"VT submit error {r.status_code}"}
        job = r.json()
        aid = job.get("data", {}).get("id")
        if not aid:
            return {"error": "no vt analysis id"}
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{aid}"
        start = datetime.utcnow()
        while True:
            rr = requests.get(analysis_url, headers=headers, timeout=10)
            if rr.status_code != 200:
                return {"error": f"vt analysis code {rr.status_code}"}
            aj = rr.json()
            status = aj.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = aj.get("data", {}).get("attributes", {}).get("stats", {})
                return {"stats": stats}
            if (datetime.utcnow() - start).seconds > 15:
                return {"error": "vt timeout"}
    except Exception as e:
        return {"error": str(e)}

# --- Load ML model if available ---
_model = None
_model_features = None
if os.path.exists(MODEL_FILENAME):
    try:
        saved = joblib.load(MODEL_FILENAME)
        if isinstance(saved, dict):
            _model = saved.get("model", saved)
            _model_features = saved.get("features", None)
        else:
            _model = saved
        print(f"[startup] Loaded ML model from {MODEL_FILENAME}")
    except Exception as e:
        print(f"[startup] Failed to load model {MODEL_FILENAME}: {e}")
        _model = None
else:
    print(f"[startup] Model file not found ({MODEL_FILENAME}) - running heuristic fallback")

# ---------- GUI ----------
def safe_open_image(path, size):
    try:
        img = Image.open(path)
        img = img.resize(size, Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception:
        return None

class PhishGUI:
    def _init_(self, root):
        self.root = root
        root.title("Phishing Detection — Professional")
        root.geometry("980x640")
        root.minsize(900, 600)

        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TButton", padding=6)
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Small.TLabel", font=("Segoe UI", 10))
        style.configure("Badge.TLabel", font=("Segoe UI", 12, "bold"))

        top_frame = ttk.Frame(root)
        top_frame.pack(fill="x", padx=10, pady=8)

        banner = safe_open_image(BANNER_FILENAME, (320, 110)) if os.path.exists(BANNER_FILENAME) else None
        if banner:
            self.banner_label = ttk.Label(top_frame, image=banner)
            self.banner_label.image = banner
            self.banner_label.pack(side="left", padx=(0,10))
        else:
            self.banner_canvas = tk.Canvas(top_frame, width=320, height=110, bg="#e6eef2", highlightthickness=0)
            self.banner_canvas.create_text(160, 55, text="PHISHING DETECTOR", font=("Verdana", 18, "bold"), fill="#1f7a8c")
            self.banner_canvas.pack(side="left", padx=(0,10))

        title_label = ttk.Label(top_frame, text="Phishing Detection Website", style="Header.TLabel", foreground="#1f7a8c")
        title_label.pack(anchor="nw", padx=6)

        main = ttk.Frame(root)
        main.pack(fill="both", expand=True, padx=10, pady=(0,10))

        left = ttk.Frame(main, width=300)
        left.pack(side="left", fill="y", padx=(0,10))

        input_card = ttk.LabelFrame(left, text="Check URL", padding=10)
        input_card.pack(fill="x", pady=(0,10))

        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(input_card, textvariable=self.url_var, font=("Segoe UI", 11))
        url_entry.pack(fill="x", padx=4, pady=(0,8))
        url_entry.bind("<Return>", lambda e: self.run_check())

        btn_frame = ttk.Frame(input_card)
        btn_frame.pack(fill="x")
        self.check_btn = ttk.Button(btn_frame, text="Check Now", command=self.run_check)
        self.check_btn.pack(side="left")
        self.clear_btn = ttk.Button(btn_frame, text="Clear", command=self._clear_input)
        self.clear_btn.pack(side="left", padx=6)

        hist_card = ttk.LabelFrame(left, text="History", padding=6)
        hist_card.pack(fill="both", expand=True)
        self.history_list = tk.Listbox(hist_card, height=12)
        self.history_list.pack(fill="both", expand=True, padx=4, pady=4)
        self.history_list.bind("<Double-Button-1>", self._load_from_history)

        hist_actions = ttk.Frame(hist_card)
        hist_actions.pack(fill="x")
        ttk.Button(hist_actions, text="Open", command=self._open_selected).pack(side="left")
        ttk.Button(hist_actions, text="Copy", command=self._copy_selected).pack(side="left", padx=6)
        ttk.Button(hist_actions, text="Clear All", command=self._clear_history).pack(side="left")

        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True)

        header = ttk.Frame(right)
        header.pack(fill="x")

        self.result_badge = ttk.Label(header, text="—", style="Badge.TLabel", background="#f0f0f0", anchor="center")
        self.result_badge.pack(side="left", padx=(0,6), ipady=6, ipadx=12)

        self.status_var = tk.StringVar(value="Idle")
        self.status_label = ttk.Label(header, textvariable=self.status_var, style="Small.TLabel")
        self.status_label.pack(side="left", padx=6)

        action_row = ttk.Frame(right)
        action_row.pack(fill="x", pady=(8,6))
        ttk.Button(action_row, text="Copy Result", command=self.copy_result).pack(side="left")
        ttk.Button(action_row, text="Open URL", command=self.open_in_browser).pack(side="left", padx=6)
        ttk.Button(action_row, text="Save Report", command=self.save_report).pack(side="left", padx=6)

        details_split = ttk.Panedwindow(right, orient="horizontal")
        details_split.pack(fill="both", expand=True)

        left_details = ttk.Frame(details_split)
        details_split.add(left_details, weight=1)
        tree_frame = ttk.LabelFrame(left_details, text="Features / Metadata", padding=6)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=4)

        self.tree = ttk.Treeview(tree_frame, columns=("value",), show="headings", selectmode="browse")
        self.tree.heading("value", text="Value")
        self.tree.pack(fill="both", expand=True)

        right_details = ttk.Frame(details_split)
        details_split.add(right_details, weight=1)
        log_frame = ttk.LabelFrame(right_details, text="Detailed Report", padding=6)
        log_frame.pack(fill="both", expand=True, padx=4, pady=4)

        self.log = ScrolledText(log_frame, wrap="word", height=18, font=("Segoe UI", 10))
        self.log.pack(fill="both", expand=True)

        bottom = ttk.Frame(root)
        bottom.pack(fill="x", padx=10, pady=(0,8))
        self.progress = ttk.Progressbar(bottom, mode="indeterminate")
        self.progress.pack(fill="x", side="left", expand=True)
        self.time_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=self.time_var, width=24).pack(side="right", padx=(6,0))

        self.history = []
        self.last_report = None

    # UI helpers
    def _clear_input(self):
        self.url_var.set("")

    def _add_history(self, url):
        if url in self.history:
            return
        self.history.insert(0, url)
        self.history_list.insert(0, url)

    def _load_from_history(self, event=None):
        sel = self.history_list.curselection()
        if sel:
            url = self.history_list.get(sel[0])
            self.url_var.set(url)

    def _open_selected(self):
        sel = self.history_list.curselection()
        if sel:
            url = self.history_list.get(sel[0])
            webbrowser.open(url)

    def _copy_selected(self):
        sel = self.history_list.curselection()
        if sel:
            url = self.history_list.get(sel[0])
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            messagebox.showinfo("Copied", "URL copied to clipboard")

    def _clear_history(self):
        if messagebox.askyesno("Clear history", "Clear all history?"):
            self.history = []
            self.history_list.delete(0, tk.END)

    def _set_badge(self, label_text):
        text = label_text
        bg = "#cccccc"
        if "PHISHING" in label_text or "SUSPICIOUS" in label_text:
            bg = "#ffcccc"
        elif "LEGIT" in label_text:
            bg = "#ccffdd"
        try:
            self.result_badge.configure(text=text, background=bg)
        except Exception:
            self.result_badge.configure(text=text)

    def _set_status(self, text):
        self.status_var.set(text)
        self.time_var.set(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))

    def _clear_tree_and_log(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        self.log.delete("1.0", tk.END)

    # Main check flow
    def run_check(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input required", "Please enter a website URL.")
            return

        self.check_btn.state(["disabled"])
        self._set_status("Checking...")
        self._set_badge("—")
        self._clear_tree_and_log()
        self.progress.start(10)

        def worker():
            try:
                features = extract_simple_features(url)
                host = features.get("host", url.split("//")[-1].split("/")[0])

                ml_pred = None
                ml_used = False
                ml_error = None
                if _model:
                    try:
                        import pandas as pd
                        df = pd.DataFrame([features])
                        if _model_features:
                            for c in _model_features:
                                if c not in df.columns:
                                    df[c] = 0
                            df = df[_model_features]
                        ml_pred = int(_model.predict(df)[0])
                        ml_used = True
                    except Exception as me:
                        ml_error = str(me)
                        ml_used = False

                fallback_score = 0
                if features.get("suspicious_words", 0):
                    fallback_score += 3
                if features.get("has_at", 0):
                    fallback_score += 2
                if features.get("has_ip", 0):
                    fallback_score += 2
                if features.get("has_hyphen", 0):
                    fallback_score += 1
                if features.get("has_https", 0) == 0:
                    fallback_score += 1
                if features.get("double_slash", 0) > 0:
                    fallback_score += 1
                if features.get("num_subdomain", 0) >= 3:
                    fallback_score += 1

                if ml_used:
                    final_label = "PHISHING ⚠" if ml_pred == 1 else "LIKELY LEGIT ✅"
                else:
                    if fallback_score >= 4:
                        final_label = "PHISHING ⚠"
                    elif fallback_score >= 2:
                        final_label = "SUSPICIOUS ⚠"
                    else:
                        final_label = "LIKELY LEGIT ✅"

                ssl_ok, ssl_valid, ssl_days, ssl_err = check_ssl(host)
                age_days, age_err = domain_age_days(url)

                report_lines = []
                report_lines.append(f"URL: {url}")
                report_lines.append(f"Final label: {final_label}")
                report_lines.append(f"Model used: {'yes' if ml_used else 'no (fallback)'}")
                if ml_used:
                    report_lines.append(f"Model prediction: {ml_pred}")
                else:
                    if ml_error:
                        report_lines.append(f"Model error: {ml_error}")
                    report_lines.append(f"Fallback score: {fallback_score}")

                feature_items = [
                    ("host", features.get("host")),
                    ("url_length", features.get("url_length")),
                    ("has_https", features.get("has_https")),
                    ("has_at", features.get("has_at")),
                    ("has_ip", features.get("has_ip")),
                    ("has_hyphen", features.get("has_hyphen")),
                    ("matched_suspicious_words", ", ".join(features.get("matched_suspicious_words") or []) or "none"),
                    ("num_subdomain", features.get("num_subdomain")),
                    ("double_slash", features.get("double_slash")),
                ]

                if ssl_err:
                    report_lines.append(f"SSL: error — {ssl_err}")
                else:
                    report_lines.append(f"SSL available: {ssl_ok}, cert_valid: {ssl_valid}, days_left: {ssl_days}")
                if age_err:
                    report_lines.append(f"WHOIS: error — {age_err}")
                else:
                    report_lines.append(f"Domain age days: {age_days}")

                vt_result = None
                if VT_API_KEY:
                    report_lines.append("VirusTotal: querying...")
                    try:
                        vt = virustotal_report(url)
                        vt_result = vt
                        if vt is None:
                            report_lines.append("VirusTotal: no API key or error (skipped)")
                        elif "error" in vt:
                            report_lines.append(f"VirusTotal error: {vt.get('error')}")
                        else:
                            report_lines.append(f"VirusTotal stats: {vt.get('stats')}")
                    except Exception as e:
                        report_lines.append(f"VirusTotal error: {e}")

                final_text = "\n".join(report_lines)
                self.last_report = {
                    "url": url, "final_label": final_label, "features": feature_items,
                    "ssl": (ssl_ok, ssl_valid, ssl_days, ssl_err), "whois": (age_days, age_err),
                    "vt": vt_result, "full_text": final_text
                }

                def ui_update():
                    self._set_badge(final_label)
                    self._set_status("Done")
                    try:
                        self.progress.stop()
                    except Exception:
                        pass
                    self.check_btn.state(["!disabled"])
                    for k, v in feature_items:
                        self.tree.insert("", "end", values=(f"{k}: {v}",))
                    self.log.delete("1.0", tk.END)
                    self.log.insert(tk.END, final_text + "\n")
                    self._add_history(url)

                self.root.after(0, ui_update)

            except Exception as e:
                def err_ui():
                    try:
                        self.progress.stop()
                    except Exception:
                        pass
                    self.check_btn.state(["!disabled"])
                    self._set_status("Error")
                    messagebox.showerror("Error", str(e))
                self.root.after(0, err_ui)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
class PhishGUI:
        def _init_(self, root):
        self.root = root
        self.root.title("Phishing Detection GUI")
        # Add your widgets below, example:
        # label = tk.Label(root, text="Welcome to Phishing Detection App")
        # label.pack(pady=20)
        # def save_report(self):
        if not getattr(self, "last_report", None):
            messagebox.showinfo("No report", "No report to save.")
            return
        fn = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not fn:
            return
        with open(fn, "w", encoding="utf-8") as f:
            f.write(self.last_report["full_text"])
        messagebox.showinfo("Saved", f"Report saved to {fn}")


if _name_ == "_main_":
    import tkinter as tk
    from tkinter import messagebox, filedialog

    root = tk.Tk()
    app = PhishGUI(root)
root.mainloop()