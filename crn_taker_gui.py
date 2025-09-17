import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import requests
import json
import time
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import queue

class CRNMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ITU OBS CRN Monitor")
        self.root.geometry("800x700")
        
        # Variables
        self.session = None
        self.bearer_token = None
        self.monitoring = False
        self.monitor_thread = None
        
        # Queue for thread-safe console updates
        self.console_queue = queue.Queue()
        
        self.setup_ui()
        self.check_console_queue()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        # Login Section
        login_frame = ttk.LabelFrame(main_frame, text="Login Credentials", padding="10")
        login_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        login_frame.columnconfigure(1, weight=1)
        
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(login_frame, textvariable=self.username_var, width=30)
        self.username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(login_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # CRN Section
        crn_frame = ttk.LabelFrame(main_frame, text="CRN Configuration", padding="10")
        crn_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        crn_frame.columnconfigure(1, weight=1)
        
        ttk.Label(crn_frame, text="CRNs to Add:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ecrn_var = tk.StringVar(value="22661, 22662, 22634, 22636")
        self.ecrn_entry = ttk.Entry(crn_frame, textvariable=self.ecrn_var, width=50)
        self.ecrn_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(crn_frame, text="CRNs to Remove:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.scrn_var = tk.StringVar()
        self.scrn_entry = ttk.Entry(crn_frame, textvariable=self.scrn_var, width=50)
        self.scrn_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(crn_frame, text="Check Interval (seconds):").grid(row=2, column=0, sticky=tk.W, padx=(0, 10))
        self.interval_var = tk.StringVar(value="3.5")
        self.interval_entry = ttk.Entry(crn_frame, textvariable=self.interval_var, width=10)
        self.interval_entry.grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.login_button = ttk.Button(button_frame, text="Login", command=self.login)
        self.login_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.start_button = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Console", command=self.clear_console)
        self.clear_button.pack(side=tk.LEFT)
        
        # Status
        self.status_var = tk.StringVar(value="Ready - Enter credentials and click Login")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Console Output
        console_frame = ttk.LabelFrame(main_frame, text="Console Output", padding="10")
        console_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        
        self.console_text = scrolledtext.ScrolledText(console_frame, height=20, width=80, state=tk.DISABLED)
        self.console_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Add some helpful text
        self.log("ITU OBS CRN Monitor v1.0")
        self.log("Enter your credentials and CRNs, then click Login to start.")
        self.log("CRNs should be comma-separated (e.g., 22661, 22662, 22634)")
        
    def log(self, message):
        """Thread-safe logging to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_queue.put(f"[{timestamp}] {message}")
        
    def check_console_queue(self):
        """Check for console updates from background threads"""
        try:
            while True:
                message = self.console_queue.get_nowait()
                self.console_text.config(state=tk.NORMAL)
                self.console_text.insert(tk.END, message + "\n")
                self.console_text.see(tk.END)
                self.console_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.check_console_queue)
            
    def clear_console(self):
        """Clear the console output"""
        self.console_text.config(state=tk.NORMAL)
        self.console_text.delete(1.0, tk.END)
        self.console_text.config(state=tk.DISABLED)
        
    def login(self):
        """Perform login in background thread"""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        self.login_button.config(state=tk.DISABLED)
        self.status_var.set("Logging in...")
        
        # Start login in background thread
        login_thread = threading.Thread(target=self._login_worker, args=(username, password))
        login_thread.daemon = True
        login_thread.start()
        
    def _login_worker(self, username, password):
        """Background login worker"""
        try:
            self.log("Starting login process...")
            
            # Create session
            self.session = requests.Session()
            
            # Step 1: Get redirect
            self.log("Getting login redirect...")
            subsession, loc = self.get_login_redirect()
            
            if not loc:
                self.log("❌ Failed to get login redirect")
                self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.status_var.set("Login failed - no redirect"))
                return
                
            # Step 2: Perform login
            self.log("Performing authentication...")
            login_resp, login_success = self.do_login(loc, username, password)
            
            if not login_success:
                self.log("❌ Login failed")
                self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.status_var.set("Login failed"))
                return
                
            # Step 3: Get JWT token
            self.log("Getting JWT token...")
            self.bearer_token = self.get_jwt_token()
            
            if not self.bearer_token:
                self.log("❌ Failed to get JWT token")
                self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.status_var.set("Failed to get JWT token"))
                return
                
            self.log(f"✅ Login successful! JWT token obtained: {self.bearer_token[:50]}...")
            
            # Update UI in main thread
            self.root.after(0, self.login_success)
            
        except Exception as e:
            self.log(f"❌ Login error: {str(e)}")
            self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.status_var.set(f"Login error: {str(e)}"))
            
    def login_success(self):
        """Called when login succeeds"""
        self.login_button.config(state=tk.NORMAL)
        self.start_button.config(state=tk.NORMAL)
        self.status_var.set("✅ Logged in successfully - Ready to monitor")
        
    def start_monitoring(self):
        """Start CRN monitoring"""
        if self.monitoring:
            return
            
        ecrn_text = self.ecrn_var.get().strip()
        scrn_text = self.scrn_var.get().strip()
        
        if not ecrn_text:
            messagebox.showerror("Error", "Please enter at least one CRN to add")
            return
            
        try:
            interval = float(self.interval_var.get())
            if interval < 1:
                raise ValueError("Interval must be at least 1 second")
        except ValueError:
            messagebox.showerror("Error", "Invalid interval value")
            return
            
        self.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("🔄 Monitoring CRNs...")
        
        # Parse CRNs
        ecrns = [crn.strip() for crn in ecrn_text.split(",") if crn.strip()]
        scrns = [crn.strip() for crn in scrn_text.split(",") if crn.strip()] if scrn_text else []
        
        self.log(f"Starting CRN monitoring with {len(ecrns)} CRNs to add, {len(scrns)} to remove")
        self.log(f"Check interval: {interval} seconds")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_worker, args=(ecrns, scrns, interval))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop CRN monitoring"""
        self.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("⏹️ Monitoring stopped")
        self.log("Monitoring stopped by user")
        
    def _monitor_worker(self, ecrns, scrns, interval):
        """Background monitoring worker"""
        while self.monitoring:
            try:
                self.make_crn_request(ecrns, scrns)
                time.sleep(interval)
            except Exception as e:
                self.log(f"❌ Monitoring error: {str(e)}")
                time.sleep(interval)
                
    # Login helper methods (adapted from original script)
    def get_login_redirect(self):
        """Get initial login redirect"""
        LOGIN_START_URL = "https://obs.itu.edu.tr/login/auth/login"
        COMMON_HEADERS = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8,tr;q=0.7",
            "Upgrade-Insecure-Requests": "1",
        }
        
        resp = self.session.get(LOGIN_START_URL, headers=COMMON_HEADERS, allow_redirects=False)
        self.log(f"Initial request status: {resp.status_code}")
        
        loc = resp.headers.get("Location")
        subsession = None
        if loc:
            parsed = urlparse(loc)
            subsession = parse_qs(parsed.query).get("subSessionId", [None])[0]
            
        self.log(f"subSessionId: {subsession}")
        return subsession, loc
        
    def scrape_hidden_fields(self, html, name):
        """Extract hidden form fields"""
        m = re.search(r'id="%s" value="([^"]*)"' % name, html)
        return m.group(1) if m else ""
        
    def do_login(self, login_url, username, password):
        """Perform the actual login"""
        COMMON_HEADERS = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8,tr;q=0.7",
            "Upgrade-Insecure-Requests": "1",
        }
        
        # Get login page
        resp = self.session.get(login_url, headers=COMMON_HEADERS)
        html = resp.text
        
        # Extract form fields
        viewstate = self.scrape_hidden_fields(html, "__VIEWSTATE")
        viewstategen = self.scrape_hidden_fields(html, "__VIEWSTATEGENERATOR")
        eventval = self.scrape_hidden_fields(html, "__EVENTVALIDATION")
        
        # Prepare payload
        payload = {
            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "__VIEWSTATE": viewstate,
            "__VIEWSTATEGENERATOR": viewstategen,
            "__EVENTVALIDATION": eventval,
            "ctl00$ContentPlaceHolder1$hfAppName": "Öğrenci Bilgi Sistemi",
            "ctl00$ContentPlaceHolder1$hfToken": "",
            "ctl00$ContentPlaceHolder1$hfVerifier": "",
            "ctl00$ContentPlaceHolder1$hfCode": "",
            "ctl00$ContentPlaceHolder1$hfState": "",
            "ctl00$ContentPlaceHolder1$tbUserName": username,
            "ctl00$ContentPlaceHolder1$tbPassword": password,
            "ctl00$ContentPlaceHolder1$btnLogin": "Giriş / Login",
        }
        
        headers = {
            **COMMON_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://girisv3.itu.edu.tr",
            "Referer": login_url,
        }
        
        # Submit login
        resp2 = self.session.post(login_url, headers=headers, data=payload, allow_redirects=True)
        self.log(f"Login POST status: {resp2.status_code}")
        
        # Check for required cookies
        has_ogrenci = any(c.name == "OgrenciCookie" for c in self.session.cookies)
        has_login = any(c.name == "LoginCookie" for c in self.session.cookies)
        
        success = "obs.itu.edu.tr" in resp2.url and has_ogrenci and has_login
        self.log(f"Login success: {success} (OgrenciCookie: {has_ogrenci}, LoginCookie: {has_login})")
        
        return resp2, success
        
    def get_jwt_token(self):
        """Get JWT token from auth endpoint"""
        url = "https://obs.itu.edu.tr/ogrenci/auth/jwt"
        headers = {
            "accept": "application/json, text/plain, */*",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
        }
        
        try:
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                token = response.text.strip().strip('"')
                return token if len(token) > 50 else None
        except Exception as e:
            self.log(f"JWT error: {e}")
            
        return None
        
    def make_crn_request(self, ecrns, scrns):
        """Make CRN registration request"""
        url = "https://obs.itu.edu.tr/api/ders-kayit/v21"
        payload = {
            "ECRN": ecrns,
            "SCRN": scrns
        }
        
        headers = {
            "accept": "application/json, text/plain, */*",
            "authorization": f"Bearer {self.bearer_token}",
            "content-type": "application/json",
            "origin": "https://obs.itu.edu.tr",
            "referer": "https://obs.itu.edu.tr/ogrenci/DersKayitIslemleri/DersKayit",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
        }
        
        try:
            response = self.session.post(url, headers=headers, json=payload)
            current_time = datetime.now().strftime("%H:%M:%S")
            
            if response.status_code == 200:
                response_json = response.json()
                if "ecrnResultList" in response_json:
                    self.log(f"[{current_time}] CRN Check Results:")
                    for result in response_json["ecrnResultList"]:
                        crn = result.get("crn", "Unknown")
                        status = result.get("statusCode", "Unknown")
                        result_code = result.get("resultCode", "Unknown")
                        message = result.get("message", "")
                        
                        log_msg = f"  CRN {crn}: Status={status}, Result={result_code}"
                        if message:
                            log_msg += f", Message={message}"
                        self.log(log_msg)
                        
                        # Highlight successful registrations
                        if status == "SUCCESS" or result_code == "SUCCESS":
                            self.log(f"🎉 SUCCESS! CRN {crn} registration successful!")
                else:
                    self.log(f"[{current_time}] No CRN results in response")
            else:
                self.log(f"[{current_time}] API Error: {response.status_code} - {response.text}")
                
        except Exception as e:
            self.log(f"❌ CRN request error: {str(e)}")

def main():
    root = tk.Tk()
    app = CRNMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()