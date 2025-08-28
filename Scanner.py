import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from urllib.parse import urljoin
import threading

class DarkVulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Dark Vulnerability Scanner")
        self.root.geometry("900x700")
        self.root.configure(bg="#1e1e1e")
        
        # Configure style for dark theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.bg_color = "#1e1e1e"
        self.card_bg = "#2d2d2d"
        self.text_color = "#e0e0e0"
        self.accent_color = "#007acc"
        self.button_color = "#3c3c3c"
        
        # Configure styles
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TLabelframe', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color)
        self.style.configure('TButton', background=self.button_color, foreground=self.text_color)
        self.style.configure('TEntry', fieldbackground=self.card_bg, foreground=self.text_color)
        self.style.configure('TCheckbutton', background=self.bg_color, foreground=self.text_color)
        self.style.configure('Horizontal.TProgressbar', background=self.accent_color)
        
        # Variables
        self.scanning = False
        
        # Create widgets
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Target URL
        ttk.Label(main_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.url_entry.insert(0, "https://example.com")
        
        # Test button
        test_btn = ttk.Button(main_frame, text="Test Connection", command=self.test_connection)
        test_btn.grid(row=0, column=2, padx=(5, 0), pady=5)
        
        # Scan options
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="5")
        options_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        options_frame.columnconfigure(0, weight=1)
        
        self.sql_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.headers_var = tk.BooleanVar(value=True)
        self.cors_var = tk.BooleanVar(value=True)
        self.info_var = tk.BooleanVar(value=True)
        self.paths_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="SQL Injection", variable=self.sql_var).grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="XSS", variable=self.xss_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Security Headers", variable=self.headers_var).grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="CORS", variable=self.cors_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Information Disclosure", variable=self.info_var).grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Common Paths", variable=self.paths_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        self.scan_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        clear_btn = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = ttk.Button(button_frame, text="Export Report", command=self.export_report)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready to scan")
        self.status_label.grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=(0, 5))
        
        # Results notebook
        self.results_notebook = ttk.Notebook(main_frame)
        self.results_notebook.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Vulnerabilities tab
        vuln_frame = ttk.Frame(self.results_notebook, padding="5")
        self.results_notebook.add(vuln_frame, text="Vulnerabilities")
        
        self.vuln_text = scrolledtext.ScrolledText(
            vuln_frame, 
            wrap=tk.WORD, 
            height=15,
            bg="#252526",
            fg="#e0e0e0",
            insertbackground="white",
            selectbackground="#37373d"
        )
        self.vuln_text.pack(fill=tk.BOTH, expand=True)
        
        # Info tab
        info_frame = ttk.Frame(self.results_notebook, padding="5")
        self.results_notebook.add(info_frame, text="Information")
        
        self.info_text = scrolledtext.ScrolledText(
            info_frame, 
            wrap=tk.WORD, 
            height=15,
            bg="#252526",
            fg="#e0e0e0",
            insertbackground="white",
            selectbackground="#37373d"
        )
        self.info_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for coloring
        self.vuln_text.tag_config("CRITICAL", foreground="#ff6b6b")
        self.vuln_text.tag_config("HIGH", foreground="#ff9e6b")
        self.vuln_text.tag_config("MEDIUM", foreground="#ffcb6b")
        self.vuln_text.tag_config("LOW", foreground="#a3eea0")
        
    def test_connection(self):
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        self.status_label.config(text="Testing connection...")
        try:
            response = requests.get(target_url, timeout=10)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Connection successful! Ready to scan.")
                self.status_label.config(text="Connection successful")
            else:
                messagebox.showwarning("Warning", f"Connection returned status code: {response.status_code}")
                self.status_label.config(text=f"Status: {response.status_code}")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            self.status_label.config(text="Connection failed")
    
    def start_scan(self):
        if self.scanning:
            return
            
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        # Clear previous results
        self.clear_results()
        
        # Start scan in separate thread
        self.scanning = True
        self.scan_btn.config(state='disabled')
        self.progress.start()
        self.status_label.config(text="Scanning...")
        
        scan_thread = threading.Thread(target=self.run_scan, args=(target_url,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self, target_url):
        try:
            scanner = SimpleScanner(target_url)
            stats = {'vulnerabilities': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            # Security headers check
            if self.headers_var.get():
                self.update_status("Checking security headers...")
                headers_vulns = scanner.check_security_headers()
                for vuln in headers_vulns:
                    self.log_vulnerability("MEDIUM", "Missing security header", vuln)
                    stats['medium'] += 1
                    stats['vulnerabilities'] += 1
            
            # CORS misconfigurations
            if self.cors_var.get():
                self.update_status("Checking CORS settings...")
                cors_vulns = scanner.check_cors()
                for vuln in cors_vulns:
                    self.log_vulnerability("HIGH", "Misconfigured CORS", vuln)
                    stats['high'] += 1
                    stats['vulnerabilities'] += 1
            
            # Information disclosure
            if self.info_var.get():
                self.update_status("Looking for information disclosure...")
                info_vulns = scanner.check_info_disclosure()
                for vuln in info_vulns:
                    self.log_vulnerability("LOW", "Information disclosure", vuln)
                    stats['low'] += 1
                    stats['vulnerabilities'] += 1
            
            # Hidden paths
            if self.paths_var.get():
                self.update_status("Searching for hidden paths...")
                found_paths = scanner.scan_common_files()
                for path in found_paths:
                    self.log_vulnerability("MEDIUM", "Exposed sensitive path", path)
                    stats['medium'] += 1
                    stats['vulnerabilities'] += 1
            
            # SQL Injection
            if self.sql_var.get():
                self.update_status("Checking for SQL Injection vulnerabilities...")
                if scanner.check_sql_injection(target_url + "/test?id=1"):
                    self.log_vulnerability("CRITICAL", "SQL Injection vulnerability", 
                                         "Potential SQL injection vulnerability detected")
                    stats['critical'] += 1
                    stats['vulnerabilities'] += 1
                else:
                    self.log_info("No obvious SQL Injection vulnerabilities detected")
            
            # XSS
            if self.xss_var.get():
                self.update_status("Checking for XSS vulnerabilities...")
                if scanner.check_xss(target_url + "/search?q=test"):
                    self.log_vulnerability("HIGH", "XSS vulnerability", 
                                         "Potential XSS vulnerability detected")
                    stats['high'] += 1
                    stats['vulnerabilities'] += 1
                else:
                    self.log_info("No obvious XSS vulnerabilities detected")
            
            # Update statistics
            self.update_stats(stats)
            self.update_status("Scan completed successfully")
            
        except Exception as e:
            self.log_vulnerability("HIGH", "Scan error", f"An error occurred during scanning: {str(e)}")
            self.update_status("Scan completed with errors")
        
        finally:
            self.scanning = False
            self.root.after(0, self.scan_finished)
    
    def scan_finished(self):
        self.progress.stop()
        self.scan_btn.config(state='normal')
    
    def update_status(self, message):
        def update():
            self.status_label.config(text=message)
        self.root.after(0, update)
    
    def log_vulnerability(self, severity, title, details):
        def update():
            text_widget = self.vuln_text
            text_widget.insert(tk.END, f"[{severity}] {title}\n", severity)
            text_widget.insert(tk.END, f"   Details: {details}\n\n")
            text_widget.see(tk.END)
        
        self.root.after(0, update)
    
    def log_info(self, message):
        def update():
            self.info_text.insert(tk.END, f"• {message}\n")
            self.info_text.see(tk.END)
        
        self.root.after(0, update)
    
    def update_stats(self, stats):
        def update():
            self.info_text.insert(tk.END, "\nScan Statistics\n", "bold")
            self.info_text.insert(tk.END, "=" * 50 + "\n")
            self.info_text.insert(tk.END, f"Total Vulnerabilities: {stats['vulnerabilities']}\n")
            self.info_text.insert(tk.END, f"Critical: {stats['critical']}\n", "CRITICAL")
            self.info_text.insert(tk.END, f"High: {stats['high']}\n", "HIGH")
            self.info_text.insert(tk.END, f"Medium: {stats['medium']}\n", "MEDIUM")
            self.info_text.insert(tk.END, f"Low: {stats['low']}\n", "LOW")
        
        self.root.after(0, update)
    
    def clear_results(self):
        self.vuln_text.delete(1.0, tk.END)
        self.info_text.delete(1.0, tk.END)
        self.status_label.config(text="Ready to scan")
    
    def export_report(self):
        messagebox.showinfo("Export", "Export report functionality will be implemented here")


class SimpleScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_security_headers(self):
        vulnerabilities = []
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'X-Frame-Options header missing - clickjacking risk',
                'X-Content-Type-Options': 'X-Content-Type-Options header missing - MIME sniffing risk',
                'X-XSS-Protection': 'X-XSS-Protection header missing - XSS protection risk',
                'Strict-Transport-Security': 'HSTS header missing - HTTPS enforcement risk',
                'Content-Security-Policy': 'CSP header missing - injection attacks risk'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append(description)
            
        except Exception as e:
            vulnerabilities.append(f"Error checking headers: {str(e)}")
        
        return vulnerabilities
    
    def check_cors(self):
        vulnerabilities = []
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            if 'Access-Control-Allow-Origin' in headers:
                if headers['Access-Control-Allow-Origin'] == '*':
                    vulnerabilities.append("CORS policy allows all origins (*)")
            
        except Exception as e:
            vulnerabilities.append(f"Error checking CORS: {str(e)}")
        
        return vulnerabilities
    
    def check_info_disclosure(self):
        vulnerabilities = []
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check for common information disclosure patterns
            info_patterns = [
                'phpinfo', 'debug', 'test', 'version', 'database',
                'password', 'config', 'admin', 'backup', '.git'
            ]
            
            for pattern in info_patterns:
                if pattern in response.text.lower():
                    vulnerabilities.append(f"Potential information disclosure: {pattern}")
            
        except Exception as e:
            vulnerabilities.append(f"Error checking information disclosure: {str(e)}")
        
        return vulnerabilities
    
    def scan_common_files(self):
        common_paths = [
            "/admin", "/login", "/config.php", "/backup", "/.env",
            "/phpinfo.php", "/test.php", "/wp-admin", "/administrator",
            "/server-status", "/.git", "/.htaccess", "/robots.txt",
            "/backup.zip", "/database.sql", "/web.config"
        ]
        
        found_paths = []
        for path in common_paths:
            full_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(full_url, timeout=5)
                if response.status_code == 200:
                    found_paths.append(full_url)
            except:
                continue
                
        return found_paths
    
    def check_sql_injection(self, url):
        payloads = ["'", "\"", "' OR '1'='1", "' UNION SELECT null--", "'; DROP TABLE users--"]
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if any(error in response.text.lower() for error in ["sql", "syntax", "mysql", "ora-"]):
                    return True
            except:
                continue
                
        return False
    
    def check_xss(self, url):
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if payload in response.text:
                    return True
            except:
                continue
                
        return False


if __name__ == "__main__":
    root = tk.Tk()
    app = DarkVulnerabilityScanner(root)
    root.mainloop()
