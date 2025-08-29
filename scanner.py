import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
from urllib.parse import urljoin, urlparse
import threading
import time
import json
import csv
from datetime import datetime
import socket
import ssl
import re
import subprocess
import sys
from bs4 import BeautifulSoup

class DarkVulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Dark Vulnerability Scanner Pro")
        self.root.geometry("1000x800")
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
        self.critical_color = "#ff5252"
        self.high_color = "#ff7b7b"
        self.medium_color = "#ffb46b"
        self.low_color = "#a3eea0"
        self.info_color = "#6bc5ff"
        
        # Configure styles
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TLabelframe', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color)
        self.style.configure('TButton', background=self.button_color, foreground=self.text_color)
        self.style.configure('TEntry', fieldbackground=self.card_bg, foreground=self.text_color)
        self.style.configure('TCheckbutton', background=self.bg_color, foreground=self.text_color)
        self.style.configure('Horizontal.TProgressbar', background=self.accent_color)
        self.style.configure('TCombobox', fieldbackground=self.card_bg, foreground=self.text_color)
        
        # Variables
        self.scanning = False
        self.scan_thread = None
        self.scan_results = []
        self.current_scan_id = None
        
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
        main_frame.rowconfigure(6, weight=1)
        
        # Scan ID and timestamp
        id_frame = ttk.Frame(main_frame)
        id_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(id_frame, text="Scan ID:").pack(side=tk.LEFT)
        self.scan_id_var = tk.StringVar(value=f"SCAN-{int(time.time())}")
        ttk.Label(id_frame, textvariable=self.scan_id_var).pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Label(id_frame, text="Start Time:").pack(side=tk.LEFT)
        self.start_time_var = tk.StringVar(value="Not started")
        ttk.Label(id_frame, textvariable=self.start_time_var).pack(side=tk.LEFT, padx=(5, 0))
        
        # Target URL
        ttk.Label(main_frame, text="Target URL:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.url_entry.insert(0, "https://example.com")
        
        # Scan depth
        ttk.Label(main_frame, text="Scan Depth:").grid(row=1, column=2, sticky=tk.W, padx=(10, 0), pady=5)
        self.depth_var = tk.StringVar(value="Medium")
        depth_combo = ttk.Combobox(main_frame, textvariable=self.depth_var, 
                                  values=["Light", "Medium", "Deep", "Intensive"], width=10)
        depth_combo.grid(row=1, column=3, padx=(5, 0), pady=5, sticky=tk.W)
        
        # Test button
        test_btn = ttk.Button(main_frame, text="Test Connection", command=self.test_connection)
        test_btn.grid(row=2, column=0, sticky=tk.W, pady=5)
        
        # Scan options
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="5")
        options_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        options_frame.columnconfigure(0, weight=1)
        
        self.sql_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.headers_var = tk.BooleanVar(value=True)
        self.cors_var = tk.BooleanVar(value=True)
        self.info_var = tk.BooleanVar(value=True)
        self.paths_var = tk.BooleanVar(value=True)
        self.ssl_var = tk.BooleanVar(value=True)
        self.subdomain_var = tk.BooleanVar(value=False)
        self.ports_var = tk.BooleanVar(value=False)
        self.crlf_var = tk.BooleanVar(value=True)
        self.jwt_var = tk.BooleanVar(value=False)
        self.backup_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="SQL Injection", variable=self.sql_var).grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="XSS", variable=self.xss_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Security Headers", variable=self.headers_var).grid(row=0, column=2, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="CORS", variable=self.cors_var).grid(row=0, column=3, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Information Disclosure", variable=self.info_var).grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Common Paths", variable=self.paths_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="SSL/TLS", variable=self.ssl_var).grid(row=1, column=2, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Subdomain Enumeration", variable=self.subdomain_var).grid(row=1, column=3, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Open Ports", variable=self.ports_var).grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="CRLF Injection", variable=self.crlf_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="JWT Vulnerabilities", variable=self.jwt_var).grid(row=2, column=2, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Backup Files", variable=self.backup_var).grid(row=2, column=3, sticky=tk.W, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=4, pady=10)
        
        self.scan_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = ttk.Button(button_frame, text="Export Report", command=self.export_report)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, mode='indeterminate')
        self.progress.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready to scan")
        self.status_label.grid(row=6, column=0, columnspan=4, sticky=tk.W, pady=(0, 5))
        
        # Results notebook
        self.results_notebook = ttk.Notebook(main_frame)
        self.results_notebook.grid(row=7, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Vulnerabilities tab
        vuln_frame = ttk.Frame(self.results_notebook, padding="5")
        self.results_notebook.add(vuln_frame, text="Vulnerabilities")
        
        # Create treeview for vulnerabilities
        columns = ('Severity', 'Type', 'Description', 'URL')
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        self.vuln_tree.heading('Severity', text='Severity')
        self.vuln_tree.heading('Type', text='Type')
        self.vuln_tree.heading('Description', text='Description')
        self.vuln_tree.heading('URL', text='URL')
        
        # Define columns
        self.vuln_tree.column('Severity', width=80)
        self.vuln_tree.column('Type', width=120)
        self.vuln_tree.column('Description', width=300)
        self.vuln_tree.column('URL', width=200)
        
        # Add scrollbar
        vuln_scrollbar = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vuln_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
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
        
        # Statistics tab
        stats_frame = ttk.Frame(self.results_notebook, padding="5")
        self.results_notebook.add(stats_frame, text="Statistics")
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame, 
            wrap=tk.WORD, 
            height=15,
            bg="#252526",
            fg="#e0e0e0",
            insertbackground="white",
            selectbackground="#37373d"
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for coloring
        self.info_text.tag_config("CRITICAL", foreground=self.critical_color)
        self.info_text.tag_config("HIGH", foreground=self.high_color)
        self.info_text.tag_config("MEDIUM", foreground=self.medium_color)
        self.info_text.tag_config("LOW", foreground=self.low_color)
        self.info_text.tag_config("INFO", foreground=self.info_color)
        self.info_text.tag_config("bold", font=('TkDefaultFont', 10, 'bold'))
        
        # Bind double click on vulnerability tree
        self.vuln_tree.bind('<Double-1>', self.on_vuln_select)
        
    def test_connection(self):
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        self.status_label.config(text="Testing connection...")
        try:
            response = requests.get(target_url, timeout=10, allow_redirects=True)
            if response.status_code < 400:
                messagebox.showinfo("Success", f"Connection successful! Status: {response.status_code}")
                self.status_label.config(text=f"Connection successful - Status: {response.status_code}")
                
                # Update URL entry with final URL (after redirects)
                final_url = response.url
                if final_url != target_url:
                    self.url_entry.delete(0, tk.END)
                    self.url_entry.insert(0, final_url)
                    self.log_info(f"Redirected to: {final_url}")
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
        
        # Generate new scan ID
        self.current_scan_id = f"SCAN-{int(time.time())}"
        self.scan_id_var.set(self.current_scan_id)
        self.start_time_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Start scan in separate thread
        self.scanning = True
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress.start()
        self.status_label.config(text="Initializing scan...")
        
        # Get scan options
        scan_options = {
            'sql': self.sql_var.get(),
            'xss': self.xss_var.get(),
            'headers': self.headers_var.get(),
            'cors': self.cors_var.get(),
            'info': self.info_var.get(),
            'paths': self.paths_var.get(),
            'ssl': self.ssl_var.get(),
            'subdomain': self.subdomain_var.get(),
            'ports': self.ports_var.get(),
            'crlf': self.crlf_var.get(),
            'jwt': self.jwt_var.get(),
            'backup': self.backup_var.get(),
            'depth': self.depth_var.get()
        }
        
        self.scan_thread = threading.Thread(target=self.run_scan, args=(target_url, scan_options))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.status_label.config(text="Scan stopping...")
            # We can't actually stop the thread, but we can set the flag
    
    def run_scan(self, target_url, options):
        try:
            scanner = AdvancedScanner(target_url)
            stats = {
                'vulnerabilities': 0, 
                'critical': 0, 
                'high': 0, 
                'medium': 0, 
                'low': 0,
                'info': 0,
                'start_time': datetime.now(),
                'end_time': None
            }
            
            # Test connection first
            self.update_status("Testing connection to target...")
            if not scanner.test_connection():
                self.log_vulnerability("HIGH", "Connection Error", "Cannot establish connection to target", target_url)
                stats['high'] += 1
                stats['vulnerabilities'] += 1
                self.update_stats(stats)
                self.update_status("Scan completed with errors")
                return
            
            # Get basic info
            self.update_status("Gathering target information...")
            info = scanner.get_site_info()
            self.log_info(f"Target: {info.get('url', 'N/A')}")
            self.log_info(f"Server: {info.get('server', 'N/A')}")
            self.log_info(f"Powered By: {info.get('powered_by', 'N/A')}")
            self.log_info(f"Technologies: {', '.join(info.get('technologies', []))}")
            
            # Security headers check
            if options['headers'] and self.scanning:
                self.update_status("Checking security headers...")
                headers_vulns = scanner.check_security_headers()
                for vuln in headers_vulns:
                    self.log_vulnerability("MEDIUM", "Missing security header", vuln['description'], vuln['url'])
                    stats['medium'] += 1
                    stats['vulnerabilities'] += 1
            
            # CORS misconfigurations
            if options['cors'] and self.scanning:
                self.update_status("Checking CORS settings...")
                cors_vulns = scanner.check_cors()
                for vuln in cors_vulns:
                    self.log_vulnerability(vuln['severity'], "CORS Misconfiguration", vuln['description'], vuln['url'])
                    stats[vuln['severity'].lower()] += 1
                    stats['vulnerabilities'] += 1
            
            # Information disclosure
            if options['info'] and self.scanning:
                self.update_status("Looking for information disclosure...")
                info_vulns = scanner.check_info_disclosure()
                for vuln in info_vulns:
                    self.log_vulnerability("LOW", "Information disclosure", vuln['description'], vuln['url'])
                    stats['low'] += 1
                    stats['vulnerabilities'] += 1
            
            # Hidden paths
            if options['paths'] and self.scanning:
                self.update_status("Searching for hidden paths...")
                found_paths = scanner.scan_common_files()
                for path in found_paths:
                    self.log_vulnerability("MEDIUM", "Exposed sensitive path", f"Found sensitive path: {path}", path)
                    stats['medium'] += 1
                    stats['vulnerabilities'] += 1
            
            # SSL/TLS check
            if options['ssl'] and self.scanning:
                self.update_status("Checking SSL/TLS configuration...")
                ssl_vulns = scanner.check_ssl()
                for vuln in ssl_vulns:
                    self.log_vulnerability(vuln['severity'], "SSL/TLS Issue", vuln['description'], vuln['url'])
                    stats[vuln['severity'].lower()] += 1
                    stats['vulnerabilities'] += 1
            
            # SQL Injection
            if options['sql'] and self.scanning:
                self.update_status("Checking for SQL Injection vulnerabilities...")
                sql_vulns = scanner.check_sql_injection()
                for vuln in sql_vulns:
                    self.log_vulnerability("CRITICAL", "SQL Injection", vuln['description'], vuln['url'])
                    stats['critical'] += 1
                    stats['vulnerabilities'] += 1
            
            # XSS
            if options['xss'] and self.scanning:
                self.update_status("Checking for XSS vulnerabilities...")
                xss_vulns = scanner.check_xss()
                for vuln in xss_vulns:
                    self.log_vulnerability("HIGH", "XSS", vuln['description'], vuln['url'])
                    stats['high'] += 1
                    stats['vulnerabilities'] += 1
            
            # CRLF Injection
            if options['crlf'] and self.scanning:
                self.update_status("Checking for CRLF Injection vulnerabilities...")
                crlf_vulns = scanner.check_crlf_injection()
                for vuln in crlf_vulns:
                    self.log_vulnerability("MEDIUM", "CRLF Injection", vuln['description'], vuln['url'])
                    stats['medium'] += 1
                    stats['vulnerabilities'] += 1
            
            # Backup files
            if options['backup'] and self.scanning:
                self.update_status("Searching for backup files...")
                backup_vulns = scanner.check_backup_files()
                for vuln in backup_vulns:
                    self.log_vulnerability("MEDIUM", "Backup File Exposure", vuln['description'], vuln['url'])
                    stats['medium'] += 1
                    stats['vulnerabilities'] += 1
            
            # Subdomain enumeration
            if options['subdomain'] and self.scanning:
                self.update_status("Enumerating subdomains...")
                subdomains = scanner.enumerate_subdomains()
                for subdomain in subdomains:
                    self.log_info(f"Found subdomain: {subdomain}")
                    stats['info'] += 1
            
            # Port scanning
            if options['ports'] and self.scanning:
                self.update_status("Scanning for open ports...")
                open_ports = scanner.scan_ports()
                for port_info in open_ports:
                    self.log_info(f"Open port: {port_info['port']} ({port_info['service']})")
                    stats['info'] += 1
            
            # Update statistics
            stats['end_time'] = datetime.now()
            stats['duration'] = stats['end_time'] - stats['start_time']
            self.update_stats(stats)
            self.update_status("Scan completed successfully")
            
        except Exception as e:
            self.log_vulnerability("HIGH", "Scan error", f"An error occurred during scanning: {str(e)}", target_url)
            self.update_status("Scan completed with errors")
        
        finally:
            self.scanning = False
            self.root.after(0, self.scan_finished)
    
    def scan_finished(self):
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
    
    def update_status(self, message):
        def update():
            self.status_label.config(text=message)
        self.root.after(0, update)
    
    def log_vulnerability(self, severity, title, details, url):
        def update():
            # Add to treeview
            item_id = self.vuln_tree.insert('', 'end', values=(severity, title, details, url))
            
            # Color code based on severity
            if severity == "CRITICAL":
                self.vuln_tree.set(item_id, 'Severity', severity)
            elif severity == "HIGH":
                self.vuln_tree.set(item_id, 'Severity', severity)
            elif severity == "MEDIUM":
                self.vuln_tree.set(item_id, 'Severity', severity)
            elif severity == "LOW":
                self.vuln_tree.set(item_id, 'Severity', severity)
                
            # Also add to info tab
            self.info_text.insert(tk.END, f"[{severity}] {title}\n", severity)
            self.info_text.insert(tk.END, f"   URL: {url}\n")
            self.info_text.insert(tk.END, f"   Details: {details}\n\n")
            self.info_text.see(tk.END)
            
            # Save to scan results
            self.scan_results.append({
                'severity': severity,
                'type': title,
                'description': details,
                'url': url
            })
        
        if self.scanning:  # Only update if still scanning
            self.root.after(0, update)
    
    def log_info(self, message):
        def update():
            self.info_text.insert(tk.END, f"• {message}\n", "INFO")
            self.info_text.see(tk.END)
        
        self.root.after(0, update)
    
    def update_stats(self, stats):
        def update():
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, "Scan Statistics\n", "bold")
            self.stats_text.insert(tk.END, "=" * 50 + "\n")
            self.stats_text.insert(tk.END, f"Scan ID: {self.current_scan_id}\n")
            self.stats_text.insert(tk.END, f"Start Time: {stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}\n")
            if stats.get('end_time'):
                self.stats_text.insert(tk.END, f"End Time: {stats['end_time'].strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.stats_text.insert(tk.END, f"Duration: {stats['duration']}\n")
            self.stats_text.insert(tk.END, f"Total Vulnerabilities: {stats['vulnerabilities']}\n")
            self.stats_text.insert(tk.END, f"Critical: {stats['critical']}\n", "CRITICAL")
            self.stats_text.insert(tk.END, f"High: {stats['high']}\n", "HIGH")
            self.stats_text.insert(tk.END, f"Medium: {stats['medium']}\n", "MEDIUM")
            self.stats_text.insert(tk.END, f"Low: {stats['low']}\n", "LOW")
            self.stats_text.insert(tk.END, f"Informational: {stats.get('info', 0)}\n", "INFO")
        
        self.root.after(0, update)
    
    def clear_results(self):
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.info_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.status_label.config(text="Ready to scan")
        self.scan_results = []
    
    def export_report(self):
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.scan_results, f, indent=4, ensure_ascii=False)
            elif file_path.endswith('.csv'):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Severity', 'Type', 'Description', 'URL'])
                    for result in self.scan_results:
                        writer.writerow([result['severity'], result['type'], result['description'], result['url']])
            elif file_path.endswith('.html'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.generate_html_report())
            else:
                messagebox.showerror("Error", "Unsupported file format")
                return
                
            messagebox.showinfo("Success", f"Report exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def generate_html_report(self):
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #1e1e1e; color: #e0e0e0; }}
                h1 {{ color: #007acc; }}
                .critical {{ color: #ff5252; }}
                .high {{ color: #ff7b7b; }}
                .medium {{ color: #ffb46b; }}
                .low {{ color: #a3eea0; }}
                .info {{ color: #6bc5ff; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #3c3c3c; }}
                th {{ background-color: #2d2d2d; }}
                tr:hover {{ background-color: #2d2d2d; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            <p><strong>Scan ID:</strong> {self.current_scan_id}</p>
            <p><strong>Target:</strong> {self.url_entry.get()}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Vulnerabilities Found</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>URL</th>
                </tr>
        """
        
        for result in self.scan_results:
            html += f"""
                <tr>
                    <td class="{result['severity'].lower()}">{result['severity']}</td>
                    <td>{result['type']}</td>
                    <td>{result['description']}</td>
                    <td><a href="{result['url']}" target="_blank">{result['url']}</a></td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        return html
    
    def on_vuln_select(self, event):
        item = self.vuln_tree.selection()[0]
        values = self.vuln_tree.item(item, 'values')
        severity, vuln_type, description, url = values
        
        # Show detailed information about the selected vulnerability
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Vulnerability Details - {vuln_type}")
        detail_window.geometry("600x400")
        detail_window.configure(bg="#1e1e1e")
        
        text_widget = scrolledtext.ScrolledText(
            detail_window, 
            wrap=tk.WORD,
            bg="#252526",
            fg="#e0e0e0",
            insertbackground="white",
            selectbackground="#37373d"
        )
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget.insert(tk.END, f"Severity: ", "bold")
        text_widget.insert(tk.END, f"{severity}\n", severity)
        text_widget.insert(tk.END, f"Type: ", "bold")
        text_widget.insert(tk.END, f"{vuln_type}\n")
        text_widget.insert(tk.END, f"URL: ", "bold")
        text_widget.insert(tk.END, f"{url}\n")
        text_widget.insert(tk.END, f"Description: ", "bold")
        text_widget.insert(tk.END, f"{description}\n\n")
        
        # Add remediation advice based on vulnerability type
        text_widget.insert(tk.END, "Remediation:\n", "bold")
        remediation = self.get_remediation_advice(vuln_type)
        text_widget.insert(tk.END, remediation)
        
        # Add exploitation info
        text_widget.insert(tk.END, "\nExploitation:\n", "bold")
        exploitation = self.get_exploitation_info(vuln_type)
        text_widget.insert(tk.END, exploitation)
        
        text_widget.config(state=tk.DISABLED)
    
    def get_remediation_advice(self, vuln_type):
        advice = {
            "SQL Injection": "• Use parameterized queries/prepared statements\n• Implement proper input validation\n• Use ORM frameworks\n• Apply the principle of least privilege\n• Regularly update and patch database systems",
            "XSS": "• Implement context-aware output encoding\n• Use Content Security Policy (CSP)\n• Validate and sanitize all user input\n• Use HTTPOnly flag for cookies\n• Consider using XSS protection libraries",
            "Missing security header": "• Implement all recommended security headers\n• Use HSTS to enforce HTTPS\n• Configure CSP to restrict resources\n• Set X-Frame-Options to prevent clickjacking\n• Ensure X-Content-Type-Options is set to nosniff",
            "CORS Misconfiguration": "• Avoid using wildcard (*) in Access-Control-Allow-Origin\n• Whitelist specific trusted domains\n• Validate Origin headers on the server side\n• Avoid including credentials with wildcard origins",
            "Information disclosure": "• Disable detailed error messages in production\n• Remove unnecessary information from headers\n• Secure configuration files and backup files\n• Implement proper access controls",
            "Exposed sensitive path": "• Remove or secure sensitive files and directories\n• Implement proper access controls\n• Use robots.txt to disallow sensitive paths\n• Regularly audit exposed files and directories",
            "SSL/TLS Issue": "• Use strong encryption protocols (TLS 1.2+)\n• Disable weak ciphers\n• Ensure certificates are valid and not expired\n• Implement proper certificate chain\n• Consider using HSTS",
            "CRLF Injection": "• Validate and sanitize user input\n• Encode CRLF sequences in user input\n• Use security headers where applicable\n• Implement proper output encoding",
            "Backup File Exposure": "• Remove unnecessary backup files from production\n• Restrict access to backup directories\n• Use proper authentication and authorization\n• Regularly audit files exposed on web servers"
        }
        
        return advice.get(vuln_type, "• Consult security best practices for this vulnerability type\n• Keep software and dependencies updated\n• Implement regular security testing\n• Follow the principle of least privilege")
    
    def get_exploitation_info(self, vuln_type):
        exploitation = {
            "SQL Injection": "• Use tools like SQLmap for automated exploitation\n• Try to extract database structure, tables, and sensitive data\n• Attempt to bypass authentication mechanisms\n• Use UNION-based attacks to extract data from other tables",
            "XSS": "• Craft malicious scripts to steal cookies or session tokens\n• Use keyloggers to capture user input\n• Perform phishing attacks by modifying page content\n• Use BeEF framework for advanced exploitation",
            "Missing security header": "• Exploit clickjacking vulnerabilities if X-Frame-Options is missing\n• Use MIME sniffing attacks if X-Content-Type-Options is missing\n• Bypass CSP protections if not properly configured",
            "CORS Misconfiguration": "• Craft malicious requests from attacker-controlled domains\n• Exploit overly permissive CORS settings to steal sensitive data\n• Use with XSS to escalate attack impact",
            "Information disclosure": "• Use exposed information to plan targeted attacks\n• Find usernames, emails for social engineering\n• Discover technology versions to exploit known vulnerabilities",
            "Exposed sensitive path": "• Access configuration files to find credentials\n• Download backup files to analyze source code\n• Find administrative interfaces for brute force attacks",
            "SSL/TLS Issue": "• Use tools like SSLScan to identify weak ciphers\n• Perform man-in-the-middle attacks on weak encryption\n• Exploit certificate validation flaws",
            "CRLF Injection": "• Inject custom HTTP headers\n• Split responses to bypass security controls\n• Perform HTTP response smuggling attacks",
            "Backup File Exposure": "• Download backup files to analyze source code\n• Extract database credentials and other sensitive information\n• Use source code to find additional vulnerabilities"
        }
        
        return exploitation.get(vuln_type, "• Research specific exploitation techniques for this vulnerability\n• Use automated tools where appropriate\n• Consider the impact of successful exploitation")


class AdvancedScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.session.max_redirects = 5
        self.timeout = 10
    
    def test_connection(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, allow_redirects=True)
            return response.status_code < 500
        except:
            return False
    
    def get_site_info(self):
        info = {
            'url': self.target_url,
            'server': 'Unknown',
            'powered_by': 'Unknown',
            'technologies': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers
            
            if 'server' in headers:
                info['server'] = headers['server']
            
            if 'x-powered-by' in headers:
                info['powered_by'] = headers['x-powered-by']
            
            # Simple technology detection
            tech_indicators = {
                'PHP': ['php', 'phpsessionid'],
                'ASP.NET': ['asp.net', 'aspx', 'viewstate'],
                'Java': ['jsessionid', 'servlet', 'jsp'],
                'WordPress': ['wp-content', 'wordpress'],
                'Drupal': ['drupal'],
                'Joomla': ['joomla'],
                'Ruby on Rails': ['rails', 'ruby'],
                'Python': ['django', 'flask', 'python'],
                'Node.js': ['node', 'express'],
            }
            
            content = response.text.lower()
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator in content or indicator in headers.get('set-cookie', '').lower():
                        if tech not in info['technologies']:
                            info['technologies'].append(tech)
                        break
            
        except Exception as e:
            pass
        
        return info
    
    def check_security_headers(self):
        vulnerabilities = []
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': {
                    'description': 'X-Frame-Options header missing - clickjacking risk',
                    'severity': 'MEDIUM'
                },
                'X-Content-Type-Options': {
                    'description': 'X-Content-Type-Options header missing - MIME sniffing risk',
                    'severity': 'LOW'
                },
                'X-XSS-Protection': {
                    'description': 'X-XSS-Protection header missing - XSS protection risk',
                    'severity': 'LOW'
                },
                'Strict-Transport-Security': {
                    'description': 'HSTS header missing - HTTPS enforcement risk',
                    'severity': 'HIGH'
                },
                'Content-Security-Policy': {
                    'description': 'CSP header missing - injection attacks risk',
                    'severity': 'MEDIUM'
                },
                'Referrer-Policy': {
                    'description': 'Referrer-Policy header missing - referrer information leakage risk',
                    'severity': 'LOW'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'description': info['description'],
                        'severity': info['severity'],
                        'url': self.target_url
                    })
            
        except Exception as e:
            vulnerabilities.append({
                'description': f"Error checking headers: {str(e)}",
                'severity': 'INFO',
                'url': self.target_url
            })
        
        return vulnerabilities
    
    def check_cors(self):
        vulnerabilities = []
        try:
            # Test with arbitrary origin
            test_origin = "https://malicious-site.com"
            response = self.session.get(
                self.target_url, 
                timeout=self.timeout,
                headers={'Origin': test_origin}
            )
            
            headers = response.headers
            acao = headers.get('Access-Control-Allow-Origin', '')
            acac = headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                if acac.lower() == 'true':
                    vulnerabilities.append({
                        'description': "CORS policy allows all origins with credentials - critical risk",
                        'severity': 'CRITICAL',
                        'url': self.target_url
                    })
                else:
                    vulnerabilities.append({
                        'description': "CORS policy allows all origins (*)",
                        'severity': 'HIGH',
                        'url': self.target_url
                    })
            elif acao == test_origin:
                vulnerabilities.append({
                    'description': "CORS policy reflects arbitrary origin - potential vulnerability",
                    'severity': 'HIGH',
                    'url': self.target_url
                })
            
            # Check for overly permissive methods
            acam = headers.get('Access-Control-Allow-Methods', '')
            if 'DELETE' in acam or 'PUT' in acam or 'POST' in acam:
                if acao == '*' or acao == test_origin:
                    vulnerabilities.append({
                        'description': f"CORS policy allows potentially dangerous methods: {acam}",
                        'severity': 'MEDIUM',
                        'url': self.target_url
                    })
            
        except Exception as e:
            vulnerabilities.append({
                'description': f"Error checking CORS: {str(e)}",
                'severity': 'INFO',
                'url': self.target_url
            })
        
        return vulnerabilities
    
    def check_info_disclosure(self):
        vulnerabilities = []
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            content = response.text
            
            # Check for common information disclosure patterns
            info_patterns = [
                ('phpinfo', 'PHPInfo exposure'),
                ('debug', 'Debug information'),
                ('test', 'Test data exposure'),
                ('version', 'Version information'),
                ('database', 'Database information'),
                ('password', 'Password exposure'),
                ('config', 'Configuration data'),
                ('admin', 'Admin information'),
                ('backup', 'Backup files'),
                ('.git', 'Git repository exposure'),
                ('.env', 'Environment file exposure'),
                ('aws_key', 'AWS key'),
                ('api_key', 'API key'),
                ('sqlite', 'SQLite database'),
                ('stacktrace', 'Stack trace'),
                ('exception', 'Exception details')
            ]
            
            for pattern, description in info_patterns:
                if re.search(rf'\b{pattern}\b', content, re.IGNORECASE):
                    vulnerabilities.append({
                        'description': f"Potential information disclosure: {description}",
                        'severity': 'LOW',
                        'url': self.target_url
                    })
            
            # Check for email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, content)
            if emails:
                vulnerabilities.append({
                    'description': f"Email addresses exposed: {', '.join(set(emails))}",
                    'severity': 'LOW',
                    'url': self.target_url
                })
            
        except Exception as e:
            vulnerabilities.append({
                'description': f"Error checking information disclosure: {str(e)}",
                'severity': 'INFO',
                'url': self.target_url
            })
        
        return vulnerabilities
    
    def scan_common_files(self):
        common_paths = [
            "/admin", "/login", "/config.php", "/backup", "/.env",
            "/phpinfo.php", "/test.php", "/wp-admin", "/administrator",
            "/server-status", "/.git", "/.htaccess", "/robots.txt",
            "/backup.zip", "/database.sql", "/web.config", "/wp-config.php",
            "/config.json", "/.DS_Store", "/.env.example", "/composer.json",
            "/package.json", "/yarn.lock", "/Gemfile", "/config/database.yml",
            "/debug.log", "/error_log", "/storage", "/uploads", "/downloads"
        ]
        
        found_paths = []
        for path in common_paths:
            full_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(full_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    found_paths.append(full_url)
            except:
                continue
                
        return found_paths
    
    def check_backup_files(self):
        vulnerabilities = []
        backup_extensions = ['.bak', '.backup', '.old', '.tmp', '.temp', '.swp', '.swo']
        base_url = self.target_url.rstrip('/')
        
        # Try common backup file patterns
        for ext in backup_extensions:
            test_url = f"{base_url}{ext}"
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code == 200 and len(response.content) > 0:
                    vulnerabilities.append({
                        'description': f"Backup file found: {test_url}",
                        'severity': 'MEDIUM',
                        'url': test_url
                    })
            except:
                continue
                
        return vulnerabilities
    
    def check_ssl(self):
        vulnerabilities = []
        try:
            hostname = urlparse(self.target_url).hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        from datetime import datetime, timedelta
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expire_date < datetime.now():
                            vulnerabilities.append({
                                'description': f"SSL certificate has expired: {expire_date.strftime('%Y-%m-%d')}",
                                'severity': 'HIGH',
                                'url': self.target_url
                            })
                        elif expire_date < datetime.now() + timedelta(days=30):
                            vulnerabilities.append({
                                'description': f"SSL certificate expires soon: {expire_date.strftime('%Y-%m-%d')}",
                                'severity': 'MEDIUM',
                                'url': self.target_url
                            })
                    
                    # Check protocol version
                    protocol = ssock.version()
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'description': f"Using deprecated TLS version: {protocol}",
                            'severity': 'MEDIUM',
                            'url': self.target_url
                        })
                    
                    # Check cipher strength
                    cipher = ssock.cipher()
                    if cipher and ('RC4' in cipher[0] or 'DES' in cipher[0] or '3DES' in cipher[0]):
                        vulnerabilities.append({
                            'description': f"Using weak cipher: {cipher[0]}",
                            'severity': 'MEDIUM',
                            'url': self.target_url
                        })
            
        except ssl.SSLCertVerificationError:
            vulnerabilities.append({
                'description': "SSL certificate verification failed",
                'severity': 'HIGH',
                'url': self.target_url
            })
        except Exception as e:
            vulnerabilities.append({
                'description': f"Error checking SSL: {str(e)}",
                'severity': 'INFO',
                'url': self.target_url
            })
        
        return vulnerabilities
    
    def check_sql_injection(self):
        vulnerabilities = []
        
        # Test URLs with parameters
        test_urls = [
            f"{self.target_url}?id=1",
            f"{self.target_url}?page=1",
            f"{self.target_url}?user=1",
            f"{self.target_url}?category=1"
        ]
        
        payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' UNION SELECT null--",
            "'; DROP TABLE users--",
            "1' OR '1'='1' --",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND (SELECT 'a' FROM users WHERE username='admin' AND LENGTH(password)>0)='a"
        ]
        
        for test_url in test_urls:
            for payload in payloads:
                if not vulnerabilities:  # Don't test if we already found something
                    try:
                        test_url_with_payload = f"{test_url}{payload}"
                        response = self.session.get(test_url_with_payload, timeout=5)
                        
                        # Check for common SQL error patterns
                        error_patterns = [
                            "sql", "syntax", "mysql", "ora-", "postgresql",
                            "microsoft.*driver", "odbc.*driver", "mysql_fetch",
                            "you have an error in your sql syntax",
                            "warning.*mysql", "unclosed quotation mark",
                            "quoted string not properly terminated"
                        ]
                        
                        content = response.text.lower()
                        for pattern in error_patterns:
                            if re.search(pattern, content):
                                vulnerabilities.append({
                                    'description': f"Potential SQL injection vulnerability detected with payload: {payload}",
                                    'severity': 'CRITICAL',
                                    'url': test_url_with_payload
                                })
                                break
                                
                    except:
                        continue
                
        return vulnerabilities
    
    def check_xss(self):
        vulnerabilities = []
        
        # Test URLs with parameters
        test_urls = [
            f"{self.target_url}?q=test",
            f"{self.target_url}?search=test",
            f"{self.target_url}?name=test",
            f"{self.target_url}?input=test"
        ]
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",
            "<svg onload=alert('XSS')>",
            "alert(String.fromCharCode(88,83,83))"
        ]
        
        for test_url in test_urls:
            for payload in payloads:
                if not vulnerabilities:  # Don't test if we already found something
                    try:
                        test_url_with_payload = f"{test_url}{payload}"
                        response = self.session.get(test_url_with_payload, timeout=5)
                        
                        # Check if payload is reflected in response
                        if payload in response.text:
                            vulnerabilities.append({
                                'description': f"Potential XSS vulnerability detected with payload: {payload}",
                                'severity': 'HIGH',
                                'url': test_url_with_payload
                            })
                            
                    except:
                        continue
                
        return vulnerabilities
    
    def check_crlf_injection(self):
        vulnerabilities = []
        
        test_urls = [
            f"{self.target_url}?redirect=https://example.com",
            f"{self.target_url}?url=https://example.com",
            f"{self.target_url}?next=/home",
            f"{self.target_url}?returnTo=/dashboard"
        ]
        
        payloads = [
            "%0d%0aSet-Cookie:injected=crlf",
            "%0d%0aX-Injected:header",
            "%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%20100%0d%0a%0d%0a<html>Injected</html>"
        ]
        
        for test_url in test_urls:
            for payload in payloads:
                try:
                    test_url_with_payload = f"{test_url}{payload}"
                    response = self.session.get(test_url_with_payload, timeout=5, allow_redirects=False)
                    
                    # Check if injection was successful
                    headers = str(response.headers).lower()
                    if 'injected' in headers or 'crlf' in headers:
                        vulnerabilities.append({
                            'description': f"Potential CRLF injection vulnerability detected with payload: {payload}",
                            'severity': 'MEDIUM',
                            'url': test_url_with_payload
                        })
                        break
                        
                except:
                    continue
                
        return vulnerabilities
    
    def enumerate_subdomains(self):
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
            'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
            'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
            'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2',
            'api', 'cdn', 'stats', 'dns1', 'www3', 'search', 'staging', 'server', 'mx1',
            'chat', 'download', 'remote', 'db', 'forums', 'store', 'pic', 'sms', 'office',
            'exchange', 'apps', 'proxy', 'ad', 'ads', 'offices', 'school', 'ce', 'gc', 'gls'
        ]
        
        domain = urlparse(self.target_url).hostname
        if domain.startswith('www.'):
            domain = domain[4:]
        
        for sub in common_subdomains:
            test_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(test_domain)
                subdomains.append(test_domain)
            except:
                continue
                
        return subdomains
    
    def scan_ports(self):
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        hostname = urlparse(self.target_url).hostname
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((hostname, port))
                    if result == 0:
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                            
                        open_ports.append({
                            'port': port,
                            'service': service
                        })
            except:
                continue
                
        return open_ports


# Fix for Windows compatibility
if __name__ == "__main__":
    # Handle Windows-specific issues
    if sys.platform == "win32":
        # Fix for Windows high DPI scaling
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    
    root = tk.Tk()
    app = DarkVulnerabilityScanner(root)
    root.mainloop()
