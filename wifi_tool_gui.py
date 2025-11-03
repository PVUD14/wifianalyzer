#!/usr/bin/env python3
"""
GUI Application for WiFi Penetration Testing Tool

This GUI provides a user-friendly interface for the WiFi penetration testing tool,
allowing Windows users to easily configure and run scans, captures, and cracking operations.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import sys


class WiFiPenTestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Penetration Testing Tool")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variables
        self.interface_var = tk.StringVar()
        self.target_bssid_var = tk.StringVar()
        self.channel_var = tk.StringVar()
        self.dictionary_var = tk.StringVar(value="C:\\Users\\Public\\wordlist.txt")
        self.output_filename_var = tk.StringVar()
        self.kali_ip_var = tk.StringVar(value="172.18.0.1")
        self.kali_username_var = tk.StringVar(value="vaptrix")
        self.kali_password_var = tk.StringVar()
        
        # SSH Process
        self.ssh_process = None
        self.is_connected = False
        
        self.create_widgets()
        
    def create_widgets(self):
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Local Windows Tab
        self.local_frame = ttk.Frame(notebook)
        notebook.add(self.local_frame, text="Local Windows")
        
        # Kali Linux SSH Tab
        self.ssh_frame = ttk.Frame(notebook)
        notebook.add(self.ssh_frame, text="Kali Linux SSH")
        
        # Create widgets for local frame
        self.create_local_widgets()
        
        # Create widgets for SSH frame
        self.create_ssh_widgets()
        
    def create_local_widgets(self):
        # Main frame
        main_frame = ttk.LabelFrame(self.local_frame, text="WiFi Penetration Tool - Local Windows", padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Interface selection
        ttk.Label(main_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(main_frame, textvariable=self.interface_var, width=30).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Button(main_frame, text="Auto-Detect", command=self.auto_detect_interface).grid(row=0, column=2, padx=5, pady=2)
        
        # Target BSSID
        ttk.Label(main_frame, text="Target BSSID:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(main_frame, textvariable=self.target_bssid_var, width=30).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Channel
        ttk.Label(main_frame, text="Channel:").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(main_frame, textvariable=self.channel_var, width=30).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Dictionary file
        ttk.Label(main_frame, text="Dictionary File:").grid(row=3, column=0, sticky=tk.W, pady=2)
        ttk.Entry(main_frame, textvariable=self.dictionary_var, width=30).grid(row=3, column=1, sticky=tk.W, pady=2)
        ttk.Button(main_frame, text="Browse", command=self.browse_dictionary).grid(row=3, column=2, padx=5, pady=2)
        
        # Output filename
        ttk.Label(main_frame, text="Output Filename:").grid(row=4, column=0, sticky=tk.W, pady=2)
        ttk.Entry(main_frame, textvariable=self.output_filename_var, width=30).grid(row=4, column=1, sticky=tk.W, pady=2)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        ttk.Button(buttons_frame, text="Run Scan", command=self.run_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Run Capture", command=self.run_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Run Crack", command=self.run_crack).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Run Full Test", command=self.run_full_test).pack(side=tk.LEFT, padx=5)
        
        # Output text area
        ttk.Label(main_frame, text="Output:").grid(row=6, column=0, sticky=tk.W, pady=(10, 2))
        self.output_text = scrolledtext.ScrolledText(main_frame, height=15)
        self.output_text.grid(row=7, column=0, columnspan=3, sticky=tk.NSEW, pady=2)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(7, weight=1)
        
    def create_ssh_widgets(self):
        # SSH Connection frame
        ssh_conn_frame = ttk.LabelFrame(self.ssh_frame, text="SSH Connection", padding=10)
        ssh_conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Kali IP
        ttk.Label(ssh_conn_frame, text="Kali IP:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(ssh_conn_frame, textvariable=self.kali_ip_var, width=20).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Username
        ttk.Label(ssh_conn_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(ssh_conn_frame, textvariable=self.kali_username_var, width=20).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Password
        ttk.Label(ssh_conn_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(ssh_conn_frame, textvariable=self.kali_password_var, width=20, show="*").grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # SSH Buttons
        ssh_buttons_frame = ttk.Frame(ssh_conn_frame)
        ssh_buttons_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(ssh_buttons_frame, text="Connect", command=self.connect_ssh).pack(side=tk.LEFT, padx=5)
        ttk.Button(ssh_buttons_frame, text="Disconnect", command=self.disconnect_ssh).pack(side=tk.LEFT, padx=5)
        
        # SSH Command frame
        ssh_cmd_frame = ttk.LabelFrame(self.ssh_frame, text="SSH Commands", padding=10)
        ssh_cmd_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Command entry
        ttk.Label(ssh_cmd_frame, text="Command:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.ssh_command_var = tk.StringVar()
        ttk.Entry(ssh_cmd_frame, textvariable=self.ssh_command_var, width=50).grid(row=0, column=1, sticky=tk.EW, pady=2)
        ttk.Button(ssh_cmd_frame, text="Execute", command=self.execute_ssh_command).grid(row=0, column=2, padx=5, pady=2)
        
        ssh_cmd_frame.columnconfigure(1, weight=1)
        
        # SSH Output
        ttk.Label(ssh_cmd_frame, text="SSH Output:").grid(row=1, column=0, sticky=tk.W, pady=(10, 2))
        self.ssh_output_text = scrolledtext.ScrolledText(ssh_cmd_frame, height=10)
        self.ssh_output_text.grid(row=2, column=0, columnspan=3, sticky=tk.NSEW, pady=2)
        
        ssh_cmd_frame.rowconfigure(2, weight=1)
        ssh_cmd_frame.columnconfigure(1, weight=1)
        
        # Predefined commands
        predefined_frame = ttk.Frame(ssh_cmd_frame)
        predefined_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        ttk.Button(predefined_frame, text="Run Scan", command=lambda: self.execute_predefined_command("sudo python3 wifi_penetration_tool/main.py")).pack(side=tk.LEFT, padx=5)
        ttk.Button(predefined_frame, text="Check Interfaces", command=lambda: self.execute_predefined_command("iw dev")).pack(side=tk.LEFT, padx=5)
        ttk.Button(predefined_frame, text="Check Tools", command=lambda: self.execute_predefined_command("which airodump-ng aireplay-ng aircrack-ng")).pack(side=tk.LEFT, padx=5)
        
    def auto_detect_interface(self):
        try:
            # Use netsh to detect wireless interfaces
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse the output to find interface names
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Name' in line and ':' in line:
                        name = line.split(':')[1].strip()
                        if name:
                            self.interface_var.set(name)
                            self.append_output(f"Auto-detected interface: {name}")
                            return
                            
            self.append_output("No wireless interfaces found")
        except Exception as e:
            self.append_output(f"Error detecting interfaces: {str(e)}")
            
    def browse_dictionary(self):
        filename = filedialog.askopenfilename(
            title="Select Dictionary File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.dictionary_var.set(filename)
            
    def append_output(self, text):
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.update_idletasks()
        
    def append_ssh_output(self, text):
        self.ssh_output_text.insert(tk.END, text + "\n")
        self.ssh_output_text.see(tk.END)
        self.ssh_output_text.update_idletasks()
        
    def run_command_async(self, command, callback=None):
        def run():
            try:
                self.append_output(f"Running: {command}")
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                self.append_output(result.stdout)
                if result.stderr:
                    self.append_output(f"Errors: {result.stderr}")
                if callback:
                    callback(result)
            except Exception as e:
                self.append_output(f"Error: {str(e)}")
                
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
        
    def run_scan(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please specify an interface")
            return
            
        command = f"python wifi_penetration_tool_windows\\main.py -i \"{interface}\""
        self.run_command_async(command)
        
    def run_capture(self):
        interface = self.interface_var.get()
        target_bssid = self.target_bssid_var.get()
        channel = self.channel_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please specify an interface")
            return
        if not target_bssid:
            messagebox.showerror("Error", "Please specify a target BSSID")
            return
        if not channel:
            messagebox.showerror("Error", "Please specify a channel")
            return
            
        command = f"python wifi_penetration_tool_windows\\main.py -i \"{interface}\" -t {target_bssid} -c {channel}"
        self.run_command_async(command)
        
    def run_crack(self):
        dictionary = self.dictionary_var.get()
        output_filename = self.output_filename_var.get() or "test_capture"
        capture_file = f"{output_filename}-01.cap"
        
        if not os.path.exists(capture_file):
            messagebox.showerror("Error", f"Capture file not found: {capture_file}")
            return
            
        command = f"python wifi_penetration_tool_windows\\main.py -d \"{dictionary}\""
        self.run_command_async(command)
        
    def run_full_test(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please specify an interface")
            return
            
        command = f"python wifi_penetration_tool_windows\\main.py -i \"{interface}\""
        self.run_command_async(command)
        
    def connect_ssh(self):
        ip = self.kali_ip_var.get()
        username = self.kali_username_var.get()
        password = self.kali_password_var.get()
        
        if not ip or not username:
            messagebox.showerror("Error", "Please specify IP and username")
            return
            
        # For security reasons, we won't actually store or use the password in this simple implementation
        # In a real application, you would use a proper SSH library like paramiko
        self.append_ssh_output(f"Connecting to {username}@{ip}")
        self.append_ssh_output("Note: This is a demonstration. Actual SSH connection would require additional libraries.")
        self.append_ssh_output("In a real implementation, you would use paramiko or similar SSH library.")
        self.is_connected = True
        
    def disconnect_ssh(self):
        if self.is_connected:
            self.append_ssh_output("Disconnected from SSH session")
            self.is_connected = False
        else:
            self.append_ssh_output("No active SSH connection")
            
    def execute_ssh_command(self):
        if not self.is_connected:
            messagebox.showerror("Error", "Not connected to SSH session")
            return
            
        command = self.ssh_command_var.get()
        if not command:
            messagebox.showerror("Error", "Please enter a command")
            return
            
        self.append_ssh_output(f"Executing: {command}")
        self.append_ssh_output("Note: This is a demonstration. Actual SSH execution would require additional libraries.")
        
    def execute_predefined_command(self, command):
        if not self.is_connected:
            messagebox.showerror("Error", "Not connected to SSH session")
            return
            
        self.ssh_command_var.set(command)
        self.execute_ssh_command()


def main():
    root = tk.Tk()
    app = WiFiPenTestGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()