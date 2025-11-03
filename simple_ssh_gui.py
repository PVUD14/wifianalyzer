#!/usr/bin/env python3
"""
Simple SSH GUI for WiFi Penetration Testing Tool

This GUI provides a user-friendly interface for SSH connections
and running penetration testing commands on the Kali Linux VM.
Includes integration with fern-wifi-cracker.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import os


class SimpleSSHGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Penetration Tool - SSH Connection")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # SSH Connection variables
        self.ssh_host_var = tk.StringVar(value="172.18.0.1")
        self.ssh_username_var = tk.StringVar(value="vaptrix")
        self.ssh_password_var = tk.StringVar(value="Xevyte@2025")
        self.ssh_port_var = tk.StringVar(value="22")
        
        # Command variables
        self.command_var = tk.StringVar()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # SSH Connection frame
        ssh_frame = ttk.LabelFrame(main_frame, text="SSH Connection", padding=10)
        ssh_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Host
        ttk.Label(ssh_frame, text="Host:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(ssh_frame, textvariable=self.ssh_host_var, width=20).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Port
        ttk.Label(ssh_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0), pady=2)
        ttk.Entry(ssh_frame, textvariable=self.ssh_port_var, width=10).grid(row=0, column=3, sticky=tk.W, pady=2)
        
        # Username
        ttk.Label(ssh_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(ssh_frame, textvariable=self.ssh_username_var, width=20).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Password
        ttk.Label(ssh_frame, text="Password:").grid(row=1, column=2, sticky=tk.W, padx=(10, 0), pady=2)
        ttk.Entry(ssh_frame, textvariable=self.ssh_password_var, width=20, show="*").grid(row=1, column=3, sticky=tk.W, pady=2)
        
        # Connection buttons
        conn_buttons_frame = ttk.Frame(ssh_frame)
        conn_buttons_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        ttk.Button(conn_buttons_frame, text="Test Connection", command=self.test_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(conn_buttons_frame, text="Show SSH Command", command=self.show_ssh_command).pack(side=tk.LEFT, padx=5)
        
        # Connection status
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(ssh_frame, textvariable=self.status_var)
        self.status_label.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=2)
        
        # Command frame
        cmd_frame = ttk.LabelFrame(main_frame, text="Command Execution", padding=10)
        cmd_frame.pack(fill=tk.BOTH, expand=True)
        
        # Command entry
        ttk.Label(cmd_frame, text="Command:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(cmd_frame, textvariable=self.command_var, width=60).grid(row=0, column=1, sticky=tk.EW, pady=2)
        ttk.Button(cmd_frame, text="Execute via SSH", command=self.execute_ssh_command).grid(row=0, column=2, padx=5, pady=2)
        
        cmd_frame.columnconfigure(1, weight=1)
        
        # Quick commands
        quick_frame = ttk.Frame(cmd_frame)
        quick_frame.grid(row=1, column=0, columnspan=3, pady=10)
        
        ttk.Label(quick_frame, text="Quick Commands:").pack(side=tk.LEFT)
        ttk.Button(quick_frame, text="System Info", command=lambda: self.set_command("uname -a")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Network Interfaces", command=lambda: self.set_command("iw dev")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Check Tools", command=lambda: self.set_command("which airodump-ng aireplay-ng aircrack-ng")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="List Interfaces", command=lambda: self.set_command("ip link show")).pack(side=tk.LEFT, padx=5)
        
        # WiFi Pen Testing commands
        wifi_frame = ttk.Frame(cmd_frame)
        wifi_frame.grid(row=2, column=0, columnspan=3, pady=5)
        
        ttk.Label(wifi_frame, text="WiFi Tools:").pack(side=tk.LEFT)
        ttk.Button(wifi_frame, text="Run Scan", command=lambda: self.set_wifi_command("sudo python3 wifi_penetration_tool/main.py")).pack(side=tk.LEFT, padx=5)
        ttk.Button(wifi_frame, text="Interface Manager", command=lambda: self.set_wifi_command("sudo python3 wifi_penetration_tool/main.py --help")).pack(side=tk.LEFT, padx=5)
        ttk.Button(wifi_frame, text="Run with Fern", command=lambda: self.set_wifi_command("sudo python3 wifi_penetration_tool/main.py --use-fern")).pack(side=tk.LEFT, padx=5)
        
        # Fern Integration frame
        fern_frame = ttk.Frame(cmd_frame)
        fern_frame.grid(row=3, column=0, columnspan=3, pady=5)
        
        ttk.Label(fern_frame, text="Fern Integration:").pack(side=tk.LEFT)
        ttk.Button(fern_frame, text="Check Fern", command=lambda: self.set_command("which fern-wifi-cracker")).pack(side=tk.LEFT, padx=5)
        ttk.Button(fern_frame, text="Install Fern", command=lambda: self.set_command("sudo apt update && sudo apt install -y fern-wifi-cracker")).pack(side=tk.LEFT, padx=5)
        ttk.Button(fern_frame, text="Run Fern Scan", command=lambda: self.set_command("sudo fern-wifi-cracker --cli --scan")).pack(side=tk.LEFT, padx=5)
        
        # Output text area
        ttk.Label(cmd_frame, text="Output:").grid(row=4, column=0, sticky=tk.W, pady=(10, 2))
        self.output_text = scrolledtext.ScrolledText(cmd_frame, height=20)
        self.output_text.grid(row=5, column=0, columnspan=3, sticky=tk.NSEW, pady=2)
        
        cmd_frame.rowconfigure(5, weight=1)
        cmd_frame.columnconfigure(1, weight=1)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
    def append_output(self, text):
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.update_idletasks()
        
    def update_status(self, text):
        self.status_var.set(text)
        
    def set_command(self, command):
        self.command_var.set(command)
        
    def set_wifi_command(self, command):
        self.command_var.set(command)
        
    def test_connection(self):
        host = self.ssh_host_var.get()
        port = self.ssh_port_var.get()
        
        def test():
            try:
                self.progress.start()
                self.append_output(f"[*] Testing connection to {host}:{port}...")
                
                # Test TCP connection using PowerShell
                cmd = f"Test-NetConnection -ComputerName {host} -Port {port}"
                result = subprocess.run(["powershell", "-Command", cmd], 
                                      capture_output=True, text=True, timeout=15)
                
                self.progress.stop()
                self.append_output(result.stdout)
                if result.stderr:
                    self.append_output(f"Errors:\n{result.stderr}")
                    
            except subprocess.TimeoutExpired:
                self.progress.stop()
                self.append_output("[-] Connection test timed out")
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Connection test failed: {str(e)}")
                
        thread = threading.Thread(target=test)
        thread.daemon = True
        thread.start()
        
    def show_ssh_command(self):
        host = self.ssh_host_var.get()
        username = self.ssh_username_var.get()
        port = self.ssh_port_var.get()
        
        ssh_cmd = f"ssh -p {port} {username}@{host}"
        self.append_output(f"[*] SSH Command: {ssh_cmd}")
        self.append_output("[*] You can copy and paste this command into your terminal")
        
    def execute_ssh_command(self):
        host = self.ssh_host_var.get()
        username = self.ssh_username_var.get()
        port = self.ssh_port_var.get()
        command = self.command_var.get()
        
        if not command:
            messagebox.showerror("Error", "Please enter a command")
            return
            
        def execute():
            try:
                self.progress.start()
                self.append_output(f"$ {command}")
                
                # Execute command via SSH
                ssh_cmd = f"ssh -p {port} -o ConnectTimeout=10 {username}@{host} '{command}'"
                result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=30)
                
                self.progress.stop()
                if result.stdout:
                    self.append_output(result.stdout)
                if result.stderr:
                    self.append_output(f"Errors:\n{result.stderr}")
                if result.returncode != 0:
                    self.append_output(f"[!] Command exited with code {result.returncode}")
                    
            except subprocess.TimeoutExpired:
                self.progress.stop()
                self.append_output("[-] Command execution timed out")
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Command execution failed: {str(e)}")
                
        thread = threading.Thread(target=execute)
        thread.daemon = True
        thread.start()


def main():
    root = tk.Tk()
    app = SimpleSSHGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()