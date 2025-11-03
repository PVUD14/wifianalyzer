#!/usr/bin/env python3
"""
Enhanced SSH GUI for WiFi Penetration Testing Tool

This GUI provides SSH connectivity to the Kali Linux VM and allows
running penetration testing commands remotely.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os

# Try to import paramiko
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    paramiko = None
    PARAMIKO_AVAILABLE = False


class SSHGUI:
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
        
        # SSH Client
        self.ssh_client = None
        self.is_connected = False
        
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
        
        ttk.Button(conn_buttons_frame, text="Connect", command=self.connect_ssh).pack(side=tk.LEFT, padx=5)
        ttk.Button(conn_buttons_frame, text="Disconnect", command=self.disconnect_ssh).pack(side=tk.LEFT, padx=5)
        ttk.Button(conn_buttons_frame, text="Test Connection", command=self.test_connection).pack(side=tk.LEFT, padx=5)
        
        # Connection status
        self.status_var = tk.StringVar(value="Not connected")
        self.status_label = ttk.Label(ssh_frame, textvariable=self.status_var, foreground="red")
        self.status_label.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=2)
        
        # Command frame
        cmd_frame = ttk.LabelFrame(main_frame, text="Command Execution", padding=10)
        cmd_frame.pack(fill=tk.BOTH, expand=True)
        
        # Command entry
        ttk.Label(cmd_frame, text="Command:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(cmd_frame, textvariable=self.command_var, width=60).grid(row=0, column=1, sticky=tk.EW, pady=2)
        ttk.Button(cmd_frame, text="Execute", command=self.execute_command).grid(row=0, column=2, padx=5, pady=2)
        
        cmd_frame.columnconfigure(1, weight=1)
        
        # Quick commands
        quick_frame = ttk.Frame(cmd_frame)
        quick_frame.grid(row=1, column=0, columnspan=3, pady=10)
        
        ttk.Label(quick_frame, text="Quick Commands:").pack(side=tk.LEFT)
        ttk.Button(quick_frame, text="System Info", command=lambda: self.run_quick_command("uname -a")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Network Interfaces", command=lambda: self.run_quick_command("iw dev")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Check Tools", command=lambda: self.run_quick_command("which airodump-ng aireplay-ng aircrack-ng")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="List Interfaces", command=lambda: self.run_quick_command("ip link show")).pack(side=tk.LEFT, padx=5)
        
        # WiFi Pen Testing commands
        wifi_frame = ttk.Frame(cmd_frame)
        wifi_frame.grid(row=2, column=0, columnspan=3, pady=5)
        
        ttk.Label(wifi_frame, text="WiFi Tools:").pack(side=tk.LEFT)
        ttk.Button(wifi_frame, text="Run Scan", command=lambda: self.run_wifi_command("sudo python3 wifi_penetration_tool/main.py")).pack(side=tk.LEFT, padx=5)
        ttk.Button(wifi_frame, text="Interface Manager", command=lambda: self.run_wifi_command("sudo python3 wifi_penetration_tool/main.py --help")).pack(side=tk.LEFT, padx=5)
        
        # Output text area
        ttk.Label(cmd_frame, text="Output:").grid(row=3, column=0, sticky=tk.W, pady=(10, 2))
        self.output_text = scrolledtext.ScrolledText(cmd_frame, height=20)
        self.output_text.grid(row=4, column=0, columnspan=3, sticky=tk.NSEW, pady=2)
        
        cmd_frame.rowconfigure(4, weight=1)
        cmd_frame.columnconfigure(1, weight=1)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
    def append_output(self, text):
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.update_idletasks()
        
    def update_status(self, text, color="black"):
        self.status_var.set(text)
        self.status_label.configure(foreground=color)
        
    def connect_ssh(self):
        if not PARAMIKO_AVAILABLE:
            messagebox.showerror("Error", "Paramiko library not found. Please install it using: pip install paramiko")
            return
            
        if self.is_connected:
            messagebox.showinfo("Info", "Already connected to SSH session")
            return
            
        host = self.ssh_host_var.get()
        port = int(self.ssh_port_var.get())
        username = self.ssh_username_var.get()
        password = self.ssh_password_var.get()
        
        if not host or not username or not password:
            messagebox.showerror("Error", "Please fill in all connection details")
            return
            
        def connect():
            try:
                self.progress.start()
                self.append_output(f"[*] Connecting to {username}@{host}:{port}...")
                
                # Create SSH client
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Connect
                self.ssh_client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=10
                )
                
                self.is_connected = True
                self.progress.stop()
                self.update_status("Connected", "green")
                self.append_output("[+] SSH connection established successfully")
                self.append_output("[*] You can now execute commands on the remote system")
                
            except paramiko.AuthenticationException:
                self.progress.stop()
                self.append_output("[-] Authentication failed")
                messagebox.showerror("Error", "Authentication failed. Check username/password.")
            except paramiko.SSHException as e:
                self.progress.stop()
                self.append_output(f"[-] SSH error: {str(e)}")
                messagebox.showerror("Error", f"SSH error: {str(e)}")
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Connection failed: {str(e)}")
                messagebox.showerror("Error", f"Connection failed: {str(e)}")
                
        thread = threading.Thread(target=connect)
        thread.daemon = True
        thread.start()
        
    def disconnect_ssh(self):
        if not self.is_connected or not self.ssh_client:
            messagebox.showinfo("Info", "No active SSH connection")
            return
            
        try:
            self.ssh_client.close()
            self.ssh_client = None
            self.is_connected = False
            self.update_status("Not connected", "red")
            self.append_output("[*] SSH connection closed")
        except Exception as e:
            self.append_output(f"[-] Error closing connection: {str(e)}")
            
    def test_connection(self):
        host = self.ssh_host_var.get()
        port = int(self.ssh_port_var.get())
        
        def test():
            try:
                self.progress.start()
                self.append_output(f"[*] Testing connection to {host}:{port}...")
                
                # Test TCP connection
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    self.progress.stop()
                    self.append_output(f"[+] Port {port} is open on {host}")
                    self.append_output("[*] TCP connection successful")
                else:
                    self.progress.stop()
                    self.append_output(f"[-] Port {port} is closed on {host}")
                    
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Connection test failed: {str(e)}")
                
        thread = threading.Thread(target=test)
        thread.daemon = True
        thread.start()
        
    def execute_command(self):
        if not self.is_connected or not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH session")
            return
            
        command = self.command_var.get()
        if not command:
            messagebox.showerror("Error", "Please enter a command")
            return
            
        def execute():
            try:
                self.progress.start()
                self.append_output(f"$ {command}")
                
                # Check if ssh_client is properly initialized
                if self.ssh_client is None:
                    self.progress.stop()
                    self.append_output("[-] SSH client not initialized")
                    return
                    
                # Execute command
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                
                # Get output
                output = stdout.read().decode('utf-8')
                error = stderr.read().decode('utf-8')
                
                if output:
                    self.append_output(output)
                if error:
                    self.append_output(f"Errors:\n{error}")
                    
                self.progress.stop()
                
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Command execution failed: {str(e)}")
                
        thread = threading.Thread(target=execute)
        thread.daemon = True
        thread.start()
        
    def run_quick_command(self, command):
        self.command_var.set(command)
        self.execute_command()
        
    def run_wifi_command(self, command):
        self.command_var.set(command)
        self.execute_command()


def main():
    # Check if paramiko is installed
    if not PARAMIKO_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error", "Paramiko library not found. Please install it using: pip install paramiko")
        root.destroy()
        return
        
    root = tk.Tk()
    app = SSHGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()