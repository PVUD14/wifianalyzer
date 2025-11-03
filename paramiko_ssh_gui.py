#!/usr/bin/env python3
"""
Paramiko-based SSH GUI for WiFi Penetration Testing Tool

This GUI provides actual SSH connectivity to the Kali Linux VM using paramiko
and allows running penetration testing commands remotely.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import paramiko
import socket
import subprocess
import platform


class ParamikoSSHGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Penetration Tool - Paramiko SSH")
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
        self.command_var = tk.StringVar(value="uname -a")
        
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
        ttk.Button(conn_buttons_frame, text="Find Kali VM", command=self.find_kali_vm).pack(side=tk.LEFT, padx=5)
        
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
        ttk.Button(quick_frame, text="System Info", command=lambda: self.set_command("uname -a")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Network Interfaces", command=lambda: self.set_command("iw dev")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Check Tools", command=lambda: self.set_command("which airodump-ng aireplay-ng aircrack-ng")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="List Interfaces", command=lambda: self.set_command("ip link show")).pack(side=tk.LEFT, padx=5)
        
        # WiFi Pen Testing commands
        wifi_frame = ttk.Frame(cmd_frame)
        wifi_frame.grid(row=2, column=0, columnspan=3, pady=5)
        
        ttk.Label(wifi_frame, text="WiFi Tools:").pack(side=tk.LEFT)
        ttk.Button(wifi_frame, text="Run Scan", command=lambda: self.set_command("sudo python3 wifi_penetration_tool/main.py")).pack(side=tk.LEFT, padx=5)
        ttk.Button(wifi_frame, text="Interface Manager", command=lambda: self.set_command("sudo python3 wifi_penetration_tool/main.py --help")).pack(side=tk.LEFT, padx=5)
        ttk.Button(wifi_frame, text="Run with Fern", command=lambda: self.set_command("sudo python3 wifi_penetration_tool/main.py --use-fern")).pack(side=tk.LEFT, padx=5)
        
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
        
    def set_command(self, command):
        self.command_var.set(command)
        
    def connect_ssh(self):
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
            except socket.timeout:
                self.progress.stop()
                self.append_output("[-] Connection timed out")
                self.append_output("[*] Troubleshooting tips:")
                self.append_output("  1. Check if the Kali VM is running")
                self.append_output("  2. Verify the IP address is correct")
                self.append_output("  3. Check network settings (Bridged/NAT/Host-only)")
                self.append_output("  4. Run 'find_kali_vm.bat' to discover the correct IP")
                messagebox.showerror("Error", "Connection timed out. Check network connectivity.")
            except socket.gaierror as e:
                self.progress.stop()
                self.append_output(f"[-] DNS resolution failed: {str(e)}")
                messagebox.showerror("Error", f"DNS resolution failed: {str(e)}")
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Connection failed: {str(e)}")
                messagebox.showerror("Error", f"Connection failed: {str(e)}")
                
        thread = threading.Thread(target=connect)
        thread.daemon = True
        thread.start()
        
    def disconnect_ssh(self):
        if not self.is_connected:
            messagebox.showinfo("Info", "No active SSH connection")
            return
            
        try:
            if self.ssh_client:
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
                    self.append_output("[*] Troubleshooting tips:")
                    self.append_output("  1. Check if the Kali VM is running")
                    self.append_output("  2. Verify SSH service is running on the VM")
                    self.append_output("  3. Check firewall settings on the VM")
                    self.append_output("  4. Run 'find_kali_vm.bat' to discover the correct IP")
                    
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Connection test failed: {str(e)}")
                
        thread = threading.Thread(target=test)
        thread.daemon = True
        thread.start()
        
    def find_kali_vm(self):
        """Run the Kali VM discovery tool."""
        self.append_output("[*] Launching Kali VM discovery tool...")
        self.append_output("[*] This will scan common IP ranges for Kali Linux VMs")
        self.append_output("[*] Please wait, this may take a few minutes...")
        
        def run_discovery():
            try:
                self.progress.start()
                # Run the discovery script
                subprocess.run(["find_kali_vm.bat"], shell=True)
                self.progress.stop()
                self.append_output("[*] Discovery tool completed")
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Failed to run discovery tool: {str(e)}")
                
        thread = threading.Thread(target=run_discovery)
        thread.daemon = True
        thread.start()
        
    def execute_command(self):
        if not self.is_connected:
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
                
                # Execute command
                if self.ssh_client is not None:
                    exec_result = self.ssh_client.exec_command(command)
                    # Handle the result properly
                    stdin = exec_result[0]
                    stdout = exec_result[1] 
                    stderr = exec_result[2]
                    
                    # Get output
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    
                    if output:
                        self.append_output(output)
                    if error:
                        self.append_output(f"Errors:\n{error}")
                else:
                    self.append_output("[-] SSH client is not initialized")
                    
                self.progress.stop()
                
            except Exception as e:
                self.progress.stop()
                self.append_output(f"[-] Command execution failed: {str(e)}")
                
        thread = threading.Thread(target=execute)
        thread.daemon = True
        thread.start()


def main():
    root = tk.Tk()
    app = ParamikoSSHGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()