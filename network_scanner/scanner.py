import socket
import subprocess
import platform
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import messagebox, simpledialog

def is_valid_ip(ip):
    """Check if the IP address is valid."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    """Check if the port is valid."""
    return 1 <= port <= 65535

def ping_ip(ip):
    """Ping an IP address to check if it's online."""

    # This checks which operating system you are currently using
    if platform.system().lower() == "windows":
        param = "-n"
    else:
        param = "-c"

    command = ["ping", param, "1", ip]

    # This checks if the ip is online or offline
    try:
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return f"[+] {ip} is online"
    except subprocess.CalledProcessError:
        return f"[-] {ip} is offline"

def scan_ip_range(ipStart, ipEnd):
    """Scan a range of IP addresses using multi-threading."""
    if not is_valid_ip(ipStart) or not is_valid_ip(ipEnd):
        return "Invalid IP range. Please provide valid IP addresses."

    start = int(ipStart.split('.')[-1])
    end = int(ipEnd.split('.')[-1])
    base_ip = '.'.join(ipStart.split('.')[:-1])  # Get the base (e.g., 192.168.1)

    results = []

    def scan_single_ip(i):
        ip = f"{base_ip}.{i}"
        results.append(ping_ip(ip))

    with ThreadPoolExecutor(max_workers=10) as executor:  # Limit threads to 10 (Change this depending on how many ips you want to check at once)
        executor.map(scan_single_ip, range(start, end + 1))

    return "\n".join(results)

def scan_ports(ip, ports):
    """Scan specific ports on an IP address using multi-threading."""
    if not is_valid_ip(ip):
        return "Invalid IP address. Please provide a valid IP address."

    results = []

    def scan_single_port(port):
        if not is_valid_port(port):
            results.append(f"Invalid port {port}. Ports must be between 1 and 65535.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                if result == 0:
                    results.append(f"[+] Port {port} is open on {ip}")
                else:
                    results.append(f"[-] Port {port} is closed on {ip}")
        except Exception as e:
            results.append(f"[!] Error scanning port {port} on {ip}: {e}")

    with ThreadPoolExecutor(max_workers=10) as executor:  # Limit threads to 10 (Change this depending on how many ports you want to check at once)
        executor.map(scan_single_port, ports)

    return "\n".join(results)

def start_gui():
    """Start the GUI for the network scanner."""
    def handle_ping():
        ip = simpledialog.askstring("Ping IP", "Enter the IP address to scan:")
        if ip and is_valid_ip(ip):
            result = ping_ip(ip)
            messagebox.showinfo("Ping Result", result)
        else:
            messagebox.showerror("Error", "Invalid IP address. Please try again.")

    def handle_ip_range():
        ipStart = simpledialog.askstring("IP Range", "Enter the starting IP address:")
        ipEnd = simpledialog.askstring("IP Range", "Enter the ending IP address:")
        if ipStart and ipEnd:
            result = scan_ip_range(ipStart, ipEnd)
            messagebox.showinfo("IP Range Scan Results", result)
        else:
            messagebox.showerror("Error", "Invalid IP range. Please try again.")

    def handle_port_scan():
        ip = simpledialog.askstring("Port Scan", "Enter the IP address to scan for open ports:")
        if not ip or not is_valid_ip(ip):
            messagebox.showerror("Error", "Invalid IP address. Please try again.")
            return

        ports = simpledialog.askstring("Port Scan", "Enter the ports to scan (comma-separated, e.g., 22,80,443):")
        try:
            ports = [int(port.strip()) for port in ports.split(",")]
            if all(is_valid_port(port) for port in ports):
                result = scan_ports(ip, ports)
                messagebox.showinfo("Port Scan Results", result)
            else:
                messagebox.showerror("Error", "One or more ports are invalid. Please try again.")
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Please enter a list of integers separated by commas.")

    def handle_exit():
        root.destroy()

    root = tk.Tk()
    root.title("Network Scanner")

    tk.Label(root, text="Welcome to my Network Scanner!", font=("Helvetica", 16)).pack(pady=10)

    tk.Button(root, text="Ping a Single IP", command=handle_ping, width=30).pack(pady=5)
    tk.Button(root, text="Scan IP Range", command=handle_ip_range, width=30).pack(pady=5)
    tk.Button(root, text="Scan Ports on an IP", command=handle_port_scan, width=30).pack(pady=5)
    tk.Button(root, text="Exit", command=handle_exit, width=30).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    start_gui()
