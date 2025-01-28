import socket
import subprocess
import platform
import ipaddress
import json
import tkinter as tk
from tkinter import messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor

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
        return True
    except subprocess.CalledProcessError:
        return False

def scan_ip_range(ipStart, ipEnd):
    """Scan a range of IP addresses using multi-threading."""
    if not is_valid_ip(ipStart) or not is_valid_ip(ipEnd):
        print("Invalid IP range. Please provide valid IP addresses.")
        return

    start = int(ipStart.split('.')[-1])
    end = int(ipEnd.split('.')[-1])
    base_ip = '.'.join(ipStart.split('.')[:-1])  # Get the base (e.g., 192.168.1)

    def scan_single_ip(i):
        ip = f"{base_ip}.{i}"
        if ping_ip(ip):
            print(f"[+] {ip} is online")
        else:
            print(f"[-] {ip} is offline")

    with ThreadPoolExecutor(max_workers=10) as executor:  # Limit threads to 10
        executor.map(scan_single_ip, range(start, end + 1))

def scan_ports(ip, ports):
    """Scan specific ports on an IP address using multi-threading."""
    if not is_valid_ip(ip):
        print("Invalid IP address. Please provide a valid IP address.")
        return

    def scan_single_port(port):
        if not is_valid_port(port):
            print(f"Invalid port {port}. Ports must be between 1 and 65535.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                if result == 0:
                    print(f"[+] Port {port} is open on {ip}")
                else:
                    print(f"[-] Port {port} is closed on {ip}")
        except Exception as e:
            print(f"[!] Error scanning port {port} on {ip}: {e}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_single_port, ports)

def save_configuration(data):
    """Save the configuration to a JSON file."""
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if not file_path:
        return

    try:
        with open(file_path, "w") as file:
            json.dump(data, file, indent=4)
        messagebox.showinfo("Success", "Configuration saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save configuration: {e}")

def main_gui():
    """Create the main GUI for the network scanner."""
    def handle_save():
        data = {
            "single_ip": single_ip_entry.get(),
            "range_start": range_start_entry.get(),
            "range_end": range_end_entry.get(),
            "ports": ports_entry.get()
        }
        save_configuration(data)

    def handle_single_ip_scan():
        ip = single_ip_entry.get().strip()
        if is_valid_ip(ip):
            if ping_ip(ip):
                messagebox.showinfo("Result", f"[+] {ip} is online")
            else:
                messagebox.showinfo("Result", f"[-] {ip} is offline")
        else:
            messagebox.showerror("Error", "Invalid IP address. Please try again.")

    def handle_range_scan():
        ip_start = range_start_entry.get().strip()
        ip_end = range_end_entry.get().strip()
        scan_ip_range(ip_start, ip_end)

    def handle_port_scan():
        ip = single_ip_entry.get().strip()
        try:
            ports = [int(port.strip()) for port in ports_entry.get().split(",")]
            scan_ports(ip, ports)
        except ValueError:
            messagebox.showerror("Error", "Invalid port list. Please enter comma-separated integers.")

    root = tk.Tk()
    root.title("Network Scanner")

    tk.Label(root, text="Single IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    single_ip_entry = tk.Entry(root, width=30)
    single_ip_entry.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(root, text="IP Range Start:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    range_start_entry = tk.Entry(root, width=30)
    range_start_entry.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(root, text="IP Range End:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
    range_end_entry = tk.Entry(root, width=30)
    range_end_entry.grid(row=2, column=1, padx=5, pady=5)

    tk.Label(root, text="Ports (comma-separated):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
    ports_entry = tk.Entry(root, width=30)
    ports_entry.grid(row=3, column=1, padx=5, pady=5)

    single_ip_button = tk.Button(root, text="Scan Single IP", command=handle_single_ip_scan)
    single_ip_button.grid(row=4, column=0, padx=5, pady=5)

    range_scan_button = tk.Button(root, text="Scan IP Range", command=handle_range_scan)
    range_scan_button.grid(row=4, column=1, padx=5, pady=5)

    port_scan_button = tk.Button(root, text="Scan Ports", command=handle_port_scan)
    port_scan_button.grid(row=5, column=0, padx=5, pady=5)

    save_button = tk.Button(root, text="Save Configuration", command=handle_save)
    save_button.grid(row=5, column=1, padx=5, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main_gui()
