import socket
import subprocess
import platform
import sys



def ping_ip(ip):
    """Ping an IP address to check if it's online."""

    # This checks which operating system you are currently using
    if platform.system().lower() == "windows" :
        param = "-n"  
    else : "-c"
    command = ["ping", param, "1", ip]
    
    # This checks if the ip is online or offline
    try:
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"[+] {ip} is online")
        return True

    except subprocess.CalledProcessError:
        print(f"[-] {ip} is offline")
        return False
def scan_ip_range(ipStart, ipEnd):
    """Scan a range of IP addresses."""
    start = int(ipStart.split('.')[-1])
    end = int(ipEnd.split('.')[-1])
    base_ip = '.'.join(ipStart.split('.')[:-1])  # Get the base (e.g., 192.168.1)

    for i in range(start, end + 1):
        ip = f"{base_ip}.{i}"
        ping_ip(ip)

        
#This function takes an ip address and a list of ports to check
def scan_ports(ip, ports):
    """Scan specific ports on an IP address."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    print(f"[+] Port {port} is open on {ip}")
                else:
                    print(f"[-] Port {port} is closed on {ip}")
        except Exception as e:
            print(f"[!] Error scanning port {port} on {ip}: {e}")
"""
# Test
if __name__ == "__main__":
    start_ip = "8.8.8.1"
    end_ip = "8.8.8.10"
    scan_ip_range(start_ip, end_ip)
"""\

if __name__ == "__main__":
    ip_to_test = "8.8.8.8"
    ports_to_test = [22, 80, 443]  # Common ports
    scan_ports(ip_to_test, ports_to_test)
