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


# Test
if __name__ == "__main__":
    start_ip = "8.8.8.1"
    end_ip = "8.8.8.10"
    scan_ip_range(start_ip, end_ip)
