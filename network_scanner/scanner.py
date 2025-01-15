import socket
import subprocess
import platform
import sys



def ping_ip(ip):
    """Ping an IP address to check if it's online."""

    # This checks which operating system you are currently using
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]
    
    # This checks if the ip is online or offline
    try:
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"[+] {ip} is online")
        return True

    except subprocess.CalledProcessError:
        print(f"[-] {ip} is offline")
        return False

# This tests the ping function
if __name__ == "__main__":
    ip_to_test = "8.8.8.8"  # Google's public DNS
    ping_ip(ip_to_test)

