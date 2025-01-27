import socket
import subprocess
import platform
import ipaddress
import sys


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
    if platform.system().lower() == "windows":
        param = "-n"
    else:
        param = "-c"

    command = ["ping", param, "1", ip]

    try:
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"[+] {ip} is online")
        return True
    except subprocess.CalledProcessError:
        print(f"[-] {ip} is offline")
        return False


def scan_ip_range(ipStart, ipEnd):
    """Scan a range of IP addresses."""
    if not is_valid_ip(ipStart) or not is_valid_ip(ipEnd):
        print("Invalid IP range. Please provide valid IP addresses.")
        return

    start = int(ipStart.split('.')[-1])
    end = int(ipEnd.split('.')[-1])
    base_ip = '.'.join(ipStart.split('.')[:-1])  # Get the base (e.g., 192.168.1)

    for i in range(start, end + 1):
        ip = f"{base_ip}.{i}"
        ping_ip(ip)


def scan_ports(ip, ports):
    """Scan specific ports on an IP address."""
    if not is_valid_ip(ip):
        print("Invalid IP address. Please provide a valid IP address.")
        return

    for port in ports:
        if not is_valid_port(port):
            print(f"Invalid port {port}. Ports must be between 1 and 65535.")
            continue

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


if __name__ == "__main__":
    while True:
        print("\nWelcome to my Network Scanner!")
        print("Please choose an option:")
        print("1. Scan a single IP address")
        print("2. Scan a range of IP addresses")
        print("3. Scan ports on an IP address")
        print("4. Exit the scanner")

        choice = input("Enter your choice (1, 2, 3, or 4): ").strip()

        if choice == "1":
            ip = input("Enter the IP address to scan: ").strip()
            if is_valid_ip(ip):
                ping_ip(ip)
            else:
                print("Invalid IP address. Please try again.")
        elif choice == "2":
            ipStart = input("Enter the starting IP address: ").strip()
            ipEnd = input("Enter the ending IP address: ").strip()
            scan_ip_range(ipStart, ipEnd)
        elif choice == "3":
            ip = input("Enter the IP address to scan for open ports: ").strip()
            if not is_valid_ip(ip):
                print("Invalid IP address. Please try again.")
                continue

            try:
                ports = input("Enter the ports to scan (comma-separated, e.g., 22,80,443): ").strip()
                ports = [int(port.strip()) for port in ports.split(",")]

                if all(is_valid_port(port) for port in ports):
                    scan_ports(ip, ports)
                else:
                    print("One or more ports are invalid. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a list of integers separated by commas.")
        elif choice == "4":
            print("Exiting the Network Scanner. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")
