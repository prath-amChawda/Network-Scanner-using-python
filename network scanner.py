import scapy.all as scapy
import socket
import os
import concurrent.futures

def check_privileges():
    """Check if the script is running with root privileges."""
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] This script must be run as root (sudo) to perform an ARP scan.")
        exit(1)

def scan_network(ip_range):
    """Perform an ARP scan to find active devices in the network."""
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        devices = []
        for element in answered_list:
            devices.append({
                'ip': element[1].psrc,
                'mac': element[1].hwsrc,
                'hostname': get_hostname(element[1].psrc)
            })
        return devices

    except Exception as e:
        print(f"[!] Error scanning network: {e}")
        return []

def get_hostname(ip):
    """Retrieve the hostname of a given IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def scan_ports(ip, port_range):
    """Scan specified ports on a given IP."""
    open_ports = []
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_port, port_range)
    
    return [port for port in results if port is not None]

def main():
    check_privileges()
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")

    print("\n[+] Scanning network...")
    devices = scan_network(ip_range)

    if not devices:
        print("[!] No active devices found.")
        return

    print("\nActive devices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")

        print(f"[*] Scanning ports on {device['ip']}...")
        open_ports = scan_ports(device['ip'], range(1, 1025))
        if open_ports:
            print(f"[+] Open ports on {device['ip']}: {open_ports}")
        else:
            print(f"[-] No open ports found on {device['ip']}.")

if __name__ == "__main__":
    main()
