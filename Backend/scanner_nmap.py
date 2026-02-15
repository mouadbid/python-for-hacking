import nmap as nm 
import sys
import psutil
import socket
import ipaddress
import scan_modules

def discover_hosts(target):
    # Initialize the scanner
    try:
        scanner = nm.PortScanner()
    except nm.PortScannerError:
        # If nmap is not found in the system path
        # If nmap is not found in the system path
        print("Nmap not found", sys.exc_info()[0])
        return []
    except Exception as e:
        # Catch unexpected errors
        print(f"Unexpected error: {e}")
        return []

    print(f"Scanning target: {target}")
    
    # Perform the scan
    # -sn: Ping Scan - disable port scan
    try:
        scanner.scan(hosts=target, arguments="-sn")
    except Exception as e:
        print(f"Scan failed: {e}")
        return []

    hosts_list = []
    
    # Iterate through all protocols (though -sn mainly uses ping) and all hosts found
    for host in scanner.all_hosts():
        # Get hostname (if available)
        hostnames = scanner[host].hostname()
        # Get status
        status = scanner[host].state()
        
        host_info = {
            'ip': host,
            'status': status,
            'hostname': hostnames
        }
        hosts_list.append(host_info)
    
    return hosts_list

def get_active_networks():
    """
    Returns a dictionary of active network interfaces and their IPv4 addresses.
    Excludes loopback (127.0.0.1) and disconnected interfaces.
    """
    active_interfaces = {}
    
    # Get all network interface stats (isup, speed, etc.)
    stats = psutil.net_if_stats()
    # Get all network interface addresses
    addrs = psutil.net_if_addrs()

    for interface_name, interface_addresses in addrs.items():
        # 1. Check if interface exists in stats and is "UP" (active)
        if interface_name in stats and stats[interface_name].isup:
            for address in interface_addresses:
                # 2. Filter for IPv4 only (AF_INET) and exclude Loopback (127.0.0.1)
                if address.family == socket.AF_INET and address.address != "127.0.0.1":
                    active_interfaces[interface_name] = address.address

    return active_interfaces

def validate_target(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False



if __name__ == "__main__":
    networks = get_active_networks()

    if networks:
        print(f"{'Interface':<20} {'IP Address':<20}")
        print("-" * 40)
        for name, ip in networks.items():
            print(f"{name:<20} {ip:<20}")
    else:
        print("No active network interfaces found.")
    target = input("Enter the target network (e.g., 192.168.1.0/24): ")

    while(not validate_target(target)):
        print("Invalid target")
        target = input("Enter the target network (e.g., 192.168.1.0/24): ")
    
    # Run the discovery
    found_hosts = discover_hosts(target)
    
    # Print results nicely
    print("-" * 40)
    print(f"Scan Results for {target}")
    print("-" * 40)
    
    if found_hosts:
        for host in found_hosts:
            print(f"IP: {host['ip']:<15} | Status: {host['status']:<10} | Hostname: {host['hostname']}")
    else:
        print("No hosts found responding to ping scan.")
        # We continue to allow manual entry in case host is up but blocking ping
    print("-" * 40)
    print("-" * 40)

    while True:
        victim = input("Enter the victim IP from the target network: ")
        try:
            # Check if victim IP is valid and in the target network
            if ipaddress.ip_address(victim) in ipaddress.ip_network(target, strict=False):
                print(f"Victim IP {victim} is valid and in the network.")
                break
            else:
                print("Error: Victim IP is not in the target network.")
        except ValueError:
            print("Error: Invalid IP address format.")
            
    print("-" * 40)
    print('Choose the type of scanning:')
    print('[T: TCP Connect Scan]')
    print('[U: UDP Scan]')
    print('[S: SYN Stealth Scan]')
    print('[O: OS Detection]')
    print('[V: Version Detection]')
    print('[A: Aggressive Scan]')
    
    scanning_type = input("Enter your choice (T/U/S/O/V/A): ").upper()

    scanner = nm.PortScanner()
    print(f"Starting scan on {victim}...")

    try:
        if scanning_type == "T":
            scan_modules.scan_tcp(victim, scanner)
        elif scanning_type == "U":
            scan_modules.scan_udp(victim, scanner)
        elif scanning_type == "S":
            scan_modules.scan_syn(victim, scanner)
        elif scanning_type == "O":
            scan_modules.scan_os(victim, scanner)
        elif scanning_type == "V":
             scan_modules.scan_version(victim, scanner)
        elif scanning_type == "A":
            scan_modules.scan_aggressive(victim, scanner)
        else:
            print("Invalid scanning type selected.")
            sys.exit(1)
            
        # Display results using the new formatter
        print(scan_modules.format_results(scanner, victim))

    except nm.PortScannerError as e:
        print(f"Nmap error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
