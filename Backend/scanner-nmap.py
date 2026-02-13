import nmap as nm 
import sys

def discover_hosts(target):
    # Initialize the scanner
    try:
        scanner = nm.PortScanner()
    except nm.PortScannerError:
        # If nmap is not found in the system path
        print("Nmap not found", sys.exc_info()[0])
        sys.exit(1)
    except Exception as e:
        # Catch unexpected errors
        print(f"Unexpected error: {e}")
        sys.exit(1)

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

if __name__ == "__main__":
    target = "192.168.1.0/24"
    
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
        print("No hosts found.")
    print("-" * 40)
