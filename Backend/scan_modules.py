import nmap

def scan_tcp(target, scanner):
    """Performs a TCP Connect Scan (-sT)"""
    print(f"Running TCP Connect Scan on {target}...")
    return scanner.scan(target, arguments='-sT -Pn')

def scan_udp(target, scanner):
    """Performs a UDP Scan (-sU)"""
    print(f"Running UDP Scan on {target}...")
    return scanner.scan(target, arguments='-sU -Pn')

def scan_syn(target, scanner):
    """Performs a SYN Stealth Scan (-sS)"""
    print(f"Running SYN Stealth Scan on {target}...")
    return scanner.scan(target, arguments='-sS -Pn')

def scan_os(target, scanner):
    """Performs OS Detection (-O)"""
    print(f"Running OS Detection on {target}...")
    return scanner.scan(target, arguments='-O -Pn')

def scan_version(target, scanner):
    """Performs Version Detection (-sV)"""
    print(f"Running Version Detection on {target}...")
    return scanner.scan(target, arguments='-sV -Pn')

def scan_aggressive(target, scanner):
    """Performs Aggressive Scan (-A)"""
    print(f"Running Aggressive Scan on {target}...")
    return scanner.scan(target, arguments='-A -Pn')

def format_results(scanner, target):
    """Formats the scan results into a readable string with detailed information."""
    if target not in scanner.all_hosts():
        return f"No scan results returned for {target}. Host might be down, filtering probes, or Nmap lacks privileges (try running as Admin)."

    host_data = scanner[target]
    
    output = []
    output.append("-" * 40)
    output.append(f"Scan Report for {target}")
    output.append(f"State: {host_data.state()}")
    
    # Process Protocols
    protocols = host_data.all_protocols()
    if not protocols:
        output.append("\nNo open ports found in the scanned range.")
        return "\n".join(output)

    for proto in protocols:
        output.append(f"\nProtocol: {proto.upper()}")
        ports = host_data[proto].keys()
        for port in sorted(ports):
            service_info = host_data[proto][port]
            state = service_info['state']
            service_name = service_info['name']
            product = service_info.get('product', '')
            version = service_info.get('version', '')
            extrainfo = service_info.get('extrainfo', '')
            
            service_details = f"{product} {version} {extrainfo}".strip()
            
            line = f"Port: {port:<5} | State: {state:<8} | Service: {service_name:<15}"
            if service_details:
                line += f" | Details: {service_details}"
            output.append(line)

    # Process OS Matches
    if 'osmatch' in host_data:
        output.append("\nOS Detection Results:")
        for osmatch in host_data['osmatch']:
            output.append(f"  - {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
            
    # Process Hostnames
    hostnames = host_data.hostname()
    if hostnames:
        output.append(f"\nHostname: {hostnames}")
        
    output.append("-" * 40)
    return "\n".join(output)
