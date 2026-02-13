import nmap
import sys
try:
    nm = nmap.PortScanner()
    print("Nmap scanner initialized")
    print(f"Nmap version: {nm.nmap_version()}")
    
    target = '127.0.0.1'
    print(f"Scanning {target} with -Pn...")
    nm.scan(target, arguments='-Pn')
    print(f"Hosts found: {nm.all_hosts()}")
    
    if target in nm.all_hosts():
        print(f"Host {target} is up")
        print(nm[target].state())
    else:
        print("Host still not found")

except nmap.PortScannerError as e:
    print(f"Nmap Error: {e}")
except Exception as e:
    print(f"Error: {e}")
