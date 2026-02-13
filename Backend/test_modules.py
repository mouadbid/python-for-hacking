import nmap
import scan_modules

def test():
    try:
        nm = nmap.PortScanner()
        target = '127.0.0.1'
        print(f"Testing TCP scan on {target}...")
        
        # Manually run a TCP scan using our module
        scan_modules.scan_tcp(target, nm)
        
        # Test formatting
        print("\n--- Formatted Results ---")
        print(scan_modules.format_results(nm, target))
        
    except Exception as e:
        print(f"Test failed: {e}")

if __name__ == "__main__":
    test()
