from flask import Flask, render_template, jsonify, request
import platform
import scanner_nmap
import scan_modules
import attack_modules
import sniff_modules
import nmap
import ipaddress
import psutil

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/system-info', methods=['GET'])
def get_system_info():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    return jsonify({
        'os': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'node': platform.node(),
        'cpu': f"{cpu_percent}%",
        'ram': f"{memory.percent}%"
    })

@app.route('/api/networks', methods=['GET'])
def get_networks():
    networks = scanner_nmap.get_active_networks()
    return jsonify(networks)

@app.route('/api/scan/discover', methods=['POST'])
def discover():
    data = request.json
    target = data.get('target')
    if not scanner_nmap.validate_target(target):
        return jsonify({'error': 'Invalid target network'}), 400
    
    hosts = scanner_nmap.discover_hosts(target)
    return jsonify(hosts)

@app.route('/api/scan/run', methods=['POST'])
def run_scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('type')
    
    scanner = nmap.PortScanner()
    
    try:
        if scan_type == "T":
            result = scan_modules.scan_tcp(target, scanner)
        elif scan_type == "U":
            result = scan_modules.scan_udp(target, scanner)
        elif scan_type == "S":
            result = scan_modules.scan_syn(target, scanner)
        elif scan_type == "O":
            result = scan_modules.scan_os(target, scanner)
        elif scan_type == "V":
            result = scan_modules.scan_version(target, scanner)
        elif scan_type == "A":
            result = scan_modules.scan_aggressive(target, scanner)
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
            
        formatted_result = scan_modules.format_results(scanner, target)
        return jsonify({'result': formatted_result, 'raw': result})
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack/bruteforce', methods=['POST'])
def brute_force():
    data = request.json
    target = data.get('target')
    service = data.get('service') # 'ssh' or 'telnet'
    port = int(data.get('port', 0))
    username = data.get('username')
    passwords = data.get('passwords') # List of passwords
    
    print(f"Received Brute Force Request: Target={target}, Service={service}, Port={port}, User={username}")

    if not all([target, service, username, passwords]):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        if service.lower() == 'ssh':
            if port == 0: port = 22
            print(f"[DEBUG] Starting SSH attack on {target}:{port}")
            results = attack_modules.brute_force_ssh(target, username, passwords, port=port)
        elif service.lower() == 'telnet':
            if port == 0: port = 23
            print(f"[DEBUG] Starting Telnet attack on {target}:{port}")
            results = attack_modules.brute_force_telnet(target, username, passwords, port=port)
        else:
            return jsonify({'error': 'Unsupported service'}), 400
            
        return jsonify(results)
        
    except Exception as e:
        print(f"[ERROR] Brute force failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Server Error: {str(e)}"}), 500

@app.route('/api/attack/analyze', methods=['POST'])
def analyze_target():
    data = request.json
    target = data.get('target')
    port = data.get('port', 80)
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
        
    result = attack_modules.check_target(target, port)
    return jsonify(result)

@app.route('/api/attack/dos', methods=['POST'])
def attack_dos():
    data = request.json
    target = data.get('target')
    port = int(data.get('port', 80))
    duration = int(data.get('duration', 60))
    packet_size = int(data.get('packet_size', 1024))
    attack_type = data.get('type', 'udp').lower()
    
    # Safety Check
    if duration > 60:
        duration = 60
        
    print(f"Starting {attack_type.upper()} Flood on {target}:{port} for {duration}s")
    
    if attack_type == 'udp':
        result = attack_modules.udp_flood(target, port, duration, packet_size)
    elif attack_type == 'tcp':
        result = attack_modules.tcp_flood(target, port, duration)
    elif attack_type == 'http':
        result = attack_modules.http_flood(target, port, duration)
    else:
        return jsonify({'error': 'Invalid attack type'}), 400
    
    return jsonify(result)

@app.route('/api/attack/my-ip', methods=['GET'])
def get_my_ip():
    try:
        # Trick to get the primary IP used for internet connection
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return jsonify({'ip': ip})
    except:
        return jsonify({'ip': '127.0.0.1'})

@app.route('/api/attack/arp/start', methods=['POST'])
def start_arp():
    data = request.json
    target = data.get('target')
    gateway = data.get('gateway')
    
    if not target or not gateway:
        return jsonify({'error': 'Target and Gateway IPs are required'}), 400
        
    result = attack_modules.start_arp_spoof(target, gateway)
    return jsonify(result)

@app.route('/api/attack/arp/stop', methods=['POST'])
def stop_arp():
    data = request.json
    target = data.get('target')
    gateway = data.get('gateway')
    
    result = attack_modules.stop_arp_spoof(target, gateway)
    return jsonify(result)

@app.route('/api/sniff', methods=['POST'])
def sniff_packets():
    data = request.json
    try:
        interface = data.get('interface')
        try:
            count = int(data.get('count', 10))
        except (ValueError, TypeError):
             count = 10
        
        except (ValueError, TypeError):
             count = 10
        
        target_ip = data.get('target_ip')
        filter_str = ""
        
        if target_ip:
            filter_str = f"host {target_ip}"
        
        # Additional custom filter if needed (not fully implemented in UI but supported in backend)
        if data.get('filter'):
             if filter_str:
                 filter_str += f" and {data.get('filter')}"
             else:
                 filter_str = data.get('filter')
        
        # Security/Sanity check on count
        if count > 100:
            count = 100
            
        print(f"[DEBUG] Sniffing {count} packets on {interface} filter='{filter_str}'")
        packets = sniff_modules.capture_packets(interface, count, filter_str)
        return jsonify(packets)
        
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5050)
