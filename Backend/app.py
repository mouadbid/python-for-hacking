from flask import Flask, render_template, jsonify, request
import platform
import scanner_nmap
import scan_modules
import attack_modules
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

if __name__ == '__main__':
    app.run(debug=True, port=5050)
