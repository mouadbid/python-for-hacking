document.addEventListener('DOMContentLoaded', () => {
    const networkList = document.getElementById('network-list');
    const targetInput = document.getElementById('target-input');
    const discoverBtn = document.getElementById('discover-btn');
    const hostsContainer = document.getElementById('hosts-container');
    const hostListSection = document.getElementById('host-list');
    const scanSection = document.getElementById('scan-section');
    const selectedHostSpan = document.getElementById('selected-host-ip');
    const scanBtn = document.getElementById('scan-btn');
    const scanTypeSelect = document.getElementById('scan-type');
    const resultsSection = document.getElementById('results-section');
    const scanOutput = document.getElementById('scan-output');

    // Brute Force Elements
    const navLinks = document.querySelectorAll('.nav-link');
    const views = document.querySelectorAll('.view-section');
    const bfTargetSelect = document.getElementById('bf-target');
    const bfAttackBtn = document.getElementById('bf-attack-btn');
    const bfOutput = document.getElementById('bf-output');
    const bfResultsSection = document.getElementById('bf-results-section');
    const bfScanBtn = document.getElementById('bf-scan-btn');
    const bfOpenPorts = document.getElementById('bf-open-ports');
    const bfPortList = document.getElementById('bf-port-list');
    const bfProtocolSelect = document.getElementById('bf-protocol');
    const bfPortInput = document.getElementById('bf-port');

    // Password Mode Elements
    const bfPassMode = document.getElementById('bf-pass-mode');
    const manualPassGroup = document.getElementById('manual-pass-group');
    const filePassGroup = document.getElementById('file-pass-group');
    const bfPassFile = document.getElementById('bf-pass-file');
    const fileStatus = document.getElementById('file-status');

    let currentHost = null;
    let discoveredHosts = []; // Store discovered hosts
    let filePasswords = []; // Store passwords from file




    // Load OS Info
    fetch('/api/system-info')
        .then(res => res.json())
        .then(data => {
            document.getElementById('os-info').innerHTML = `
                <span>${data.os} ${data.release}</span>
                <span style="margin-left: 1rem; color: #00ff41;">CPU: ${data.cpu}</span>
                <span style="margin-left: 1rem; color: #00ff41;">RAM: ${data.ram}</span>
            `;
        })
        .catch(err => {
            console.error('Failed to load OS info:', err);
            document.getElementById('os-info').textContent = 'OS: Unknown';
        });

    // Load Networks
    fetch('/api/networks')
        .then(res => res.json())
        .then(data => {
            networkList.innerHTML = '';
            for (const [name, ip] of Object.entries(data)) {
                const div = document.createElement('div');
                div.className = 'network-item';
                div.innerHTML = `<strong>${name}</strong><br><small>${ip}</small>`;
                div.onclick = () => {
                    // Pre-fill subnet guess (assuming /24 for simplicity, though accurate calculation handles it)
                    const parts = ip.split('.');
                    parts.pop();
                    targetInput.value = parts.join('.') + '.0/24';

                    document.querySelectorAll('.network-item').forEach(el => el.classList.remove('active'));
                    div.classList.add('active');
                };
                networkList.appendChild(div);
            }
        });

    // Discover Hosts
    discoverBtn.onclick = () => {
        const target = targetInput.value;
        if (!target) return alert('Please enter a target network');

        discoverBtn.disabled = true;
        discoverBtn.textContent = 'Scanning...';
        hostsContainer.innerHTML = '<div class="loading">Scanning network...</div>';
        hostListSection.classList.remove('hidden');

        fetch('/api/scan/discover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        })
            .then(res => res.json())
            .then(hosts => {
                hostsContainer.innerHTML = '';
                discoveredHosts = hosts; // Update global list
                updateBruteForceTargets();

                if (hosts.length === 0) {
                    hostsContainer.innerHTML = '<div>No hosts found. Try a different range.</div>';
                    return;
                }

                hosts.forEach(host => {
                    const div = document.createElement('div');
                    div.className = 'host-item';
                    div.innerHTML = `
                    <strong>${host.ip}</strong>
                    <br><small>${host.hostname || 'Unknown Host'}</small>
                    <br><span class="status">${host.status}</span>
                `;
                    div.onclick = () => {
                        document.querySelectorAll('.host-item').forEach(el => el.classList.remove('active'));
                        div.classList.add('active');
                        currentHost = host.ip;
                        selectedHostSpan.textContent = currentHost;
                        scanSection.classList.remove('disabled');
                    };
                    hostsContainer.appendChild(div);
                });
            })
            .catch(err => {
                hostsContainer.innerHTML = `<div class="error">Error: ${err}</div>`;
            })
            .finally(() => {
                discoverBtn.disabled = false;
                discoverBtn.textContent = 'Discover Hosts';
            });
    };

    // Run Scan
    scanBtn.onclick = () => {
        if (!currentHost) return;

        scanBtn.disabled = true;
        scanBtn.textContent = 'Running Scan...';
        resultsSection.classList.remove('hidden');
        scanOutput.textContent = 'Scanning target ' + currentHost + '...\nThis may take a moment.';

        fetch('/api/scan/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: currentHost,
                type: scanTypeSelect.value
            })
        })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    scanOutput.textContent = 'Error: ' + data.error;
                } else {
                    scanOutput.textContent = data.result;
                }
            })
            .catch(err => {
                scanOutput.textContent = 'Stack Error: ' + err;
            })
            .finally(() => {
                scanBtn.disabled = false;
                scanBtn.textContent = 'Run Scan';
            });
    };

    // Tab Switching
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = link.getAttribute('data-tab');
            if (!tabId) return;

            // Update Active Link
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Update View
            views.forEach(view => view.classList.add('hidden'));
            document.getElementById(`${tabId}-view`).classList.remove('hidden');
        });
    });

    // Populate Brute Force Targets
    function updateBruteForceTargets() {
        bfTargetSelect.innerHTML = '<option value="">Select a target...</option>';
        discoveredHosts.forEach(host => {
            const option = document.createElement('option');
            option.value = host.ip;
            option.textContent = `${host.ip} (${host.hostname || 'Unknown'})`;
            bfTargetSelect.appendChild(option);
        });
    }

    // Scan Target for Ports
    bfScanBtn.onclick = () => {
        const target = bfTargetSelect.value;
        if (!target) return alert('Please select a target first');

        bfScanBtn.disabled = true;
        bfScanBtn.textContent = 'Scanning...';
        bfPortList.innerHTML = '<span style="color: #aaa;">Scanning...</span>';
        bfOpenPorts.classList.remove('hidden');

        fetch('/api/scan/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                type: 'T' // TCP Connect Scan
            })
        })
            .then(res => res.json())
            .then(data => {
                bfPortList.innerHTML = '';

                if (data.error) {
                    bfPortList.innerHTML = `<span style="color: #ff0055;">Error: ${data.error}</span>`;
                    return;
                }

                // Parse Raw Nmap Data
                const scanData = data.raw.scan && data.raw.scan[target];
                if (!scanData || !scanData.tcp) {
                    bfPortList.innerHTML = '<span style="color: #aaa;">No open ports found or host down.</span>';
                    return;
                }

                const ports = scanData.tcp;

                for (const [port, info] of Object.entries(ports)) {
                    if (info.state === 'open') {
                        // Add to Port List
                        const badge = document.createElement('div');
                        badge.style.cssText = 'background: rgba(0, 255, 65, 0.1); color: #00ff41; padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid rgba(0, 255, 65, 0.3); font-size: 0.8rem; cursor: pointer;';
                        badge.textContent = `${port}/${info.name}`;
                        badge.title = "Click to select this port";

                        // Auto-fill on click
                        badge.onclick = () => {
                            bfPortInput.value = port;
                            if (info.name.includes('ssh')) bfProtocolSelect.value = 'ssh';
                            else if (info.name.includes('telnet')) bfProtocolSelect.value = 'telnet';
                            // Highlight effect
                            Array.from(bfPortList.children).forEach(c => c.style.background = 'rgba(0, 255, 65, 0.1)');
                            badge.style.background = 'rgba(0, 255, 65, 0.4)';
                        };

                        bfPortList.appendChild(badge);
                    }
                }
            })
            .catch(err => {
                bfPortList.innerHTML = `<span style="color: #ff0055;">Error: ${err}</span>`;
            })
            .finally(() => {
                bfScanBtn.disabled = false;
                bfScanBtn.textContent = 'Scan Ports';
            });
    };



    // Password Mode Toggle
    bfPassMode.addEventListener('change', () => {
        if (bfPassMode.value === 'manual') {
            manualPassGroup.classList.remove('hidden');
            filePassGroup.classList.add('hidden');
        } else {
            manualPassGroup.classList.add('hidden');
            filePassGroup.classList.remove('hidden');
        }
    });

    // File Upload Handling
    bfPassFile.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result;
            filePasswords = text.split('\n').filter(p => p.trim() !== '');
            fileStatus.textContent = `Loaded ${filePasswords.length} passwords from ${file.name}`;
            fileStatus.style.color = '#00ff41';
        };
        reader.onerror = () => {
            fileStatus.textContent = 'Error reading file';
            fileStatus.style.color = '#ff0055';
        };
        reader.readAsText(file);
    });

    // Run Brute Force Attack
    bfAttackBtn.onclick = () => {
        const target = bfTargetSelect.value;
        const service = bfProtocolSelect.value;
        const port = parseInt(bfPortInput.value);
        const username = document.getElementById('bf-username').value;
        const mode = bfPassMode.value;

        let passwords = [];

        if (mode === 'manual') {
            const passwordText = document.getElementById('bf-passwords').value;
            passwords = passwordText.split('\n').filter(p => p.trim() !== '');
        } else {
            passwords = filePasswords;
        }

        if (!target || !username || passwords.length === 0) {
            alert('Please fill in all fields (Target, Username) and provide passwords.');
            return;
        }

        bfAttackBtn.disabled = true;
        bfAttackBtn.textContent = 'Attacking...';
        bfResultsSection.classList.remove('hidden');
        bfOutput.textContent = `Starting ${service.toUpperCase()} attack on ${target}:${port} for user ${username}...\nTesting ${passwords.length} passwords...`;

        fetch('/api/attack/bruteforce', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target,
                service,
                port,
                username,
                passwords
            })
        })
            .then(res => res.json())
            .then(results => {
                if (results.error) {
                    bfOutput.textContent = `Error: ${results.error}`;
                } else {
                    let output = '';
                    let success = false;
                    results.forEach(res => {
                        output += `${res.message}\n`;
                        if (res.status === 'success') success = true;
                    });

                    if (success) {
                        bfOutput.innerHTML = `<span style="color: #00ff41">${output}</span>`;
                    } else {
                        bfOutput.textContent = output;
                    }
                }
            })
            .catch(err => {
                bfOutput.textContent = `Error: ${err}`;
            })
            .finally(() => {
                bfAttackBtn.disabled = false;
                bfAttackBtn.textContent = 'Start Attack';
            });
    };
});
