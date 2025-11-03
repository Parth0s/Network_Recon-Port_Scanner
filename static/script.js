let scanInterval = null;
let currentScanType = 'quick';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeScanTypes();
    initializeFormatOptions();
    initializeScopeOptions();
});

// Scan Type Selection
function initializeScanTypes() {
    document.querySelectorAll('.scan-type-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.scan-type-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentScanType = btn.dataset.type;
        });
    });
}

// Port Range Quick Buttons
function setPortRange(range) {
    document.getElementById('port-range').value = range;
    document.querySelectorAll('.option-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
}

// Advanced Options Toggle
function toggleAdvanced() {
    const options = document.getElementById('advanced-options');
    const btn = event.currentTarget;
    
    options.classList.toggle('open');
    btn.classList.toggle('open');
}

// Start/Stop Scan
function startScan() {
    const btn = document.getElementById('start-scan-btn');
    const isScanning = btn.classList.contains('scanning');
    
    if (isScanning) {
        stopScan();
    } else {
        beginScan();
    }
}

function beginScan() {
    const target = document.getElementById('target-network').value;
    const portRange = document.getElementById('port-range').value;
    
    if (!target) {
        alert('Please enter a target network');
        return;
    }
    
    // Update UI
    const btn = document.getElementById('start-scan-btn');
    btn.classList.add('scanning');
    btn.innerHTML = '<span class="btn-icon">⏸</span><span>Stop Scan</span>';
    
    document.getElementById('status-indicator').classList.add('scanning');
    document.getElementById('status-text').textContent = 'Scanning...';
    document.getElementById('message-box').textContent = 'Scanning network for active hosts...';
    
    // Start scan
    fetch('/start-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            target: target,
            port_range: portRange,
            scan_type: currentScanType
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'started') {
            // Poll for progress
            scanInterval = setInterval(updateScanProgress, 1000);
        }
    })
    .catch(err => {
        console.error('Scan error:', err);
        alert('Failed to start scan: ' + err.message);
        stopScan();
    });
}

function stopScan() {
    const btn = document.getElementById('start-scan-btn');
    btn.classList.remove('scanning');
    btn.innerHTML = '<span class="btn-icon">▶</span><span>Start Scan</span>';
    
    document.getElementById('status-indicator').classList.remove('scanning');
    document.getElementById('status-text').textContent = 'Ready';
    
    if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
    }
}

function updateScanProgress() {
    fetch('/scan-progress')
        .then(res => res.json())
        .then(data => {
            // Update stats
            document.getElementById('hosts-scanned').textContent = data.stats.hosts_scanned;
            document.getElementById('active-hosts').textContent = data.stats.active_hosts;
            document.getElementById('ports-checked').textContent = data.stats.ports_checked;
            
            // Update results if scan complete
            if (!data.in_progress) {
                stopScan();
                displayResults(data.results);
                document.getElementById('message-box').textContent = 'Scan complete!';
            }
        })
        .catch(err => console.error('Progress update error:', err));
}

function displayResults(results) {
    const tbody = document.getElementById('results-tbody');
    const hostsCount = document.getElementById('hosts-count');
    
    tbody.innerHTML = '';
    
    const hosts = Object.keys(results);
    hostsCount.textContent = hosts.length;
    
    if (hosts.length === 0) {
        tbody.innerHTML = '<tr class="no-data"><td colspan="5">No hosts discovered yet</td></tr>';
        return;
    }
    
    hosts.forEach(ip => {
        const data = results[ip];
        const row = document.createElement('tr');
        
        const openPorts = data.ports ? data.ports.length : 0;
        const portsText = openPorts > 0 ? openPorts : '-';
        
        row.innerHTML = `
            <td>${ip}</td>
            <td>${data.hostname || 'N/A'}</td>
            <td><span style="color: #10b981;">●</span> ${data.status || 'up'}</td>
            <td>${portsText}</td>
            <td>${data.os || 'Unknown'}</td>
        `;
        
        row.style.cursor = 'pointer';
        row.addEventListener('click', () => showHostDetails(ip, data));
        
        tbody.appendChild(row);
    });
}

function showHostDetails(ip, data) {
    let detailsHTML = `<h3>Host: ${ip}</h3>`;
    detailsHTML += `<p>Hostname: ${data.hostname || 'N/A'}</p>`;
    detailsHTML += `<p>OS: ${data.os || 'Unknown'}</p>`;
    
    if (data.ports && data.ports.length > 0) {
        detailsHTML += '<h4>Open Ports:</h4><ul>';
        data.ports.forEach(port => {
            detailsHTML += `<li>Port ${port.port} - ${port.service} ${port.version || ''}</li>`;
        });
        detailsHTML += '</ul>';
    }
    
    // Display in a modal or message box
    document.getElementById('message-box').innerHTML = detailsHTML;
}

// Format Options
function initializeFormatOptions() {
    document.querySelectorAll('.format-option').forEach(option => {
        option.addEventListener('click', () => {
            document.querySelectorAll('.format-option').forEach(o => o.classList.remove('selected'));
            option.classList.add('selected');
            option.querySelector('input[type="radio"]').checked = true;
        });
    });
}

// Scope Options
function initializeScopeOptions() {
    document.querySelectorAll('.scope-option').forEach(option => {
        option.addEventListener('click', () => {
            document.querySelectorAll('.scope-option').forEach(o => o.classList.remove('selected'));
            option.classList.add('selected');
            option.querySelector('input[type="radio"]').checked = true;
        });
    });
}

// Generate Report
function generateReport() {
    const format = document.querySelector('input[name="format"]:checked').value;
    const scope = document.querySelector('input[name="scope"]:checked').value;
    
    const sections = [];
    document.querySelectorAll('.checkbox-list input[type="checkbox"]:checked').forEach(cb => {
        sections.push(cb.parentElement.textContent.trim());
    });
    
    fetch('/export-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format, scope, sections })
    })
    .then(res => res.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_report.${format}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    })
    .catch(err => {
        console.error('Export error:', err);
        alert('Failed to generate report');
    });
}
