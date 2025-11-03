from flask import Flask, render_template, request, jsonify, send_file
from scanner import NetworkScanner
import threading
import json
from datetime import datetime
import io
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
scanner = NetworkScanner()

# Global variables for scan state
scan_in_progress = False
scan_results = {}
scan_stats = {
    'hosts_scanned': 0,
    'active_hosts': 0,
    'ports_checked': 0
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    global scan_in_progress, scan_results, scan_stats
    
    if scan_in_progress:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    data = request.json
    target = data.get('target', '')
    port_range = data.get('port_range', '1-1000')
    scan_type = data.get('scan_type', 'quick')
    
    app.logger.info(f"Starting scan: target={target}, ports={port_range}, type={scan_type}")
    
    if not target:
        return jsonify({'error': 'Target network required'}), 400
    
    # Reset state
    scan_in_progress = True
    scan_results = {}
    scan_stats = {'hosts_scanned': 0, 'active_hosts': 0, 'ports_checked': 0}
    
    # Start scan in background thread
    thread = threading.Thread(
        target=run_scan,
        args=(target, port_range, scan_type)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started'})

def run_scan(target, port_range, scan_type):
    global scan_in_progress, scan_results, scan_stats
    
    try:
        app.logger.info("Scan thread started")
        results = scanner.scan_network(
            target, 
            port_range, 
            scan_type,
            progress_callback=update_progress
        )
        scan_results = results
        app.logger.info(f"Scan complete. Found {len(results)} hosts")
    except Exception as e:
        app.logger.error(f"Scan error: {e}")
        import traceback
        traceback.print_exc()
        scan_results = {'error': str(e)}
    finally:
        scan_in_progress = False
        app.logger.info("Scan thread finished")

def update_progress(hosts_scanned, active_hosts, ports_checked):
    global scan_stats
    scan_stats = {
        'hosts_scanned': hosts_scanned,
        'active_hosts': active_hosts,
        'ports_checked': ports_checked
    }
    app.logger.debug(f"Progress: scanned={hosts_scanned}, active={active_hosts}, ports={ports_checked}")

@app.route('/scan-progress')
def scan_progress():
    return jsonify({
        'in_progress': scan_in_progress,
        'stats': scan_stats,
        'results': scan_results if not scan_in_progress else {}
    })

@app.route('/export-report', methods=['POST'])
def export_report():
    data = request.json
    format_type = data.get('format', 'pdf')
    scope = data.get('scope', 'all')
    sections = data.get('sections', [])
    
    app.logger.info(f"Generating {format_type} report")
    
    if format_type == 'json':
        output = io.BytesIO()
        output.write(json.dumps(scan_results, indent=2).encode('utf-8'))
        output.seek(0)
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
    
    elif format_type == 'pdf':
        pdf_buffer = scanner.generate_pdf_report(scan_results, sections)
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
    
    elif format_type == 'csv':
        csv_buffer = scanner.generate_csv_report(scan_results)
        return send_file(
            csv_buffer,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    
    elif format_type == 'xml':
        xml_buffer = scanner.generate_xml_report(scan_results)
        return send_file(
            xml_buffer,
            mimetype='application/xml',
            as_attachment=True,
            download_name=f'scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xml'
        )

if __name__ == '__main__':
    print("\n" + "="*50)
    print("Network Recon Scanner Starting...")
    print("Open: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
