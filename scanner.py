import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import re
import time
import platform
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import io
import csv
import xml.etree.ElementTree as ET

# Try scapy for ARP
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try nmap
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

class NetworkScanner:
    def __init__(self):
        self.common_ports = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
            139: 'NetBIOS', 389: 'LDAP', 636: 'LDAPS', 1433: 'MSSQL',
            1521: 'Oracle', 6379: 'Redis', 9200: 'Elasticsearch', 5000: 'Flask',
            8000: 'HTTP-Alt', 9090: 'HTTP-Alt', 5353: 'mDNS'
        }
        self.device_vendors = {}

    def scan_network(self, target, port_range, scan_type, progress_callback=None):
        """Main scanning - GUARANTEED to find ALL devices"""
        results = {}
        try:
            # Parse target
            if '-' in target:
                base = target.rsplit('.', 1)[0]
                start, end = target.rsplit('.', 1)[1].split('-')
                target_cidr = f"{base}.0/24"
            elif '/' in target:
                target_cidr = target
            else:
                target_cidr = f"{target}/32"

            print(f"\n{'='*60}")
            print(f"[SCAN] Starting scan of {target_cidr}")
            print(f"{'='*60}\n")

            # STEP 1: COMPREHENSIVE Device Discovery (ALL METHODS)
            print("[1/3] Running comprehensive device discovery...")
            all_devices = self.comprehensive_discovery(target_cidr)
            
            print(f"[FOUND] {len(all_devices)} total devices on network\n")
            
            # Show what we found
            for ip, mac in all_devices.items():
                print(f"  • {ip:<15} MAC: {mac}")
            print()

            if progress_callback:
                progress_callback(len(all_devices), len(all_devices), 0)

            # STEP 2: Determine ports based on scan type (CONSISTENT)
            print("[2/3] Preparing port scan...")
            ports = self.get_ports_for_scan(port_range, scan_type)
            print(f"  Will scan {len(ports)} ports per host\n")

            # STEP 3: Port scan each device (UNIFIED METHOD)
            print("[3/3] Scanning ports on all devices...")
            total_ports_checked = 0

            for idx, (ip, mac) in enumerate(all_devices.items(), 1):
                print(f"[{idx}/{len(all_devices)}] Scanning {ip}...")
                
                # Use UNIFIED scanning method
                host_data = self.unified_scan_host(ip, ports, scan_type)
                
                # Add MAC address
                host_data['mac'] = mac
                
                # Always add to results (even 0 ports)
                results[ip] = host_data
                
                total_ports_checked += len(ports)
                
                if progress_callback:
                    progress_callback(len(all_devices), len(all_devices), total_ports_checked)
                
                print(f"  → Found {len(host_data.get('ports', []))} open ports")

            print(f"\n[COMPLETE] Scan finished!")
            print(f"{'='*60}\n")

            return results

        except Exception as e:
            print(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()
            return {}

    def comprehensive_discovery(self, target_cidr):
        """COMPREHENSIVE discovery - combines ALL methods"""
        all_devices = {}
        
        print("  [DISCOVERY] Using multiple detection methods...")
        
        # Method 1: Scapy ARP (if available)
        if SCAPY_AVAILABLE:
            try:
                print("  [ARP-SCAPY] Scanning with scapy (5s timeout)...")
                arp = ARP(pdst=target_cidr)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = srp(packet, timeout=5, verbose=0, retry=2)[0]  # Increased timeout + retry
                
                for sent, received in result:
                    all_devices[received.psrc] = received.hwsrc
                    print(f"    Found: {received.psrc} ({received.hwsrc})")
                
                print(f"  [ARP-SCAPY] Found {len(all_devices)} devices")
            except Exception as e:
                print(f"  [ARP-SCAPY] Error: {e}")
        
        # Method 2: System ARP table (always try, even if scapy worked)
        try:
            print("  [ARP-SYSTEM] Reading system ARP cache...")
            if platform.system() == 'Windows':
                output = subprocess.check_output(['arp', '-a'], text=True, timeout=10)
                for line in output.split('\n'):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-:]+)\s+dynamic', line)
                    if match:
                        ip, mac = match.groups()
                        if ip not in all_devices:
                            all_devices[ip] = mac
                            print(f"    Found: {ip} ({mac})")
            else:
                # First, populate ARP table with ping broadcast
                network = ipaddress.ip_network(target_cidr, strict=False)
                broadcast = str(network.broadcast_address)
                
                # Try multiple broadcast pings
                for _ in range(3):
                    subprocess.run(['ping', '-c', '2', '-b', broadcast],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                    time.sleep(0.5)
                
                # Read ARP table
                output = subprocess.check_output(['arp', '-n'], text=True, timeout=10)
                for line in output.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip_match = re.match(r'\d+\.\d+\.\d+\.\d+', parts[0])
                        if ip_match and parts[2] not in ['(incomplete)', '<incomplete>']:
                            if parts[0] not in all_devices:
                                all_devices[parts[0]] = parts[2]
                                print(f"    Found: {parts[0]} ({parts[2]})")
            
            print(f"  [ARP-SYSTEM] Total unique devices so far: {len(all_devices)}")
        except Exception as e:
            print(f"  [ARP-SYSTEM] Error: {e}")
        
        # Method 3: nmap host discovery (if available and not enough devices found)
        if NMAP_AVAILABLE:
            try:
                print("  [NMAP-PING] Running nmap host discovery...")
                nm = nmap.PortScanner()
                nm.scan(hosts=target_cidr, arguments='-sn -T4')  # Faster timing
                
                for host in nm.all_hosts():
                    if host not in all_devices:
                        if 'mac' in nm[host]['addresses']:
                            mac = nm[host]['addresses']['mac']
                        else:
                            mac = 'Unknown'
                        all_devices[host] = mac
                        print(f"    Found: {host} ({mac})")
                
                print(f"  [NMAP-PING] Total unique devices so far: {len(all_devices)}")
            except Exception as e:
                print(f"  [NMAP-PING] Error: {e}")
        
        # Method 4: Aggressive ping sweep (last resort - only if very few devices)
        if len(all_devices) < 3:
            print("  [PING-SWEEP] Running aggressive ping sweep...")
            network = ipaddress.ip_network(target_cidr, strict=False)
            
            def ping_host(ip):
                try:
                    param = '-n' if platform.system() == 'Windows' else '-c'
                    result = subprocess.run(
                        ['ping', param, '2', '-W', '2', str(ip)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=3
                    )
                    if result.returncode == 0:
                        return str(ip)
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
                for future in as_completed(futures):
                    result = future.result()
                    if result and result not in all_devices:
                        all_devices[result] = 'Unknown'
                        print(f"    Found: {result}")
            
            print(f"  [PING-SWEEP] Total devices found: {len(all_devices)}")
        
        return all_devices

    def get_ports_for_scan(self, port_range, scan_type):
        """Determine ports to scan based on scan type - CONSISTENT"""
        if scan_type == 'quick':
            # Quick scan - common ports
            return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900, 8080]
        elif scan_type == 'deep':
            # Deep scan - top 1000 ports
            return list(range(1, 1001))
        elif scan_type == 'service' or scan_type == 'os':
            # Service/OS detection - top 100 ports
            return list(range(1, 101))
        else:
            # Custom port range
            try:
                if '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                    return list(range(start_port, min(end_port + 1, 65536)))
                else:
                    return [int(port_range)]
            except:
                return list(range(1, 1001))

    def unified_scan_host(self, ip, ports, scan_type):
        """UNIFIED scanning method - consistent output regardless of scan type"""
        result = {
            'hostname': self.get_hostname(ip),
            'status': 'up',
            'ports': [],
            'os': 'Unknown'
        }
        
        try:
            # Use nmap if available AND scan type requires it
            if NMAP_AVAILABLE and scan_type in ['service', 'os']:
                result = self.nmap_scan_host(ip, ports, scan_type)
            else:
                # Use socket scanning for all other cases
                result = self.socket_scan_host(ip, ports)
        except Exception as e:
            print(f"    [ERROR] Scan failed: {e}")
            # Return basic result even on error
            pass
        
        return result

    def nmap_scan_host(self, ip, ports, scan_type):
        """Use nmap for advanced scanning"""
        result = {
            'hostname': self.get_hostname(ip),
            'status': 'up',
            'ports': [],
            'os': 'Unknown'
        }
        
        try:
            nm = nmap.PortScanner()
            port_str = ','.join(map(str, ports[:100]))  # Limit to 100 ports for speed
            
            # Different arguments based on scan type
            if scan_type == 'os':
                args = '-sV -O -T4'  # OS detection
            else:
                args = '-sV -T4'  # Service version detection
            
            nm.scan(ip, port_str, arguments=args)
            
            if ip in nm.all_hosts():
                # OS detection
                if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
                    result['os'] = nm[ip]['osmatch'][0]['name']
                
                # Ports
                for proto in nm[ip].all_protocols():
                    for port in nm[ip][proto].keys():
                        info = nm[ip][proto][port]
                        if info['state'] == 'open':
                            result['ports'].append({
                                'port': port,
                                'name': self.common_ports.get(port, info.get('name', 'unknown')),
                                'state': 'open',
                                'service': info.get('name', 'unknown'),
                                'version': info.get('version', ''),
                                'product': info.get('product', '')
                            })
        except Exception as e:
            print(f"    [NMAP] Error: {e}, falling back to socket scan")
            return self.socket_scan_host(ip, ports)
        
        return result

    def socket_scan_host(self, ip, ports):
        """Socket-based port scan"""
        result = {
            'hostname': self.get_hostname(ip),
            'status': 'up',
            'ports': [],
            'os': 'Unknown'
        }
        
        open_ports = []
        
        # Scan with sockets - parallel
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.check_port, ip, port): port for port in ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result(timeout=2):
                        open_ports.append(port)
                except:
                    pass
        
        # Build port list
        for port in sorted(open_ports):
            service_info = self.detect_service(ip, port)
            result['ports'].append({
                'port': port,
                'name': self.common_ports.get(port, 'unknown'),
                'state': 'open',
                'service': service_info['service'],
                'version': service_info['version'],
                'product': service_info['product']
            })
        
        # OS detection from ports
        if open_ports:
            result['os'] = self.detect_os_from_ports(open_ports)
        
        return result

    def check_port(self, ip, port, timeout=1):
        """Check single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def detect_service(self, host, port):
        """Detect service running on port"""
        info = {
            'service': self.common_ports.get(port, 'unknown'),
            'version': '',
            'product': ''
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            # Try to grab banner
            if port in [80, 8080, 8000, 5000]:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if 'Apache' in banner:
                    info['product'] = 'Apache'
                    match = re.search(r'Apache/([\d.]+)', banner)
                    if match:
                        info['version'] = match.group(1)
                elif 'nginx' in banner:
                    info['product'] = 'nginx'
                    match = re.search(r'nginx/([\d.]+)', banner)
                    if match:
                        info['version'] = match.group(1)
            elif port == 22:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'SSH' in banner:
                    info['product'] = 'OpenSSH'
                    match = re.search(r'OpenSSH_([\d.]+)', banner)
                    if match:
                        info['version'] = match.group(1)
            
            sock.close()
        except:
            pass
        
        return info

    def detect_os_from_ports(self, ports):
        """Detect OS from port patterns"""
        if 3389 in ports:
            return 'Windows (RDP detected)'
        elif 445 in ports and 139 in ports:
            return 'Windows (SMB detected)'
        elif 22 in ports and 80 in ports:
            return 'Linux/Unix (SSH+HTTP)'
        elif 22 in ports:
            return 'Linux/Unix'
        elif 548 in ports:
            return 'macOS'
        return 'Unknown'

    def get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip

    # OS Detection Methods
    def detect_os_nmap(self, host):
        """Detect OS using nmap"""
        if not NMAP_AVAILABLE:
            return "Unknown (nmap not available)"
        
        try:
            nm = nmap.PortScanner()
            nm.scan(host, arguments='-O')
            
            if host in nm.all_hosts():
                if 'osmatch' in nm[host]:
                    if nm[host]['osmatch']:
                        return nm[host]['osmatch'][0]['name']
            
            return "Unknown"
        except:
            return "Unknown"

    def detect_os_ttl(self, host):
        """Detect OS based on TTL values"""
        try:
            if platform.system() == 'Windows':
                output = subprocess.check_output(['ping', '-n', '1', host], 
                                               text=True, timeout=5)
                ttl_match = re.search(r'TTL=(\d+)', output)
            else:
                output = subprocess.check_output(['ping', '-c', '1', host], 
                                               text=True, timeout=5)
                ttl_match = re.search(r'ttl=(\d+)', output)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Network Device"
            
            return "Unknown"
        except:
            return "Unknown"

    # Host Discovery Methods
    def arp_discover_scapy(self, target_cidr):
        """ARP discovery using scapy"""
        if not SCAPY_AVAILABLE:
            return []
        
        devices = []
        try:
            arp = ARP(pdst=target_cidr)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'method': 'ARP-Scapy'
                })
        except Exception as e:
            print(f"ARP Scapy error: {e}")
        
        return devices

    def arp_discover_system(self, target_cidr):
        """ARP discovery using system ARP table"""
        devices = []
        try:
            # First ping broadcast to populate ARP table
            network = ipaddress.ip_network(target_cidr, strict=False)
            broadcast = str(network.broadcast_address)
            
            if platform.system() == 'Windows':
                subprocess.run(['ping', '-n', '2', broadcast], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                output = subprocess.check_output(['arp', '-a'], text=True, timeout=10)
                
                for line in output.split('\n'):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-:]+)\s+dynamic', line)
                    if match:
                        ip, mac = match.groups()
                        if ipaddress.ip_address(ip) in network:
                            devices.append({
                                'ip': ip,
                                'mac': mac,
                                'method': 'ARP-System'
                            })
            else:
                subprocess.run(['ping', '-c', '2', '-b', broadcast], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                output = subprocess.check_output(['arp', '-n'], text=True, timeout=10)
                
                for line in output.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip_match = re.match(r'\d+\.\d+\.\d+\.\d+', parts[0])
                        if ip_match and parts[2] != '(incomplete)':
                            ip = parts[0]
                            if ipaddress.ip_address(ip) in network:
                                devices.append({
                                    'ip': ip,
                                    'mac': parts[2],
                                    'method': 'ARP-System'
                                })
        except Exception as e:
            print(f"ARP System error: {e}")
        
        return devices

    def arp_discover_all(self, target_cidr):
        """Combined ARP discovery"""
        all_devices = {}
        
        # Try scapy method
        scapy_devices = self.arp_discover_scapy(target_cidr)
        for device in scapy_devices:
            all_devices[device['ip']] = device['mac']
        
        # Try system method (don't return early - always try both)
        system_devices = self.arp_discover_system(target_cidr)
        for device in system_devices:
            if device['ip'] not in all_devices:  # Add only new devices
                all_devices[device['ip']] = device['mac']
        
        return all_devices

    def nmap_discover(self, target_cidr):
        """Host discovery using nmap"""
        if not NMAP_AVAILABLE:
            return {}
        
        devices = {}
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target_cidr, arguments='-sn')
            
            for host in nm.all_hosts():
                mac = nm[host]['addresses'].get('mac', 'Unknown')
                devices[host] = mac
        except Exception as e:
            print(f"Nmap discover error: {e}")
        
        return devices

    def ping_sweep(self, target_cidr):
        """Ping sweep discovery"""
        devices = {}
        try:
            network = ipaddress.ip_network(target_cidr, strict=False)
            
            def ping_host(ip):
                try:
                    if platform.system() == 'Windows':
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                              stdout=subprocess.DEVNULL, 
                                              stderr=subprocess.DEVNULL, timeout=2)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                              stdout=subprocess.DEVNULL, 
                                              stderr=subprocess.DEVNULL, timeout=2)
                    
                    if result.returncode == 0:
                        return str(ip)
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        devices[result] = 'Unknown'
        
        except Exception as e:
            print(f"Ping sweep error: {e}")
        
        return devices

    # Service Detection
    def detect_service_banner(self, host, port, timeout=2):
        """Detect service by banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send appropriate request based on port
            if port in [80, 8080, 8000, 5000, 9090]:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 443:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 25:
                sock.send(b'EHLO test\r\n')
            elif port == 21:
                pass  # FTP sends banner immediately
            elif port == 22:
                pass  # SSH sends banner immediately
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse banner for service info
            service_info = self.parse_banner(banner, port)
            return service_info
            
        except:
            return {
                'service': self.common_ports.get(port, 'unknown'),
                'version': '',
                'product': ''
            }

    def parse_banner(self, banner, port):
        """Parse service banner for detailed info"""
        info = {
            'service': self.common_ports.get(port, 'unknown'),
            'version': '',
            'product': ''
        }
        
        banner_lower = banner.lower()
        
        # HTTP servers
        if 'apache' in banner_lower:
            info['product'] = 'Apache'
            match = re.search(r'apache/([\d.]+)', banner_lower)
            if match:
                info['version'] = match.group(1)
        elif 'nginx' in banner_lower:
            info['product'] = 'nginx'
            match = re.search(r'nginx/([\d.]+)', banner_lower)
            if match:
                info['version'] = match.group(1)
        elif 'iis' in banner_lower:
            info['product'] = 'Microsoft IIS'
            match = re.search(r'iis/([\d.]+)', banner_lower)
            if match:
                info['version'] = match.group(1)
        
        # SSH
        elif 'ssh' in banner_lower:
            info['service'] = 'SSH'
            if 'openssh' in banner_lower:
                info['product'] = 'OpenSSH'
                match = re.search(r'openssh_([\d.]+)', banner_lower)
                if match:
                    info['version'] = match.group(1)
        
        # FTP
        elif 'ftp' in banner_lower:
            info['service'] = 'FTP'
            if 'vsftpd' in banner_lower:
                info['product'] = 'vsftpd'
            elif 'filezilla' in banner_lower:
                info['product'] = 'FileZilla'
        
        return info

    # Report Generation
    def generate_pdf_report(self, results, sections):
        """Generate PDF report"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Title
        elements.append(Paragraph("Network Scan Report", styles['Title']))
        elements.append(Spacer(1, 20))
        
        # Summary
        total_hosts = len(results)
        total_open_ports = sum(len(data.get('ports', [])) for data in results.values())
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Hosts Scanned', str(total_hosts)],
            ['Total Open Ports', str(total_open_ports)],
            ['Scan Date', time.strftime('%Y-%m-%d %H:%M:%S')]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 30))

        # Host details
        for host, data in results.items():
            # Host header
            elements.append(Paragraph(f"Host: {host}", styles['Heading2']))
            elements.append(Paragraph(f"Hostname: {data.get('hostname', 'N/A')}", styles['Normal']))
            elements.append(Paragraph(f"MAC Address: {data.get('mac', 'Unknown')}", styles['Normal']))
            elements.append(Paragraph(f"Operating System: {data.get('os', 'Unknown')}", styles['Normal']))
            elements.append(Paragraph(f"Open Ports: {len(data.get('ports', []))}", styles['Normal']))
            elements.append(Spacer(1, 10))

            # Ports table
            if data.get('ports'):
                port_data = [['Port', 'Service', 'Product', 'Version']]
                for port in data['ports']:
                    port_data.append([
                        str(port['port']),
                        port.get('service', 'unknown'),
                        port.get('product', 'N/A'),
                        port.get('version', 'N/A')
                    ])

                port_table = Table(port_data)
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(port_table)
            else:
                elements.append(Paragraph("No open ports found.", styles['Normal']))

            elements.append(Spacer(1, 20))

        doc.build(elements)
        buffer.seek(0)
        return buffer

    def generate_csv_report(self, results):
        """Generate CSV report"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Header
        writer.writerow(['IP Address', 'Hostname', 'MAC Address', 'Operating System', 
                        'Port', 'Service', 'Product', 'Version', 'Status'])

        for host, data in results.items():
            if data.get('ports'):
                for port in data['ports']:
                    writer.writerow([
                        host,
                        data.get('hostname', 'N/A'),
                        data.get('mac', 'Unknown'),
                        data.get('os', 'Unknown'),
                        port['port'],
                        port.get('service', 'unknown'),
                        port.get('product', 'N/A'),
                        port.get('version', 'N/A'),
                        port.get('state', 'open')
                    ])
            else:
                # Host with no open ports
                writer.writerow([
                    host,
                    data.get('hostname', 'N/A'),
                    data.get('mac', 'Unknown'),
                    data.get('os', 'Unknown'),
                    'None',
                    'N/A',
                    'N/A',
                    'N/A',
                    'No open ports'
                ])

        buffer.seek(0)
        return io.BytesIO(buffer.getvalue().encode('utf-8'))

    def generate_json_report(self, results):
        """Generate JSON report"""
        report = {
            'scan_info': {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_hosts': len(results),
                'total_open_ports': sum(len(data.get('ports', [])) for data in results.values())
            },
            'hosts': results
        }
        
        import json
        return io.BytesIO(json.dumps(report, indent=2).encode('utf-8'))

    def generate_xml_report(self, results):
        """Generate XML report"""
        root = ET.Element('netscan')
        
        # Scan info
        info = ET.SubElement(root, 'scaninfo')
        ET.SubElement(info, 'timestamp').text = time.strftime('%Y-%m-%d %H:%M:%S')
        ET.SubElement(info, 'total_hosts').text = str(len(results))
        ET.SubElement(info, 'total_open_ports').text = str(
            sum(len(data.get('ports', [])) for data in results.values())
        )
        
        # Hosts
        for host_ip, data in results.items():
            host_elem = ET.SubElement(root, 'host', ip=host_ip)
            ET.SubElement(host_elem, 'hostname').text = data.get('hostname', 'N/A')
            ET.SubElement(host_elem, 'mac').text = data.get('mac', 'Unknown')
            ET.SubElement(host_elem, 'os').text = data.get('os', 'Unknown')
            ET.SubElement(host_elem, 'status').text = data.get('status', 'up')
            
            ports_elem = ET.SubElement(host_elem, 'ports')
            for port in data.get('ports', []):
                port_elem = ET.SubElement(ports_elem, 'port', number=str(port['port']))
                ET.SubElement(port_elem, 'service').text = port.get('service', 'unknown')
                ET.SubElement(port_elem, 'product').text = port.get('product', 'N/A')
                ET.SubElement(port_elem, 'version').text = port.get('version', 'N/A')
                ET.SubElement(port_elem, 'state').text = port.get('state', 'open')

        return io.BytesIO(ET.tostring(root, encoding='utf-8'))
