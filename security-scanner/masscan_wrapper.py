"""
Masscan Wrapper - High-Speed IP Range Scanner
ONLY for large-scale port discovery on IP ranges
"""
import subprocess
import json
import re
import sys
from typing import Dict, List, Any

class MasscanWrapper:
    """Wrapper for Masscan - Internet-scale port scanning"""
    
    def __init__(self):
        self.tool_name = "masscan"
    
    def scan(self, ip_range: str, ports: str = "80,443,22,21,25,3389,8080,8443") -> Dict[str, Any]:
        """
        Masscan LARGE IP RANGE scan ONLY
        
        PURPOSE: Internet-scale port discovery (10M packets/sec)
        USE WHEN: Scanning /16, /24 networks or 1000+ IPs
        AVOID: Single targets (use RustScan instead)
        
        Args:
            ip_range: IP range in CIDR (e.g., "192.168.1.0/24", "10.0.0.0/16")
            ports: Common ports only (default: web + SSH + RDP)
        
        Returns:
            Dict with discovered IPs and their open ports ONLY
        """
        # AUTO-CONVERT: Single IP to /32 CIDR
        if '/' not in ip_range:
            # Check if it's a valid IP
            import re
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_range):
                ip_range = f"{ip_range}/32"  # Single host
                print(f"[*] Auto-converted to CIDR: {ip_range}", file=sys.stderr)
            else:
                return {
                    'success': False,
                    'error': 'Masscan requires IP address or CIDR notation. Use RustScan for domains.',
                    'tool': 'masscan',
                    'role': 'scale'
                }
        
        # AUTO-CALCULATE rate based on range size
        cidr_size = int(ip_range.split('/')[-1])
        rate = self.get_recommended_rate(cidr_size)
        
        # Build masscan command - SCALE OPTIMIZED
        cmd = [
            'masscan',
            ip_range,
            '-p', ports,
            '--rate', str(rate),
            '-oJ', '-',  # Output JSON to stdout
            '--open-only',  # Only show open ports
            '--banners'  # Minimal banner grab for identification
        ]
        
        try:
            # Run masscan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large scans
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr or 'Masscan failed',
                    'command': ' '.join(cmd)
                }
            
            # Parse masscan JSON output
            discovered = self._parse_masscan_output(result.stdout)
            
            return {
                'success': True,
                'tool': 'masscan',
                'role': 'scale',
                'purpose': 'Large-scale IP range discovery',
                'ip_range': ip_range,
                'cidr_size': cidr_size,
                'ports_scanned': ports,
                'rate': rate,
                'discovered': discovered,
                'total_ips': len(discovered),
                'total_ports': sum(len(d['open_ports']) for d in discovered),
                'feed_to_nmap': True,  # Feed discovered IPs to Nmap
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Masscan timeout (>5 minutes)',
                'command': ' '.join(cmd)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': ' '.join(cmd)
            }
    
    def _parse_masscan_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse masscan JSON output"""
        discovered = {}
        
        # Masscan outputs one JSON object per line
        for line in output.strip().split('\n'):
            if not line or line.startswith('#'):
                continue
            
            try:
                data = json.loads(line.rstrip(','))
                
                # Extract IP and port
                if 'ip' in data and 'ports' in data:
                    ip = data['ip']
                    port_info = data['ports'][0]
                    port = port_info['port']
                    protocol = port_info.get('proto', 'tcp')
                    
                    # Group by IP
                    if ip not in discovered:
                        discovered[ip] = {
                            'ip': ip,
                            'open_ports': [],
                            'source': 'masscan'
                        }
                    
                    discovered[ip]['open_ports'].append({
                        'port': port,
                        'protocol': protocol
                    })
            
            except json.JSONDecodeError:
                continue
        
        # Convert to list and sort ports
        result = []
        for ip_data in discovered.values():
            ip_data['open_ports'] = sorted(
                ip_data['open_ports'], 
                key=lambda x: x['port']
            )
            result.append(ip_data)
        
        # Sort by IP
        result.sort(key=lambda x: x['ip'])
        
        return result
    
    def validate_ip_range(self, ip_range: str) -> bool:
        """Validate IP range format"""
        # Check CIDR notation
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        if re.match(cidr_pattern, ip_range):
            return True
        
        # Check IP range notation
        range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$'
        if re.match(range_pattern, ip_range):
            return True
        
        return False
    
    def get_recommended_rate(self, cidr_size: int) -> int:
        """Get recommended scan rate based on CIDR size"""
        if cidr_size >= 24:  # /24 or smaller (256 IPs)
            return 10000
        elif cidr_size >= 20:  # /20 to /23 (1K-4K IPs)
            return 50000
        elif cidr_size >= 16:  # /16 to /19 (4K-64K IPs)
            return 100000
        else:  # Larger than /16
            return 500000  # Up to 10M for huge ranges
