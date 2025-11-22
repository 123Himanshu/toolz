"""
Masscan Wrapper - High-Speed IP Range Scanner
ONLY for large-scale port discovery on IP ranges /
"""
import subprocess
import json
import re
from typing import Dict, List, Any

class MasscanWrapper:
    """Wrapper for Masscan - Internet-scale port scanning"""
    
    def __init__(self):
        self.tool_name = "masscan"
    
    def scan(self, ip_range: str, ports: str = "1-1000", rate: int = 10000, 
             max_rate: int = None, exclude_ports: str = None) -> Dict[str, Any]:
        """
        Masscan IP range scan - ONLY for port discovery
        
        Args:
            ip_range: IP range (e.g., "192.168.1.0/24", "10.0.0.0/16")
            ports: Port range (e.g., "80,443", "1-1000", "1-65535")
            rate: Packets per second (default: 10000)
            max_rate: Maximum rate limit (optional)
            exclude_ports: Ports to exclude (optional)
        
        Returns:
            Dict with discovered IPs and their open ports
        """
        
        # Build masscan command
        cmd = [
            'masscan',
            ip_range,
            '-p', ports,
            '--rate', str(rate),
            '-oJ', '-',  # Output JSON to stdout
            '--open-only'  # Only show open ports
        ]
        
        if max_rate:
            cmd.extend(['--max-rate', str(max_rate)])
        
        if exclude_ports:
            cmd.extend(['--exclude-ports', exclude_ports])
        
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
                'ip_range': ip_range,
                'ports_scanned': ports,
                'rate': rate,
                'discovered': discovered,
                'total_ips': len(discovered),
                'total_ports': sum(len(d['open_ports']) for d in discovered),
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
