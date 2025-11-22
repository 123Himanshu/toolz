"""
Naabu Wrapper - Web-Focused Domain Port Scanner
ONLY for domain-based web reconnaissance, NOT for IP sweeps
"""
import subprocess
import json
import re
from typing import Dict, List, Any

class NaabuWrapper:
    """
    Wrapper for Naabu - Domain/Subdomain Web Port Scanner
    
    Purpose: Clean domain → port detection for web security workflows
    Focus: HTTP/HTTPS ports, subdomain enumeration, web services
    NOT for: IP range scanning, detailed service detection
    """
    
    def __init__(self):
        self.tool_name = "naabu"
        # Common web ports (default focus)
        self.web_ports = "80,81,443,8000,8008,8080,8443,8888,9000,9090"
    
    def scan_domain(self, domain: str, ports: str = None, top_ports: int = None,
                    exclude_ports: str = None, rate: int = 1000, 
                    timeout: int = 10, retries: int = 1) -> Dict[str, Any]:
        """
        Scan domain for open ports - Web-focused
        
        Args:
            domain: Domain name (e.g., "example.com", "sub.example.com")
            ports: Specific ports (e.g., "80,443,8080") - defaults to web ports
            top_ports: Scan top N ports (e.g., 100, 1000)
            exclude_ports: Ports to exclude
            rate: Packets per second (default: 1000)
            timeout: Timeout in seconds (default: 10)
            retries: Number of retries (default: 1)
        
        Returns:
            Dict with domain, open ports, and source
        """
        
        # Validate domain
        if not self._is_valid_domain(domain):
            return {
                'success': False,
                'error': 'Invalid domain format. Use domain names, not IP addresses.',
                'domain': domain
            }
        
        # Build naabu command
        cmd = [
            'naabu',
            '-host', domain,
            '-json',  # JSON output
            '-silent',  # Clean output
            '-rate', str(rate),
            '-timeout', str(timeout),
            '-retries', str(retries)
        ]
        
        # Port selection (prioritize web ports if nothing specified)
        if ports:
            cmd.extend(['-p', ports])
        elif top_ports:
            cmd.extend(['-top-ports', str(top_ports)])
        else:
            # Default: web ports only
            cmd.extend(['-p', self.web_ports])
        
        if exclude_ports:
            cmd.extend(['-exclude-ports', exclude_ports])
        
        try:
            # Run naabu
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            if result.returncode != 0 and not result.stdout:
                return {
                    'success': False,
                    'error': result.stderr or 'Naabu scan failed',
                    'command': ' '.join(cmd),
                    'domain': domain
                }
            
            # Parse naabu JSON output
            open_ports = self._parse_naabu_output(result.stdout)
            
            return {
                'success': True,
                'tool': 'naabu',
                'domain': domain,
                'ports_scanned': ports or top_ports or 'web-ports',
                'open_ports': open_ports,
                'total_ports': len(open_ports),
                'rate': rate,
                'source': 'naabu',
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Naabu timeout (>2 minutes)',
                'command': ' '.join(cmd),
                'domain': domain
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': ' '.join(cmd),
                'domain': domain
            }
    
    def scan_subdomains(self, domains: List[str], ports: str = None,
                       rate: int = 1000) -> Dict[str, Any]:
        """
        Scan multiple subdomains for open ports
        Perfect for subdomain enumeration workflows
        
        Args:
            domains: List of domain/subdomain names
            ports: Ports to scan (defaults to web ports)
            rate: Scan rate
        
        Returns:
            Dict with results for all domains
        """
        
        results = []
        
        for domain in domains:
            result = self.scan_domain(
                domain=domain,
                ports=ports,
                rate=rate
            )
            results.append(result)
        
        # Aggregate results
        successful = [r for r in results if r.get('success')]
        failed = [r for r in results if not r.get('success')]
        
        total_ports = sum(r.get('total_ports', 0) for r in successful)
        
        return {
            'success': len(successful) > 0,
            'tool': 'naabu',
            'scan_type': 'subdomain_scan',
            'total_domains': len(domains),
            'successful_scans': len(successful),
            'failed_scans': len(failed),
            'total_ports_found': total_ports,
            'results': results,
            'source': 'naabu'
        }
    
    def _parse_naabu_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse naabu JSON output"""
        ports = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # Naabu JSON format: {"host":"example.com","port":80,"protocol":"tcp"}
                if 'port' in data:
                    port_info = {
                        'port': data['port'],
                        'protocol': data.get('protocol', 'tcp'),
                        'host': data.get('host', '')
                    }
                    
                    # Identify if it's a web port
                    if self._is_web_port(data['port']):
                        port_info['service_type'] = 'web'
                    
                    ports.append(port_info)
            
            except json.JSONDecodeError:
                continue
        
        # Sort by port number
        ports.sort(key=lambda x: x['port'])
        
        return ports
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format (not IP address)"""
        # Check if it's an IP address (reject)
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain):
            return False
        
        # Check domain format
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))
    
    def _is_web_port(self, port: int) -> bool:
        """Check if port is a common web port"""
        web_ports = [80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 3000, 5000]
        return port in web_ports
    
    def get_web_ports_preset(self) -> str:
        """Get default web ports string"""
        return self.web_ports
    
    def format_for_nmap(self, naabu_result: Dict[str, Any]) -> str:
        """
        Format Naabu results for Nmap follow-up scan
        
        Args:
            naabu_result: Result from scan_domain()
        
        Returns:
            Comma-separated port string for Nmap
        """
        if not naabu_result.get('success'):
            return ""
        
        ports = naabu_result.get('open_ports', [])
        port_numbers = [str(p['port']) for p in ports]
        
        return ','.join(port_numbers)
