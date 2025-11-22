"""
ZMap Wrapper - Internet-Scale Single-Port Scanner
ONLY for internet-wide single-port scanning
"""
import subprocess
import re
from typing import Dict, List, Any, Optional

class ZMapWrapper:
    """
    Wrapper for ZMap - Internet-scale single-port scanner
    
    Purpose: Fast discovery of IPs with specific port open
    Focus: Single port, massive IP ranges, internet research
    NOT for: Multi-port scanning, detailed service detection
    """
    
    def __init__(self):
        self.tool_name = "zmap"
    
    def scan_single_port(self, port: int, target_range: str = "0.0.0.0/0",
                        bandwidth: str = "10M", max_targets: int = None,
                        output_fields: str = "saddr,sport") -> Dict[str, Any]:
        """
        ZMap single-port scan - Internet-scale port discovery
        
        Args:
            port: Single port to scan (e.g., 443, 22, 80)
            target_range: IP range in CIDR (default: "0.0.0.0/0" = entire internet)
            bandwidth: Scan bandwidth (e.g., "10M", "100M", "1G")
            max_targets: Maximum number of IPs to scan (optional limit)
            output_fields: Fields to output (default: "saddr,sport")
        
        Returns:
            Dict with discovered IPs and statistics
        """
        
        # Validate single port
        if not isinstance(port, int) or port < 1 or port > 65535:
            return {
                'success': False,
                'error': 'Invalid port. ZMap requires a single port number (1-65535).',
                'port': port
            }
        
        # Build zmap command
        cmd = [
            'zmap',
            '-p', str(port),
            '-B', bandwidth,
            '-o', '-',  # Output to stdout
            '--output-fields', output_fields
        ]
        
        if max_targets:
            cmd.extend(['-n', str(max_targets)])
        
        # Add target range
        cmd.append(target_range)
        
        try:
            # Run zmap
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr or 'ZMap scan failed',
                    'command': ' '.join(cmd),
                    'port': port
                }
            
            # Parse zmap output
            discovered_ips = self._parse_zmap_output(result.stdout)
            statistics = self._parse_statistics(result.stderr)
            
            return {
                'success': True,
                'tool': 'zmap',
                'port': port,
                'target_range': target_range,
                'bandwidth': bandwidth,
                'discovered_ips': discovered_ips,
                'total_discovered': len(discovered_ips),
                'statistics': statistics,
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'ZMap timeout (>10 minutes)',
                'command': ' '.join(cmd),
                'port': port
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': ' '.join(cmd),
                'port': port
            }
    
    def _parse_zmap_output(self, output: str) -> List[str]:
        """Parse ZMap output to extract IP addresses"""
        ips = []
        
        for line in output.strip().split('\n'):
            if not line or line.startswith('#'):
                continue
            
            # Extract IP address (first field)
            parts = line.split(',')
            if parts:
                ip = parts[0].strip()
                # Validate IP format
                if self._is_valid_ip(ip):
                    ips.append(ip)
        
        return ips
    
    def _parse_statistics(self, stderr: str) -> Dict[str, Any]:
        """Parse ZMap statistics from stderr"""
        stats = {}
        
        # Extract key statistics
        patterns = {
            'sent': r'sent:\s*(\d+)',
            'received': r'received:\s*(\d+)',
            'success_rate': r'success_rate:\s*([\d.]+)',
            'hitrate': r'hitrate:\s*([\d.]+)',
            'duration': r'duration:\s*([\d.]+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, stderr)
            if match:
                stats[key] = match.group(1)
        
        return stats
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        # Check each octet is 0-255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    def scan_common_ports(self, ports: List[int], target_range: str = "0.0.0.0/0",
                         bandwidth: str = "10M", max_targets: int = None) -> Dict[str, Any]:
        """
        Scan multiple ports sequentially (NOT recommended for ZMap)
        
        Note: ZMap is optimized for single-port scans. For multi-port,
        use Masscan instead.
        
        Args:
            ports: List of ports to scan
            target_range: IP range
            bandwidth: Scan bandwidth
            max_targets: Maximum IPs per port
        
        Returns:
            Dict with results for each port
        """
        results = []
        
        for port in ports:
            result = self.scan_single_port(
                port=port,
                target_range=target_range,
                bandwidth=bandwidth,
                max_targets=max_targets
            )
            results.append(result)
        
        # Aggregate results
        total_discovered = sum(r.get('total_discovered', 0) for r in results if r.get('success'))
        
        return {
            'success': any(r.get('success') for r in results),
            'tool': 'zmap',
            'scan_type': 'multi_port_sequential',
            'ports': ports,
            'target_range': target_range,
            'total_discovered': total_discovered,
            'results': results,
            'warning': 'ZMap is optimized for single-port scans. Consider using Masscan for multi-port.'
        }
    
    def get_recommended_bandwidth(self, network_type: str = "home") -> str:
        """
        Get recommended bandwidth based on network type
        
        Args:
            network_type: 'home', 'datacenter', 'research'
        
        Returns:
            Bandwidth string (e.g., "10M", "100M", "1G")
        """
        recommendations = {
            'home': '10M',      # Home internet
            'datacenter': '100M',  # Datacenter
            'research': '1G'    # Research network
        }
        
        return recommendations.get(network_type, '10M')
    
    def validate_target_range(self, target_range: str) -> bool:
        """Validate CIDR notation"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        return bool(re.match(pattern, target_range))
