"""
RustScan JSON/stdout parser
"""
import json
import re
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime

class RustScanParser(BaseParser):
    """Parser for RustScan JSON and stdout output"""
    
    def __init__(self):
        super().__init__("RustScan")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse RustScan output (JSON or text)"""
        if not self.validate_file(file_path):
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try JSON first
            try:
                data = json.loads(content)
                return self._parse_json(data)
            except json.JSONDecodeError:
                # Fall back to text parsing
                return self._parse_text(content)
                
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_json(self, data: Dict[str, Any]) -> List[NormalizedVulnerability]:
        """Parse JSON format"""
        vulnerabilities = []
        
        # RustScan JSON structure varies, handle common formats
        hosts = data.get('hosts', [])
        if not hosts and 'ip' in data:
            hosts = [data]
        
        for host in hosts:
            ip_address = host.get('ip', host.get('address', ''))
            ports = host.get('ports', [])
            
            asset_id = self.generate_asset_id(ip_address)
            
            for port_info in ports:
                if isinstance(port_info, dict):
                    port = port_info.get('port', port_info.get('id'))
                    protocol = port_info.get('protocol', 'tcp')
                else:
                    port = port_info
                    protocol = 'tcp'
                
                vuln = NormalizedVulnerability(
                    asset_id=asset_id,
                    ip_address=ip_address,
                    port=int(port) if port else None,
                    protocol=protocol,
                    service_name='unknown',
                    scanner_source="RustScan",
                    timestamp=datetime.now(),
                    raw_data={'host': host}
                )
                vulnerabilities.append(vuln)
        
        self.logger.info(f"[RustScan] Parsed {len(vulnerabilities)} findings (JSON)")
        return vulnerabilities
    
    def _parse_text(self, content: str) -> List[NormalizedVulnerability]:
        """Parse text/stdout format"""
        vulnerabilities = []
        
        # Extract IP and ports from text output
        # Common format: "Open 192.168.1.1:80"
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        port_pattern = r':(\d+)'
        
        lines = content.split('\n')
        current_ip = None
        
        for line in lines:
            # Look for IP addresses
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                current_ip = ip_match.group(1)
            
            # Look for ports
            port_matches = re.findall(port_pattern, line)
            if port_matches and current_ip:
                asset_id = self.generate_asset_id(current_ip)
                
                for port in port_matches:
                    vuln = NormalizedVulnerability(
                        asset_id=asset_id,
                        ip_address=current_ip,
                        port=int(port),
                        protocol='tcp',
                        service_name='unknown',
                        scanner_source="RustScan",
                        timestamp=datetime.now(),
                        raw_data={'line': line}
                    )
                    vulnerabilities.append(vuln)
        
        self.logger.info(f"[RustScan] Parsed {len(vulnerabilities)} findings (text)")
        return vulnerabilities
