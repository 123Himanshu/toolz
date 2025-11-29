"""
Nikto TXT/JSON parser
"""
import json
import re
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime

class NiktoParser(BaseParser):
    """Parser for Nikto text and JSON output"""
    
    def __init__(self):
        super().__init__("Nikto")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Nikto output (JSON or text)"""
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
        
        # Nikto JSON structure
        hosts = data.get('hosts', [])
        if not hosts and 'host' in data:
            hosts = [data]
        
        for host_data in hosts:
            host = host_data.get('host', host_data.get('ip', ''))
            port = host_data.get('port', 80)
            
            ip_address = host if self._is_ip(host) else None
            hostname = host if not self._is_ip(host) else None
            asset_id = self.generate_asset_id(ip_address, hostname)
            
            vulnerabilities_list = host_data.get('vulnerabilities', [])
            
            for vuln_data in vulnerabilities_list:
                vuln = self._parse_vulnerability(vuln_data, asset_id, 
                                                ip_address, hostname, port)
                if vuln:
                    vulnerabilities.append(vuln)
        
        self.logger.info(f"[Nikto] Parsed {len(vulnerabilities)} findings (JSON)")
        return vulnerabilities
    
    def _parse_text(self, content: str) -> List[NormalizedVulnerability]:
        """Parse text format"""
        vulnerabilities = []
        
        lines = content.split('\n')
        current_host = None
        current_port = 80
        
        for line in lines:
            # Look for target line: "+ Target IP: 192.168.1.1"
            target_match = re.search(r'\+ Target (?:IP|Host):\s*([^\s]+)', line)
            if target_match:
                current_host = target_match.group(1)
                continue
            
            # Look for port: "+ Target Port: 443"
            port_match = re.search(r'\+ Target Port:\s*(\d+)', line)
            if port_match:
                current_port = int(port_match.group(1))
                continue
            
            # Look for findings (lines starting with +)
            if line.startswith('+') and current_host:
                # Skip header lines
                if 'Target IP' in line or 'Target Port' in line or 'Start Time' in line:
                    continue
                
                ip_address = current_host if self._is_ip(current_host) else None
                hostname = current_host if not self._is_ip(current_host) else None
                asset_id = self.generate_asset_id(ip_address, hostname)
                
                # Extract OSVDB ID if present
                osvdb_match = re.search(r'OSVDB-(\d+)', line)
                
                vuln = NormalizedVulnerability(
                    asset_id=asset_id,
                    hostname=hostname,
                    ip_address=ip_address,
                    port=current_port,
                    protocol='tcp',
                    service_name='http',
                    severity='MEDIUM',
                    misconfiguration=line.strip(),
                    scanner_source="Nikto",
                    timestamp=datetime.now(),
                    raw_data={'line': line}
                )
                vulnerabilities.append(vuln)
        
        self.logger.info(f"[Nikto] Parsed {len(vulnerabilities)} findings (text)")
        return vulnerabilities
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any], asset_id: str,
                            ip_address: str, hostname: str, port: int) -> NormalizedVulnerability:
        """Parse individual vulnerability from JSON"""
        
        msg = vuln_data.get('msg', '')
        osvdb = vuln_data.get('OSVDB', '')
        method = vuln_data.get('method', 'GET')
        
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            protocol='tcp',
            service_name='http',
            severity='MEDIUM',
            misconfiguration=msg,
            scanner_source="Nikto",
            timestamp=datetime.now(),
            raw_data=vuln_data
        )
        
        return vuln
    
    def _is_ip(self, value: str) -> bool:
        """Check if string is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))
