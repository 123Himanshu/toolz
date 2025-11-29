"""
Wapiti JSON parser
"""
import json
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime
import re

class WapitiParser(BaseParser):
    """Parser for Wapiti JSON output"""
    
    def __init__(self):
        super().__init__("Wapiti")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Wapiti JSON output"""
        if not self.validate_file(file_path):
            return []
        
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract target info
            target = data.get('target', {})
            target_url = target.get('url', '')
            
            # Parse URL
            ip_address, hostname, port = self._parse_url(target_url)
            asset_id = self.generate_asset_id(ip_address, hostname)
            
            # Parse vulnerabilities
            vulnerabilities_data = data.get('vulnerabilities', {})
            
            for vuln_type, findings in vulnerabilities_data.items():
                for finding in findings:
                    vuln = self._parse_finding(finding, vuln_type, asset_id, 
                                               ip_address, hostname, port)
                    if vuln:
                        vulnerabilities.append(vuln)
            
            self.logger.info(f"[Wapiti] Parsed {len(vulnerabilities)} findings from {file_path}")
            return vulnerabilities
            
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_finding(self, finding: Dict[str, Any], vuln_type: str,
                      asset_id: str, ip_address: str, hostname: str, 
                      port: int) -> NormalizedVulnerability:
        """Parse individual vulnerability finding"""
        
        # Extract details
        method = finding.get('method', 'GET')
        path = finding.get('path', '')
        level = finding.get('level', 1)
        
        # Map Wapiti level to severity
        severity_map = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW'}
        severity = severity_map.get(level, 'INFO')
        
        # Extract CWE if present
        cwe = None
        info = finding.get('info', '')
        cwe_match = re.search(r'CWE-(\d+)', info)
        if cwe_match:
            cwe = f"CWE-{cwe_match.group(1)}"
        
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            protocol='tcp',
            service_name='http',
            severity=severity,
            cwe=cwe,
            misconfiguration=vuln_type,
            scanner_source="Wapiti",
            timestamp=datetime.now(),
            raw_data=finding
        )
        
        return vuln
    
    def _parse_url(self, url: str):
        """Parse URL to extract IP/hostname and port"""
        ip_address = None
        hostname = None
        port = 80
        
        url_match = re.match(r'https?://([^:/]+)(?::(\d+))?', url)
        if url_match:
            host_part = url_match.group(1)
            port_part = url_match.group(2)
            
            if self._is_ip(host_part):
                ip_address = host_part
            else:
                hostname = host_part
            
            if port_part:
                port = int(port_part)
            else:
                port = 443 if url.startswith('https://') else 80
        
        return ip_address, hostname, port
    
    def _is_ip(self, value: str) -> bool:
        """Check if string is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))
