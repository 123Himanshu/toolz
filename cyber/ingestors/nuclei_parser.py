"""
Nuclei JSON parser
"""
import json
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime
import re

class NucleiParser(BaseParser):
    """Parser for Nuclei JSON output"""
    
    def __init__(self):
        super().__init__("Nuclei")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Nuclei JSON output"""
        if not self.validate_file(file_path):
            return []
        
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Nuclei outputs line-delimited JSON
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        vuln = self._parse_record(data)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue
            
            self.logger.info(f"[Nuclei] Parsed {len(vulnerabilities)} findings from {file_path}")
            return vulnerabilities
            
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_record(self, data: Dict[str, Any]) -> NormalizedVulnerability:
        """Parse individual Nuclei finding"""
        
        # Extract basic info
        template_id = data.get('template-id', data.get('templateID', ''))
        info = data.get('info', {})
        severity = info.get('severity', 'info').upper()
        
        # Extract target info
        host = data.get('host', '')
        matched_at = data.get('matched-at', data.get('matched', host))
        
        # Parse URL to extract IP/hostname and port
        ip_address = None
        hostname = None
        port = None
        
        url_match = re.match(r'https?://([^:/]+)(?::(\d+))?', matched_at)
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
                port = 443 if matched_at.startswith('https://') else 80
        
        asset_id = self.generate_asset_id(ip_address, hostname)
        
        # Extract CVE if present
        cve_id = None
        cve_list = info.get('classification', {}).get('cve-id', [])
        if cve_list:
            cve_id = cve_list[0] if isinstance(cve_list, list) else cve_list
        
        # Extract CWE
        cwe = None
        cwe_list = info.get('classification', {}).get('cwe-id', [])
        if cwe_list:
            cwe = cwe_list[0] if isinstance(cwe_list, list) else cwe_list
        
        # CVSS score
        cvss_score = info.get('classification', {}).get('cvss-score')
        
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            protocol='tcp',
            service_name='http',
            cve_id=cve_id,
            cvss_score=float(cvss_score) if cvss_score else None,
            severity=severity,
            cwe=cwe,
            misconfiguration=template_id,
            scanner_source="Nuclei",
            timestamp=datetime.now(),
            raw_data=data
        )
        
        return vuln
    
    def _is_ip(self, value: str) -> bool:
        """Check if string is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))
