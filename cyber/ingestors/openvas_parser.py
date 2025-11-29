"""
OpenVAS XML parser
"""
import xmltodict
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime
import re

class OpenVASParser(BaseParser):
    """Parser for OpenVAS XML output"""
    
    def __init__(self):
        super().__init__("OpenVAS")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse OpenVAS XML output"""
        if not self.validate_file(file_path):
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = xmltodict.parse(f.read())
            
            vulnerabilities = []
            
            # OpenVAS report structure
            report = data.get('report', {})
            results = report.get('results', {}).get('result', [])
            
            # Handle single result case
            if isinstance(results, dict):
                results = [results]
            
            for result in results:
                vuln = self._parse_result(result)
                if vuln:
                    vulnerabilities.append(vuln)
            
            self.logger.info(f"[OpenVAS] Parsed {len(vulnerabilities)} findings from {file_path}")
            return vulnerabilities
            
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_result(self, result: Dict[str, Any]) -> NormalizedVulnerability:
        """Parse individual result"""
        
        # Extract host info
        host = result.get('host', {})
        if isinstance(host, str):
            ip_address = host
            hostname = None
        else:
            ip_address = host.get('#text', host.get('ip', ''))
            hostname = host.get('hostname')
        
        asset_id = self.generate_asset_id(ip_address, hostname)
        
        # Extract port info
        port_info = result.get('port', '')
        port = None
        protocol = 'tcp'
        service_name = 'unknown'
        
        if port_info:
            # Format: "22/tcp" or "general/tcp"
            port_match = re.match(r'(\d+|general)/(\w+)', port_info)
            if port_match:
                port_str = port_match.group(1)
                protocol = port_match.group(2)
                if port_str.isdigit():
                    port = int(port_str)
        
        # Extract vulnerability details
        nvt = result.get('nvt', {})
        name = nvt.get('name', '')
        cvss_base = nvt.get('cvss_base')
        cve = nvt.get('cve', '')
        
        # Extract CVE from refs if not in cve field
        if not cve or cve == 'NOCVE':
            refs = nvt.get('refs', {}).get('ref', [])
            if isinstance(refs, dict):
                refs = [refs]
            for ref in refs:
                ref_id = ref.get('@id', '')
                if ref_id.startswith('CVE-'):
                    cve = ref_id
                    break
        
        # Severity
        threat = result.get('threat', 'Log')
        severity_map = {
            'High': 'HIGH',
            'Medium': 'MEDIUM',
            'Low': 'LOW',
            'Log': 'INFO'
        }
        severity = severity_map.get(threat, 'INFO')
        
        # Description
        description = result.get('description', '')
        
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            protocol=protocol,
            service_name=service_name,
            cve_id=cve if cve and cve != 'NOCVE' else None,
            cvss_score=float(cvss_base) if cvss_base else None,
            severity=severity,
            misconfiguration=name,
            scanner_source="OpenVAS",
            timestamp=datetime.now(),
            raw_data=result
        )
        
        return vuln
