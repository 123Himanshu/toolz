"""
Nessus XML parser (supports .nessus format)
"""
import xmltodict
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime

class NessusParser(BaseParser):
    """Parser for Nessus XML output"""
    
    def __init__(self):
        super().__init__("Nessus")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Nessus XML output"""
        if not self.validate_file(file_path):
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = xmltodict.parse(f.read())
            
            vulnerabilities = []
            
            # Nessus report structure
            nessus_client_data = data.get('NessusClientData_v2', {})
            report = nessus_client_data.get('Report', {})
            report_hosts = report.get('ReportHost', [])
            
            # Handle single host case
            if isinstance(report_hosts, dict):
                report_hosts = [report_hosts]
            
            for report_host in report_hosts:
                vulns = self._parse_host(report_host)
                vulnerabilities.extend(vulns)
            
            self.logger.info(f"[Nessus] Parsed {len(vulnerabilities)} findings from {file_path}")
            return vulnerabilities
            
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_host(self, report_host: Dict[str, Any]) -> List[NormalizedVulnerability]:
        """Parse individual host"""
        vulnerabilities = []
        
        # Extract host info
        hostname = report_host.get('@name', '')
        
        # Get host properties
        host_properties = report_host.get('HostProperties', {}).get('tag', [])
        if isinstance(host_properties, dict):
            host_properties = [host_properties]
        
        ip_address = None
        os_info = None
        
        for prop in host_properties:
            prop_name = prop.get('@name', '')
            prop_value = prop.get('#text', '')
            
            if prop_name == 'host-ip':
                ip_address = prop_value
            elif prop_name == 'operating-system':
                os_info = prop_value
        
        asset_id = self.generate_asset_id(ip_address, hostname)
        
        # Parse report items (vulnerabilities)
        report_items = report_host.get('ReportItem', [])
        if isinstance(report_items, dict):
            report_items = [report_items]
        
        for item in report_items:
            vuln = self._parse_report_item(item, asset_id, ip_address, hostname, os_info)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_report_item(self, item: Dict[str, Any], asset_id: str,
                          ip_address: str, hostname: str, os_info: str) -> NormalizedVulnerability:
        """Parse individual vulnerability item"""
        
        # Basic info
        port = item.get('@port')
        protocol = item.get('@protocol', 'tcp')
        service_name = item.get('@svc_name', 'unknown')
        plugin_name = item.get('@pluginName', '')
        severity = item.get('@severity', '0')
        
        # Map Nessus severity (0-4) to standard severity
        severity_map = {
            '0': 'INFO',
            '1': 'LOW',
            '2': 'MEDIUM',
            '3': 'HIGH',
            '4': 'CRITICAL'
        }
        severity_str = severity_map.get(str(severity), 'INFO')
        
        # Extract detailed info
        cve = item.get('cve')
        cvss_base_score = item.get('cvss_base_score')
        cvss_vector = item.get('cvss_vector')
        exploit_available = item.get('exploit_available', 'false') == 'true'
        patch_publication_date = item.get('patch_publication_date')
        plugin_output = item.get('plugin_output', '')
        
        # CWE
        cwe = item.get('cwe')
        
        # Extract attack vector from CVSS vector
        attack_vector = None
        if cvss_vector:
            if 'AV:N' in cvss_vector:
                attack_vector = 'NETWORK'
            elif 'AV:A' in cvss_vector:
                attack_vector = 'ADJACENT'
            elif 'AV:L' in cvss_vector:
                attack_vector = 'LOCAL'
        
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            port=int(port) if port and str(port).isdigit() else None,
            protocol=protocol,
            service_name=service_name,
            os=os_info,
            cve_id=cve,
            cvss_score=float(cvss_base_score) if cvss_base_score else None,
            severity=severity_str,
            cwe=cwe,
            exploit_available=exploit_available,
            attack_vector=attack_vector,
            patch_available=bool(patch_publication_date),
            misconfiguration=plugin_name if not cve else None,
            scanner_source="Nessus",
            timestamp=datetime.now(),
            raw_data=item
        )
        
        return vuln
