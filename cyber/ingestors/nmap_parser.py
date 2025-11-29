"""
Nmap XML parser
"""
import xmltodict
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime

class NmapParser(BaseParser):
    """Parser for Nmap XML output"""
    
    def __init__(self):
        super().__init__("Nmap")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Nmap XML output"""
        if not self.validate_file(file_path):
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = xmltodict.parse(f.read())
            
            vulnerabilities = []
            nmaprun = data.get('nmaprun', {})
            hosts = nmaprun.get('host', [])
            
            # Handle single host case
            if isinstance(hosts, dict):
                hosts = [hosts]
            
            for host in hosts:
                vulns = self._parse_host(host)
                vulnerabilities.extend(vulns)
            
            self.logger.info(f"[Nmap] Parsed {len(vulnerabilities)} findings from {file_path}")
            return vulnerabilities
            
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_host(self, host: Dict[str, Any]) -> List[NormalizedVulnerability]:
        """Parse individual host data"""
        vulnerabilities = []
        
        # Extract host info
        address = host.get('address', {})
        if isinstance(address, list):
            address = address[0]
        
        ip_address = address.get('@addr', '')
        hostname = None
        
        hostnames = host.get('hostnames', {}).get('hostname', [])
        if hostnames:
            if isinstance(hostnames, dict):
                hostname = hostnames.get('@name')
            elif isinstance(hostnames, list):
                hostname = hostnames[0].get('@name')
        
        asset_id = self.generate_asset_id(ip_address, hostname)
        
        # Extract OS info
        os_info = None
        osmatch = host.get('os', {}).get('osmatch', {})
        if osmatch:
            if isinstance(osmatch, list):
                osmatch = osmatch[0]
            os_info = osmatch.get('@name')
        
        # Parse ports
        ports = host.get('ports', {}).get('port', [])
        if isinstance(ports, dict):
            ports = [ports]
        
        for port in ports:
            vuln = self._parse_port(port, asset_id, ip_address, hostname, os_info)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_port(self, port: Dict[str, Any], asset_id: str, ip_address: str, 
                    hostname: str, os_info: str) -> NormalizedVulnerability:
        """Parse port information"""
        
        port_id = port.get('@portid')
        protocol = port.get('@protocol', 'tcp')
        
        service = port.get('service', {})
        service_name = service.get('@name', 'unknown')
        service_version = service.get('@version', '')
        service_product = service.get('@product', '')
        
        # Build version string
        version_str = f"{service_product} {service_version}".strip() if service_product else service_version
        
        # Extract CPE for tech stack
        tech_stack = []
        cpe = service.get('cpe', [])
        if isinstance(cpe, str):
            tech_stack.append(cpe)
        elif isinstance(cpe, list):
            tech_stack.extend(cpe)
        
        # Check for vulnerabilities in scripts
        scripts = port.get('script', [])
        if isinstance(scripts, dict):
            scripts = [scripts]
        
        cve_list = []
        for script in scripts:
            script_id = script.get('@id', '')
            if 'vuln' in script_id or 'cve' in script_id:
                output = script.get('@output', '')
                # Extract CVEs from output
                import re
                cves = re.findall(r'CVE-\d{4}-\d+', output)
                cve_list.extend(cves)
        
        # Create vulnerability record
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            port=int(port_id) if port_id else None,
            protocol=protocol,
            service_name=service_name,
            service_version=version_str,
            tech_stack=tech_stack,
            os=os_info,
            cve_id=cve_list[0] if cve_list else None,
            scanner_source="Nmap",
            timestamp=datetime.now(),
            raw_data={'port': port}
        )
        
        return vuln
