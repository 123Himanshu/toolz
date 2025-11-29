"""
Masscan XML/JSON parser
"""
import json
import xmltodict
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime

class MasscanParser(BaseParser):
    """Parser for Masscan XML and JSON output"""
    
    def __init__(self):
        super().__init__("Masscan")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Masscan output (XML or JSON)"""
        if not self.validate_file(file_path):
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Detect format
            if content.strip().startswith('{') or content.strip().startswith('['):
                return self._parse_json(content)
            else:
                return self._parse_xml(content)
                
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_json(self, content: str) -> List[NormalizedVulnerability]:
        """Parse JSON format"""
        vulnerabilities = []
        
        try:
            data = json.loads(content)
            
            # Masscan JSON is line-delimited, might be array or multiple objects
            if not isinstance(data, list):
                data = [data]
            
            for record in data:
                ip_address = record.get('ip', '')
                ports = record.get('ports', [])
                
                asset_id = self.generate_asset_id(ip_address)
                
                for port_info in ports:
                    port = port_info.get('port')
                    protocol = port_info.get('proto', 'tcp')
                    service = port_info.get('service', {})
                    service_name = service.get('name', 'unknown')
                    
                    vuln = NormalizedVulnerability(
                        asset_id=asset_id,
                        ip_address=ip_address,
                        port=int(port) if port else None,
                        protocol=protocol,
                        service_name=service_name,
                        scanner_source="Masscan",
                        timestamp=datetime.now(),
                        raw_data={'record': record}
                    )
                    vulnerabilities.append(vuln)
            
            self.logger.info(f"[Masscan] Parsed {len(vulnerabilities)} findings (JSON)")
            
        except json.JSONDecodeError:
            # Handle line-delimited JSON
            for line in content.split('\n'):
                if line.strip():
                    try:
                        record = json.loads(line)
                        ip_address = record.get('ip', '')
                        ports = record.get('ports', [])
                        
                        asset_id = self.generate_asset_id(ip_address)
                        
                        for port_info in ports:
                            port = port_info.get('port')
                            protocol = port_info.get('proto', 'tcp')
                            
                            vuln = NormalizedVulnerability(
                                asset_id=asset_id,
                                ip_address=ip_address,
                                port=int(port) if port else None,
                                protocol=protocol,
                                service_name='unknown',
                                scanner_source="Masscan",
                                timestamp=datetime.now(),
                                raw_data={'record': record}
                            )
                            vulnerabilities.append(vuln)
                    except:
                        continue
        
        return vulnerabilities
    
    def _parse_xml(self, content: str) -> List[NormalizedVulnerability]:
        """Parse XML format"""
        vulnerabilities = []
        
        try:
            data = xmltodict.parse(content)
            hosts = data.get('nmaprun', {}).get('host', [])
            
            if isinstance(hosts, dict):
                hosts = [hosts]
            
            for host in hosts:
                address = host.get('address', {})
                if isinstance(address, list):
                    address = address[0]
                
                ip_address = address.get('@addr', '')
                asset_id = self.generate_asset_id(ip_address)
                
                ports = host.get('ports', {}).get('port', [])
                if isinstance(ports, dict):
                    ports = [ports]
                
                for port in ports:
                    port_id = port.get('@portid')
                    protocol = port.get('@protocol', 'tcp')
                    state = port.get('state', {}).get('@state', 'unknown')
                    
                    if state == 'open':
                        vuln = NormalizedVulnerability(
                            asset_id=asset_id,
                            ip_address=ip_address,
                            port=int(port_id) if port_id else None,
                            protocol=protocol,
                            service_name='unknown',
                            scanner_source="Masscan",
                            timestamp=datetime.now(),
                            raw_data={'port': port}
                        )
                        vulnerabilities.append(vuln)
            
            self.logger.info(f"[Masscan] Parsed {len(vulnerabilities)} findings (XML)")
            
        except Exception as e:
            self.logger.error(f"[Masscan] XML parse error: {e}")
        
        return vulnerabilities
