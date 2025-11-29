"""
Naabu JSON parser
"""
import json
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime

class NaabuParser(BaseParser):
    """Parser for Naabu JSON output"""
    
    def __init__(self):
        super().__init__("Naabu")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Naabu JSON output"""
        if not self.validate_file(file_path):
            return []
        
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Naabu outputs line-delimited JSON
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        vuln = self._parse_record(data)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"[Naabu] Failed to parse line: {line[:50]}...")
                        continue
            
            self.logger.info(f"[Naabu] Parsed {len(vulnerabilities)} findings from {file_path}")
            return vulnerabilities
            
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_record(self, data: Dict[str, Any]) -> NormalizedVulnerability:
        """Parse individual Naabu record"""
        
        # Naabu format: {"host":"192.168.1.1","port":"80","protocol":"tcp"}
        host = data.get('host', data.get('ip', ''))
        port = data.get('port')
        protocol = data.get('protocol', 'tcp')
        
        asset_id = self.generate_asset_id(host)
        
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            ip_address=host if self._is_ip(host) else None,
            hostname=host if not self._is_ip(host) else None,
            port=int(port) if port else None,
            protocol=protocol,
            service_name='unknown',
            scanner_source="Naabu",
            timestamp=datetime.now(),
            raw_data=data
        )
        
        return vuln
    
    def _is_ip(self, value: str) -> bool:
        """Check if string is an IP address"""
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))
