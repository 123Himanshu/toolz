"""
MITRE ATT&CK technique mapping
"""
import requests
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from utils.logger import engine_logger

class ATTCKMapper:
    """Map vulnerabilities to MITRE ATT&CK techniques"""
    
    def __init__(self):
        self.logger = engine_logger
        self.technique_map = self._load_technique_mappings()
    
    def _load_technique_mappings(self) -> Dict[str, List[str]]:
        """Load CVE to ATT&CK technique mappings"""
        
        # In production, load from MITRE ATT&CK STIX data
        # For now, use heuristic mapping based on vulnerability characteristics
        
        mappings = {
            # Common mappings based on vulnerability types
            'RCE': ['T1190', 'T1203'],  # Exploit Public-Facing Application, Exploitation for Client Execution
            'SQLi': ['T1190', 'T1213'],  # Exploit Public-Facing Application, Data from Information Repositories
            'XSS': ['T1189', 'T1059'],  # Drive-by Compromise, Command and Scripting Interpreter
            'LPE': ['T1068'],  # Exploitation for Privilege Escalation
            'PrivEsc': ['T1068', 'T1548'],  # Exploitation for Privilege Escalation, Abuse Elevation Control Mechanism
            'InfoLeak': ['T1005', 'T1083'],  # Data from Local System, File and Directory Discovery
            'AuthBypass': ['T1078'],  # Valid Accounts
            'SSRF': ['T1090'],  # Proxy
            'Deserialization': ['T1203'],  # Exploitation for Client Execution
        }
        
        return mappings
    
    def map(self, vulnerability: NormalizedVulnerability) -> NormalizedVulnerability:
        """Map vulnerability to ATT&CK techniques"""
        
        techniques = []
        
        try:
            # Map based on CWE
            if vulnerability.cwe:
                techniques.extend(self._map_by_cwe(vulnerability.cwe))
            
            # Map based on misconfiguration type
            if vulnerability.misconfiguration:
                techniques.extend(self._map_by_description(vulnerability.misconfiguration))
            
            # Map based on service
            if vulnerability.service_name:
                techniques.extend(self._map_by_service(vulnerability.service_name))
            
            # Remove duplicates
            techniques = list(set(techniques))
            
            if techniques:
                vulnerability.mitre_techniques = techniques
                self.logger.debug(f"Mapped {vulnerability.cve_id or 'vuln'} to techniques: {techniques}")
        
        except Exception as e:
            self.logger.error(f"ATT&CK mapping error: {e}")
        
        return vulnerability
    
    def _map_by_cwe(self, cwe: str) -> List[str]:
        """Map CWE to ATT&CK techniques"""
        
        cwe_mappings = {
            'CWE-78': ['T1059'],  # OS Command Injection
            'CWE-79': ['T1189'],  # XSS
            'CWE-89': ['T1190'],  # SQL Injection
            'CWE-94': ['T1059'],  # Code Injection
            'CWE-119': ['T1203'],  # Buffer Overflow
            'CWE-190': ['T1203'],  # Integer Overflow
            'CWE-200': ['T1005'],  # Information Exposure
            'CWE-269': ['T1068'],  # Privilege Escalation
            'CWE-287': ['T1078'],  # Authentication Bypass
            'CWE-502': ['T1203'],  # Deserialization
            'CWE-918': ['T1090'],  # SSRF
        }
        
        return cwe_mappings.get(cwe, [])
    
    def _map_by_description(self, description: str) -> List[str]:
        """Map vulnerability description to techniques"""
        
        description_lower = description.lower()
        techniques = []
        
        if 'remote code execution' in description_lower or 'rce' in description_lower:
            techniques.extend(self.technique_map.get('RCE', []))
        
        if 'sql injection' in description_lower or 'sqli' in description_lower:
            techniques.extend(self.technique_map.get('SQLi', []))
        
        if 'cross-site scripting' in description_lower or 'xss' in description_lower:
            techniques.extend(self.technique_map.get('XSS', []))
        
        if 'privilege escalation' in description_lower:
            techniques.extend(self.technique_map.get('PrivEsc', []))
        
        if 'information disclosure' in description_lower or 'info leak' in description_lower:
            techniques.extend(self.technique_map.get('InfoLeak', []))
        
        return techniques
    
    def _map_by_service(self, service: str) -> List[str]:
        """Map service type to common attack techniques"""
        
        service_lower = service.lower()
        
        if service_lower in ['http', 'https', 'web']:
            return ['T1190']  # Exploit Public-Facing Application
        
        if service_lower in ['ssh', 'telnet']:
            return ['T1021']  # Remote Services
        
        if service_lower in ['smb', 'cifs']:
            return ['T1021.002']  # SMB/Windows Admin Shares
        
        if service_lower in ['rdp']:
            return ['T1021.001']  # Remote Desktop Protocol
        
        return []
