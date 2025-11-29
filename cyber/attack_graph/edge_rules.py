"""
Edge rules for attack graph construction
Defines relationships between nodes based on vulnerabilities and configurations
"""
from typing import Dict, Any, List, Tuple
from models.schemas import NormalizedVulnerability
from utils.logger import engine_logger

class EdgeRuleEngine:
    """Defines rules for creating edges in the attack graph"""
    
    def __init__(self):
        self.logger = engine_logger
    
    def create_vulnerability_edge(self, vuln: NormalizedVulnerability) -> Dict[str, Any]:
        """Create edge attributes for a vulnerability"""
        
        # Determine edge type based on vulnerability characteristics
        edge_type = self._determine_edge_type(vuln)
        
        # Calculate edge weight (lower = easier to exploit)
        weight = self._calculate_edge_weight(vuln)
        
        # Determine privilege gained
        privilege_gained = self._determine_privilege_gained(vuln)
        
        # Determine impact
        impact = self._determine_impact(vuln)
        
        edge_attrs = {
            'type': edge_type,
            'weight': weight,
            'cve_id': vuln.cve_id,
            'cvss_score': vuln.cvss_score or 0,
            'epss_score': vuln.epss_score or 0,
            'exploit_available': vuln.exploit_available,
            'privilege_gained': privilege_gained,
            'impact': impact,
            'attack_vector': vuln.attack_vector,
            'mitre_techniques': vuln.mitre_techniques,
            'service': vuln.service_name,
            'port': vuln.port
        }
        
        return edge_attrs
    
    def _determine_edge_type(self, vuln: NormalizedVulnerability) -> str:
        """Determine the type of attack edge"""
        
        # Check MITRE techniques
        if vuln.mitre_techniques:
            if 'T1190' in vuln.mitre_techniques:
                return 'RCE'  # Remote Code Execution
            if 'T1068' in vuln.mitre_techniques:
                return 'LPE'  # Local Privilege Escalation
            if 'T1021' in vuln.mitre_techniques:
                return 'LATERAL'  # Lateral Movement
            if 'T1005' in vuln.mitre_techniques or 'T1083' in vuln.mitre_techniques:
                return 'INFO_LEAK'
        
        # Check CWE
        if vuln.cwe:
            if vuln.cwe in ['CWE-78', 'CWE-94']:
                return 'RCE'
            if vuln.cwe in ['CWE-269', 'CWE-264']:
                return 'PRIV_ESC'
            if vuln.cwe in ['CWE-200', 'CWE-209']:
                return 'INFO_LEAK'
        
        # Check attack vector
        if vuln.attack_vector == 'NETWORK':
            return 'REMOTE_EXPLOIT'
        elif vuln.attack_vector == 'LOCAL':
            return 'LOCAL_EXPLOIT'
        
        # Default
        return 'EXPLOIT'
    
    def _calculate_edge_weight(self, vuln: NormalizedVulnerability) -> float:
        """
        Calculate edge weight (complexity of exploitation)
        Lower weight = easier to exploit
        """
        
        weight = 10.0  # Base weight
        
        # CVSS score reduces weight (higher CVSS = easier/more severe)
        if vuln.cvss_score:
            weight -= (vuln.cvss_score / 10.0) * 3
        
        # EPSS score reduces weight (higher EPSS = more likely to be exploited)
        if vuln.epss_score:
            weight -= vuln.epss_score * 2
        
        # Exploit availability significantly reduces weight
        if vuln.exploit_available:
            weight -= 2
        
        # Attack vector affects weight
        if vuln.attack_vector == 'NETWORK':
            weight -= 1  # Network exploits are more accessible
        elif vuln.attack_vector == 'LOCAL':
            weight += 1  # Local exploits require prior access
        
        # Privilege required increases weight
        if vuln.privilege_required:
            if vuln.privilege_required == 'NONE':
                weight -= 1
            elif vuln.privilege_required == 'LOW':
                weight += 0.5
            elif vuln.privilege_required == 'HIGH':
                weight += 2
        
        # Ensure weight is positive
        weight = max(0.1, weight)
        
        return weight
    
    def _determine_privilege_gained(self, vuln: NormalizedVulnerability) -> str:
        """Determine what privilege level is gained through this vulnerability"""
        
        # Check MITRE techniques
        if vuln.mitre_techniques:
            if 'T1068' in vuln.mitre_techniques or 'T1548' in vuln.mitre_techniques:
                return 'SYSTEM'
            if 'T1078' in vuln.mitre_techniques:
                return 'USER'
        
        # Check CWE
        if vuln.cwe:
            if vuln.cwe in ['CWE-269', 'CWE-264']:
                return 'ELEVATED'
        
        # Check attack vector and CVSS
        if vuln.attack_vector == 'NETWORK' and vuln.cvss_score and vuln.cvss_score >= 9.0:
            return 'SYSTEM'
        
        # Default based on service
        if vuln.service_name in ['ssh', 'rdp', 'telnet']:
            return 'USER'
        
        return 'USER'
    
    def _determine_impact(self, vuln: NormalizedVulnerability) -> str:
        """Determine the impact of exploiting this vulnerability"""
        
        if vuln.cvss_score:
            if vuln.cvss_score >= 9.0:
                return 'CRITICAL'
            elif vuln.cvss_score >= 7.0:
                return 'HIGH'
            elif vuln.cvss_score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        # Fallback to severity
        if vuln.severity:
            return vuln.severity
        
        return 'MEDIUM'
    
    def create_reachability_edge(self, source_segment: str, target_segment: str, 
                                 reachable: bool = True) -> Dict[str, Any]:
        """Create network reachability edge"""
        
        return {
            'type': 'REACHABILITY',
            'weight': 0.1 if reachable else 100.0,
            'reachable': reachable,
            'source_segment': source_segment,
            'target_segment': target_segment
        }
    
    def create_credential_edge(self, credential_type: str, strength: str = 'weak') -> Dict[str, Any]:
        """Create credential reuse edge"""
        
        weight_map = {
            'weak': 0.5,
            'medium': 2.0,
            'strong': 5.0
        }
        
        return {
            'type': 'CREDENTIAL_REUSE',
            'weight': weight_map.get(strength, 2.0),
            'credential_type': credential_type,
            'strength': strength
        }
    
    def create_trust_edge(self, trust_level: str = 'implicit') -> Dict[str, Any]:
        """Create trust relationship edge"""
        
        return {
            'type': 'TRUST',
            'weight': 1.0,
            'trust_level': trust_level
        }
