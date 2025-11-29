"""
Trivy JSON parser
"""
import json
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability
from ingestors.base_parser import BaseParser
from datetime import datetime

class TrivyParser(BaseParser):
    """Parser for Trivy JSON output"""
    
    def __init__(self):
        super().__init__("Trivy")
    
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse Trivy JSON output"""
        if not self.validate_file(file_path):
            return []
        
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract artifact name (container image, filesystem, etc.)
            artifact_name = data.get('ArtifactName', 'unknown')
            asset_id = self.generate_asset_id(hostname=artifact_name)
            
            # Parse results
            results = data.get('Results', [])
            
            for result in results:
                target = result.get('Target', '')
                vulnerabilities_list = result.get('Vulnerabilities', [])
                
                for vuln_data in vulnerabilities_list:
                    vuln = self._parse_vulnerability(vuln_data, asset_id, 
                                                    artifact_name, target)
                    if vuln:
                        vulnerabilities.append(vuln)
            
            self.logger.info(f"[Trivy] Parsed {len(vulnerabilities)} findings from {file_path}")
            return vulnerabilities
            
        except Exception as e:
            return self.handle_parse_error(e, f"in file {file_path}")
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any], asset_id: str,
                            artifact_name: str, target: str) -> NormalizedVulnerability:
        """Parse individual vulnerability"""
        
        # Extract vulnerability details
        vuln_id = vuln_data.get('VulnerabilityID', '')
        pkg_name = vuln_data.get('PkgName', '')
        installed_version = vuln_data.get('InstalledVersion', '')
        fixed_version = vuln_data.get('FixedVersion', '')
        severity = vuln_data.get('Severity', 'UNKNOWN')
        
        # CVSS scores
        cvss = vuln_data.get('CVSS', {})
        cvss_score = None
        
        # Try different CVSS versions
        for version in ['nvd', 'redhat', 'V3Score']:
            if version in cvss:
                score_data = cvss[version]
                if isinstance(score_data, dict):
                    cvss_score = score_data.get('V3Score')
                else:
                    cvss_score = score_data
                if cvss_score:
                    break
        
        # CWE
        cwe_ids = vuln_data.get('CweIDs', [])
        cwe = cwe_ids[0] if cwe_ids else None
        
        # References
        references = vuln_data.get('References', [])
        
        vuln = NormalizedVulnerability(
            asset_id=asset_id,
            hostname=artifact_name,
            service_name=pkg_name,
            service_version=installed_version,
            tech_stack=[f"{pkg_name}:{installed_version}"],
            cve_id=vuln_id if vuln_id.startswith('CVE') else None,
            cvss_score=float(cvss_score) if cvss_score else None,
            severity=severity,
            cwe=cwe,
            patch_available=bool(fixed_version),
            scanner_source="Trivy",
            timestamp=datetime.now(),
            raw_data=vuln_data
        )
        
        return vuln
