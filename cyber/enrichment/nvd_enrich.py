"""
NVD (National Vulnerability Database) enrichment
"""
import requests
import time
from typing import Dict, Any, Optional
from models.schemas import NormalizedVulnerability
from utils.logger import engine_logger
from utils.config import config

class NVDEnricher:
    """Enrich vulnerabilities with NVD data"""
    
    def __init__(self):
        self.logger = engine_logger
        self.api_key = config.get('api_keys.nvd_api_key', '')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.rate_limit_delay = 0.6 if self.api_key else 6  # With key: 10/sec, without: 5/30sec
    
    def enrich(self, vulnerability: NormalizedVulnerability) -> NormalizedVulnerability:
        """Enrich vulnerability with NVD data"""
        
        if not vulnerability.cve_id:
            return vulnerability
        
        try:
            cve_data = self._fetch_cve_data(vulnerability.cve_id)
            
            if cve_data:
                vulnerability = self._apply_enrichment(vulnerability, cve_data)
                self.logger.debug(f"Enriched {vulnerability.cve_id} with NVD data")
            
            time.sleep(self.rate_limit_delay)
            
        except Exception as e:
            self.logger.error(f"NVD enrichment error for {vulnerability.cve_id}: {e}")
        
        return vulnerability
    
    def _fetch_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NVD API"""
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        params = {'cveId': cve_id}
        
        try:
            response = requests.get(self.base_url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if vulnerabilities:
                    return vulnerabilities[0].get('cve', {})
            
            elif response.status_code == 404:
                self.logger.warning(f"CVE {cve_id} not found in NVD")
            else:
                self.logger.warning(f"NVD API returned status {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"NVD API request failed: {e}")
        
        return None
    
    def _apply_enrichment(self, vulnerability: NormalizedVulnerability, 
                         cve_data: Dict[str, Any]) -> NormalizedVulnerability:
        """Apply NVD data to vulnerability"""
        
        # Extract CVSS metrics
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS v3.1 first, then v3.0, then v2.0
        cvss_data = None
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0]
                break
        
        if cvss_data:
            cvss_info = cvss_data.get('cvssData', {})
            
            # Update CVSS score if not present
            if not vulnerability.cvss_score:
                base_score = cvss_info.get('baseScore')
                if base_score:
                    vulnerability.cvss_score = float(base_score)
            
            # Update attack vector
            if not vulnerability.attack_vector:
                attack_vector = cvss_info.get('attackVector')
                if attack_vector:
                    vulnerability.attack_vector = attack_vector
            
            # Update privilege required
            if not vulnerability.privilege_required:
                priv_required = cvss_info.get('privilegesRequired')
                if priv_required:
                    vulnerability.privilege_required = priv_required
        
        # Extract CWE if not present
        if not vulnerability.cwe:
            weaknesses = cve_data.get('weaknesses', [])
            for weakness in weaknesses:
                descriptions = weakness.get('description', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        cwe_id = desc.get('value', '')
                        if cwe_id.startswith('CWE-'):
                            vulnerability.cwe = cwe_id
                            break
                if vulnerability.cwe:
                    break
        
        # Extract references
        references = cve_data.get('references', [])
        exploit_refs = []
        patch_refs = []
        
        for ref in references:
            tags = ref.get('tags', [])
            url = ref.get('url', '')
            
            if 'Exploit' in tags:
                exploit_refs.append(url)
            if 'Patch' in tags or 'Vendor Advisory' in tags:
                patch_refs.append(url)
        
        # Update exploit metadata
        if exploit_refs:
            vulnerability.exploit_metadata['nvd_exploit_refs'] = exploit_refs
            vulnerability.exploit_available = True
        
        # Update patch availability
        if patch_refs:
            vulnerability.patch_available = True
            vulnerability.exploit_metadata['patch_refs'] = patch_refs
        
        # Store full NVD data
        vulnerability.exploit_metadata['nvd_data'] = cve_data
        
        return vulnerability
