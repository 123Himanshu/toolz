"""
EPSS (Exploit Prediction Scoring System) enrichment
"""
import requests
from typing import Dict, Any, Optional
from models.schemas import NormalizedVulnerability
from utils.logger import engine_logger

class EPSSEnricher:
    """Enrich vulnerabilities with EPSS scores"""
    
    def __init__(self):
        self.logger = engine_logger
        self.base_url = "https://api.first.org/data/v1/epss"
        self.cache = {}
    
    def enrich(self, vulnerability: NormalizedVulnerability) -> NormalizedVulnerability:
        """Enrich vulnerability with EPSS score"""
        
        if not vulnerability.cve_id:
            return vulnerability
        
        try:
            epss_data = self._fetch_epss_score(vulnerability.cve_id)
            
            if epss_data:
                vulnerability.epss_score = epss_data.get('epss')
                vulnerability.exploit_metadata['epss_percentile'] = epss_data.get('percentile')
                self.logger.debug(f"EPSS score for {vulnerability.cve_id}: {vulnerability.epss_score}")
        
        except Exception as e:
            self.logger.error(f"EPSS enrichment error: {e}")
        
        return vulnerability
    
    def _fetch_epss_score(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch EPSS score from FIRST API"""
        
        # Check cache
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            params = {'cve': cve_id}
            response = requests.get(self.base_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                epss_data = data.get('data', [])
                
                if epss_data:
                    result = {
                        'epss': float(epss_data[0].get('epss', 0)),
                        'percentile': float(epss_data[0].get('percentile', 0))
                    }
                    
                    # Cache result
                    self.cache[cve_id] = result
                    return result
        
        except Exception as e:
            self.logger.debug(f"EPSS API request failed: {e}")
        
        return None
    
    def bulk_fetch(self, cve_ids: list) -> Dict[str, Dict[str, Any]]:
        """Fetch EPSS scores for multiple CVEs"""
        
        results = {}
        
        # EPSS API supports bulk queries
        try:
            # Split into batches of 100
            batch_size = 100
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i+batch_size]
                cve_param = ','.join(batch)
                
                params = {'cve': cve_param}
                response = requests.get(self.base_url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    epss_data = data.get('data', [])
                    
                    for item in epss_data:
                        cve = item.get('cve')
                        results[cve] = {
                            'epss': float(item.get('epss', 0)),
                            'percentile': float(item.get('percentile', 0))
                        }
        
        except Exception as e:
            self.logger.error(f"EPSS bulk fetch failed: {e}")
        
        return results
