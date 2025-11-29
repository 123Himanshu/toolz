"""
Main enrichment engine that coordinates all enrichers
"""
from typing import List
from models.schemas import NormalizedVulnerability
from enrichment.nvd_enrich import NVDEnricher
from enrichment.exploitdb_enrich import ExploitDBEnricher
from enrichment.epss_enrich import EPSSEnricher
from enrichment.attck_mapping import ATTCKMapper
from utils.logger import engine_logger
from utils.config import config
from tqdm import tqdm

class EnrichmentEngine:
    """Coordinates all enrichment sources"""
    
    def __init__(self):
        self.logger = engine_logger
        self.nvd_enricher = NVDEnricher() if config.get('enrichment.nvd_enabled', True) else None
        self.exploitdb_enricher = ExploitDBEnricher() if config.get('enrichment.exploitdb_enabled', True) else None
        self.epss_enricher = EPSSEnricher() if config.get('enrichment.epss_enabled', True) else None
        self.attck_mapper = ATTCKMapper() if config.get('enrichment.mitre_attck_enabled', True) else None
    
    def enrich_all(self, vulnerabilities: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        """Enrich all vulnerabilities with threat intelligence"""
        
        self.logger.info(f"Enriching {len(vulnerabilities)} vulnerabilities")
        
        enriched = []
        
        for vuln in tqdm(vulnerabilities, desc="Enriching vulnerabilities"):
            enriched_vuln = self.enrich_single(vuln)
            enriched.append(enriched_vuln)
        
        self.logger.info("Enrichment complete")
        return enriched
    
    def enrich_single(self, vulnerability: NormalizedVulnerability) -> NormalizedVulnerability:
        """Enrich a single vulnerability"""
        
        try:
            # NVD enrichment
            if self.nvd_enricher and vulnerability.cve_id:
                vulnerability = self.nvd_enricher.enrich(vulnerability)
            
            # ExploitDB enrichment
            if self.exploitdb_enricher and vulnerability.cve_id:
                vulnerability = self.exploitdb_enricher.enrich(vulnerability)
            
            # EPSS enrichment
            if self.epss_enricher and vulnerability.cve_id:
                vulnerability = self.epss_enricher.enrich(vulnerability)
            
            # MITRE ATT&CK mapping
            if self.attck_mapper:
                vulnerability = self.attck_mapper.map(vulnerability)
        
        except Exception as e:
            self.logger.error(f"Enrichment error for {vulnerability.cve_id or vulnerability.asset_id}: {e}")
        
        return vulnerability
    
    def bulk_enrich_epss(self, vulnerabilities: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        """Bulk EPSS enrichment for better performance"""
        
        if not self.epss_enricher:
            return vulnerabilities
        
        # Collect all CVE IDs
        cve_ids = [v.cve_id for v in vulnerabilities if v.cve_id]
        
        if not cve_ids:
            return vulnerabilities
        
        self.logger.info(f"Bulk fetching EPSS scores for {len(cve_ids)} CVEs")
        
        # Fetch all EPSS scores
        epss_scores = self.epss_enricher.bulk_fetch(cve_ids)
        
        # Apply to vulnerabilities
        for vuln in vulnerabilities:
            if vuln.cve_id and vuln.cve_id in epss_scores:
                epss_data = epss_scores[vuln.cve_id]
                vuln.epss_score = epss_data.get('epss')
                vuln.exploit_metadata['epss_percentile'] = epss_data.get('percentile')
        
        return vulnerabilities
