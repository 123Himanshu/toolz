"""
Normalization pipeline for vulnerability data
Handles deduplication, merging, and conflict resolution
"""
from typing import List, Dict, Any
from collections import defaultdict
from models.schemas import NormalizedVulnerability
from utils.logger import engine_logger
from datetime import datetime

class VulnerabilityNormalizer:
    """Normalizes and deduplicates vulnerability data from multiple scanners"""
    
    def __init__(self):
        self.logger = engine_logger
    
    def normalize(self, vulnerabilities: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        """
        Normalize vulnerability list:
        - Deduplicate identical findings
        - Merge CVEs from different scanners
        - Resolve conflicts
        """
        self.logger.info(f"Normalizing {len(vulnerabilities)} vulnerabilities")
        
        # Group by asset and vulnerability identifier
        grouped = self._group_vulnerabilities(vulnerabilities)
        
        # Merge grouped vulnerabilities
        normalized = []
        for key, vuln_list in grouped.items():
            merged = self._merge_vulnerabilities(vuln_list)
            normalized.append(merged)
        
        self.logger.info(f"Normalized to {len(normalized)} unique vulnerabilities")
        return normalized
    
    def _group_vulnerabilities(self, vulnerabilities: List[NormalizedVulnerability]) -> Dict[str, List[NormalizedVulnerability]]:
        """Group vulnerabilities by asset, port, and CVE/misconfiguration"""
        grouped = defaultdict(list)
        
        for vuln in vulnerabilities:
            # Create grouping key
            key_parts = [
                vuln.asset_id,
                str(vuln.port) if vuln.port else 'no_port',
                vuln.cve_id if vuln.cve_id else vuln.misconfiguration if vuln.misconfiguration else 'no_vuln'
            ]
            key = '|'.join(key_parts)
            grouped[key].append(vuln)
        
        return grouped
    
    def _merge_vulnerabilities(self, vuln_list: List[NormalizedVulnerability]) -> NormalizedVulnerability:
        """Merge multiple vulnerability records into one"""
        
        if len(vuln_list) == 1:
            return vuln_list[0]
        
        # Use first as base
        merged = vuln_list[0]
        
        # Collect all scanner sources
        scanner_sources = [v.scanner_source for v in vuln_list]
        merged.scanner_source = ', '.join(set(scanner_sources))
        
        # Merge fields with conflict resolution
        for vuln in vuln_list[1:]:
            # Take non-null values
            if not merged.hostname and vuln.hostname:
                merged.hostname = vuln.hostname
            
            if not merged.ip_address and vuln.ip_address:
                merged.ip_address = vuln.ip_address
            
            if not merged.service_name or merged.service_name == 'unknown':
                if vuln.service_name and vuln.service_name != 'unknown':
                    merged.service_name = vuln.service_name
            
            if not merged.service_version and vuln.service_version:
                merged.service_version = vuln.service_version
            
            if not merged.os and vuln.os:
                merged.os = vuln.os
            
            # Merge tech stack
            merged.tech_stack = list(set(merged.tech_stack + vuln.tech_stack))
            
            # Take highest CVSS score
            if vuln.cvss_score:
                if not merged.cvss_score or vuln.cvss_score > merged.cvss_score:
                    merged.cvss_score = vuln.cvss_score
            
            # Take most severe severity
            if vuln.severity:
                merged.severity = self._resolve_severity(merged.severity, vuln.severity)
            
            # Merge CWE
            if not merged.cwe and vuln.cwe:
                merged.cwe = vuln.cwe
            
            # Exploit availability - if any scanner says yes, it's yes
            if vuln.exploit_available:
                merged.exploit_available = True
            
            # Take EPSS score if available
            if vuln.epss_score:
                if not merged.epss_score or vuln.epss_score > merged.epss_score:
                    merged.epss_score = vuln.epss_score
            
            # Merge MITRE techniques
            merged.mitre_techniques = list(set(merged.mitre_techniques + vuln.mitre_techniques))
            
            # Patch availability
            if vuln.patch_available:
                merged.patch_available = True
            
            # Merge exploit metadata
            merged.exploit_metadata.update(vuln.exploit_metadata)
        
        # Update timestamp to latest
        merged.timestamp = datetime.now()
        
        return merged
    
    def _resolve_severity(self, sev1: str, sev2: str) -> str:
        """Resolve severity conflict by taking the higher severity"""
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        if not sev1:
            return sev2
        if not sev2:
            return sev1
        
        try:
            idx1 = severity_order.index(sev1.upper())
            idx2 = severity_order.index(sev2.upper())
            return severity_order[max(idx1, idx2)]
        except ValueError:
            return sev1
    
    def deduplicate_by_cve(self, vulnerabilities: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        """Additional deduplication specifically for CVEs across assets"""
        cve_map = defaultdict(list)
        non_cve = []
        
        for vuln in vulnerabilities:
            if vuln.cve_id:
                key = f"{vuln.asset_id}|{vuln.cve_id}"
                cve_map[key].append(vuln)
            else:
                non_cve.append(vuln)
        
        # Merge CVE duplicates
        deduplicated = []
        for key, vuln_list in cve_map.items():
            merged = self._merge_vulnerabilities(vuln_list)
            deduplicated.append(merged)
        
        # Add non-CVE vulnerabilities
        deduplicated.extend(non_cve)
        
        return deduplicated
