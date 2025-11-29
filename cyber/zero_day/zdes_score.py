"""
Zero-Day Exposure Score (ZDES) Calculator
Scores assets based on zero-day exposure risk factors
"""
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability, Asset, ZeroDayIndicator
from utils.logger import engine_logger
from datetime import datetime, timedelta

class ZDESCalculator:
    """Calculate Zero-Day Exposure Score for assets"""
    
    def __init__(self):
        self.logger = engine_logger
        self.eol_software = self._load_eol_database()
    
    def _load_eol_database(self) -> Dict[str, datetime]:
        """Load End-of-Life software database"""
        
        # Simplified EOL database
        # In production, load from endoflife.date API or similar
        return {
            'windows_7': datetime(2020, 1, 14),
            'windows_server_2008': datetime(2020, 1, 14),
            'ubuntu_16.04': datetime(2021, 4, 30),
            'centos_6': datetime(2020, 11, 30),
            'php_5': datetime(2019, 1, 1),
            'python_2': datetime(2020, 1, 1),
        }
    
    def calculate_zdes(self, asset: Asset, vulnerabilities: List[NormalizedVulnerability]) -> float:
        """
        Calculate ZDES score (0-100) for an asset
        Higher score = higher zero-day exposure risk
        """
        
        score = 0.0
        indicators = []
        
        # Factor 1: Unknown/unclassified services (20 points)
        unknown_score, unknown_indicators = self._score_unknown_services(vulnerabilities)
        score += unknown_score
        indicators.extend(unknown_indicators)
        
        # Factor 2: EOL software (25 points)
        eol_score, eol_indicators = self._score_eol_software(asset, vulnerabilities)
        score += eol_score
        indicators.extend(eol_indicators)
        
        # Factor 3: Unknown version fingerprints (15 points)
        version_score, version_indicators = self._score_unknown_versions(vulnerabilities)
        score += version_score
        indicators.extend(version_indicators)
        
        # Factor 4: Weak configurations (10 points)
        config_score, config_indicators = self._score_weak_configs(vulnerabilities)
        score += config_score
        indicators.extend(config_indicators)
        
        # Factor 5: Abnormal port-service mapping (10 points)
        port_score, port_indicators = self._score_abnormal_ports(vulnerabilities)
        score += port_score
        indicators.extend(port_indicators)
        
        # Factor 6: Lack of patches (10 points)
        patch_score, patch_indicators = self._score_patch_status(vulnerabilities)
        score += patch_score
        indicators.extend(patch_indicators)
        
        # Factor 7: External exposure (10 points)
        exposure_score, exposure_indicators = self._score_external_exposure(asset, vulnerabilities)
        score += exposure_score
        indicators.extend(exposure_indicators)
        
        self.logger.debug(f"ZDES for {asset.asset_id}: {score:.2f}")
        
        return min(100.0, score)
    
    def _score_unknown_services(self, vulns: List[NormalizedVulnerability]) -> tuple:
        """Score based on unknown/unclassified services"""
        
        unknown_count = 0
        indicators = []
        
        for vuln in vulns:
            if vuln.service_name in ['unknown', 'unidentified', None, '']:
                unknown_count += 1
                indicators.append(ZeroDayIndicator(
                    asset_id=vuln.asset_id,
                    indicator_type='exposure',
                    description=f'Unknown service on port {vuln.port}',
                    confidence=0.6,
                    severity='MEDIUM'
                ))
        
        # Score: 0-20 points based on proportion of unknown services
        if vulns:
            ratio = unknown_count / len(vulns)
            score = ratio * 20
        else:
            score = 0
        
        return score, indicators
    
    def _score_eol_software(self, asset: Asset, vulns: List[NormalizedVulnerability]) -> tuple:
        """Score based on End-of-Life software"""
        
        score = 0
        indicators = []
        
        # Check OS
        if asset.os:
            os_lower = asset.os.lower()
            for eol_name, eol_date in self.eol_software.items():
                if eol_name.replace('_', ' ') in os_lower:
                    if datetime.now() > eol_date:
                        score += 15
                        indicators.append(ZeroDayIndicator(
                            asset_id=asset.asset_id,
                            indicator_type='exposure',
                            description=f'EOL operating system: {asset.os}',
                            confidence=0.9,
                            severity='HIGH',
                            details={'eol_date': eol_date.isoformat()}
                        ))
        
        # Check service versions
        for vuln in vulns:
            if vuln.service_version:
                version_lower = vuln.service_version.lower()
                for eol_name, eol_date in self.eol_software.items():
                    if eol_name.replace('_', ' ') in version_lower:
                        if datetime.now() > eol_date:
                            score += 5
                            indicators.append(ZeroDayIndicator(
                                asset_id=vuln.asset_id,
                                indicator_type='exposure',
                                description=f'EOL software: {vuln.service_name} {vuln.service_version}',
                                confidence=0.8,
                                severity='MEDIUM',
                                details={'eol_date': eol_date.isoformat()}
                            ))
                            break
        
        return min(25, score), indicators
    
    def _score_unknown_versions(self, vulns: List[NormalizedVulnerability]) -> tuple:
        """Score based on unknown version fingerprints"""
        
        unknown_count = 0
        indicators = []
        
        for vuln in vulns:
            if vuln.service_name and vuln.service_name != 'unknown':
                if not vuln.service_version or vuln.service_version == '':
                    unknown_count += 1
                    indicators.append(ZeroDayIndicator(
                        asset_id=vuln.asset_id,
                        indicator_type='exposure',
                        description=f'Unknown version for {vuln.service_name} on port {vuln.port}',
                        confidence=0.5,
                        severity='LOW'
                    ))
        
        # Score: 0-15 points
        if vulns:
            ratio = unknown_count / len(vulns)
            score = ratio * 15
        else:
            score = 0
        
        return score, indicators
    
    def _score_weak_configs(self, vulns: List[NormalizedVulnerability]) -> tuple:
        """Score based on weak configurations"""
        
        score = 0
        indicators = []
        
        weak_config_keywords = [
            'default', 'misconfiguration', 'weak', 'insecure',
            'anonymous', 'unauthenticated', 'exposed'
        ]
        
        for vuln in vulns:
            if vuln.misconfiguration:
                misc_lower = vuln.misconfiguration.lower()
                if any(keyword in misc_lower for keyword in weak_config_keywords):
                    score += 2
                    indicators.append(ZeroDayIndicator(
                        asset_id=vuln.asset_id,
                        indicator_type='exposure',
                        description=f'Weak configuration: {vuln.misconfiguration}',
                        confidence=0.7,
                        severity='MEDIUM'
                    ))
        
        return min(10, score), indicators
    
    def _score_abnormal_ports(self, vulns: List[NormalizedVulnerability]) -> tuple:
        """Score based on abnormal port-service mappings"""
        
        # Standard port mappings
        standard_ports = {
            'http': [80, 8080, 8000],
            'https': [443, 8443],
            'ssh': [22],
            'ftp': [21],
            'smtp': [25, 587],
            'mysql': [3306],
            'postgresql': [5432],
            'rdp': [3389],
            'smb': [445, 139]
        }
        
        score = 0
        indicators = []
        
        for vuln in vulns:
            if vuln.service_name and vuln.port:
                expected_ports = standard_ports.get(vuln.service_name.lower(), [])
                if expected_ports and vuln.port not in expected_ports:
                    score += 2
                    indicators.append(ZeroDayIndicator(
                        asset_id=vuln.asset_id,
                        indicator_type='anomaly',
                        description=f'{vuln.service_name} on non-standard port {vuln.port}',
                        confidence=0.6,
                        severity='LOW'
                    ))
        
        return min(10, score), indicators
    
    def _score_patch_status(self, vulns: List[NormalizedVulnerability]) -> tuple:
        """Score based on lack of patches"""
        
        unpatched_count = 0
        indicators = []
        
        for vuln in vulns:
            if vuln.cve_id and not vuln.patch_available:
                unpatched_count += 1
                if vuln.cvss_score and vuln.cvss_score >= 7.0:
                    indicators.append(ZeroDayIndicator(
                        asset_id=vuln.asset_id,
                        indicator_type='exposure',
                        description=f'Unpatched high-severity CVE: {vuln.cve_id}',
                        confidence=0.8,
                        severity='HIGH'
                    ))
        
        # Score: 0-10 points
        if vulns:
            ratio = unpatched_count / len(vulns)
            score = ratio * 10
        else:
            score = 0
        
        return score, indicators
    
    def _score_external_exposure(self, asset: Asset, vulns: List[NormalizedVulnerability]) -> tuple:
        """Score based on external exposure"""
        
        score = 0
        indicators = []
        
        if asset.is_external:
            score += 5
            
            # Additional points for externally exposed vulnerable services
            for vuln in vulns:
                if vuln.attack_vector == 'NETWORK' and vuln.cvss_score and vuln.cvss_score >= 7.0:
                    score += 1
                    indicators.append(ZeroDayIndicator(
                        asset_id=vuln.asset_id,
                        indicator_type='exposure',
                        description=f'Externally exposed vulnerable service: {vuln.service_name}',
                        confidence=0.9,
                        severity='HIGH'
                    ))
        
        return min(10, score), indicators
