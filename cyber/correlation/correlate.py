"""
Correlation Engine
Merges all intelligence sources and calculates final risk scores
"""
from typing import List, Dict, Any, Tuple
from models.schemas import NormalizedVulnerability, Asset, AttackPath, ZeroDayIndicator
from utils.logger import engine_logger
from utils.config import config
from collections import defaultdict
import numpy as np

class CorrelationEngine:
    """Correlates all data sources and calculates comprehensive risk scores"""
    
    def __init__(self):
        self.logger = engine_logger
        self.weights = config.get('risk_weights', {
            'cvss': 0.25,
            'epss': 0.20,
            'exploitability': 0.20,
            'chain_potential': 0.15,
            'zdes': 0.10,
            'path_impact': 0.10
        })
    
    def correlate_all(self, 
                     vulnerabilities: List[NormalizedVulnerability],
                     assets: List[Asset],
                     attack_paths: List[AttackPath],
                     zero_day_indicators: List[ZeroDayIndicator]) -> Dict[str, Any]:
        """
        Correlate all intelligence sources
        Returns comprehensive risk assessment
        """
        
        self.logger.info("Starting correlation analysis")
        
        # Calculate asset risk scores
        asset_risks = self._calculate_asset_risks(vulnerabilities, assets, attack_paths, zero_day_indicators)
        
        # Identify critical attack paths
        critical_paths = self._identify_critical_paths(attack_paths)
        
        # Identify high-risk assets
        high_risk_assets = self._identify_high_risk_assets(asset_risks)
        
        # Generate kill chain sequences
        kill_chains = self._generate_kill_chains(attack_paths)
        
        # Create zero-day exposure map
        zd_exposure_map = self._create_zero_day_map(assets, zero_day_indicators)
        
        # Calculate overall network risk
        network_risk = self._calculate_network_risk(asset_risks, attack_paths)
        
        correlation_result = {
            'asset_risks': asset_risks,
            'high_risk_assets': high_risk_assets,
            'critical_paths': critical_paths,
            'kill_chains': kill_chains,
            'zero_day_exposure_map': zd_exposure_map,
            'network_risk_score': network_risk,
            'total_vulnerabilities': len(vulnerabilities),
            'total_assets': len(assets),
            'total_attack_paths': len(attack_paths),
            'total_zero_day_indicators': len(zero_day_indicators)
        }
        
        self.logger.info("Correlation analysis complete")
        
        return correlation_result
    
    def _calculate_asset_risks(self, 
                               vulnerabilities: List[NormalizedVulnerability],
                               assets: List[Asset],
                               attack_paths: List[AttackPath],
                               zero_day_indicators: List[ZeroDayIndicator]) -> Dict[str, Dict[str, Any]]:
        """Calculate comprehensive risk score for each asset"""
        
        asset_risks = {}
        
        # Group data by asset
        asset_vulns = defaultdict(list)
        asset_paths = defaultdict(list)
        asset_zd_indicators = defaultdict(list)
        
        for vuln in vulnerabilities:
            asset_vulns[vuln.asset_id].append(vuln)
        
        for path in attack_paths:
            asset_paths[path.target].append(path)
        
        for indicator in zero_day_indicators:
            asset_zd_indicators[indicator.asset_id].append(indicator)
        
        # Calculate risk for each asset
        for asset in assets:
            asset_id = asset.asset_id
            
            vulns = asset_vulns.get(asset_id, [])
            paths = asset_paths.get(asset_id, [])
            zd_inds = asset_zd_indicators.get(asset_id, [])
            
            risk_score = self._calculate_risk_score(asset, vulns, paths, zd_inds)
            
            asset_risks[asset_id] = {
                'asset': asset.to_dict(),
                'risk_score': risk_score,
                'vulnerability_count': len(vulns),
                'attack_path_count': len(paths),
                'zero_day_indicator_count': len(zd_inds),
                'zdes_score': asset.zdes_score,
                'risk_level': self._get_risk_level(risk_score)
            }
        
        return asset_risks
    
    def _calculate_risk_score(self, 
                             asset: Asset,
                             vulns: List[NormalizedVulnerability],
                             paths: List[AttackPath],
                             zd_indicators: List[ZeroDayIndicator]) -> float:
        """
        Calculate weighted risk score
        Score range: 0-100
        """
        
        # Component 1: CVSS score (weighted average)
        cvss_scores = [v.cvss_score for v in vulns if v.cvss_score]
        cvss_component = (np.mean(cvss_scores) * 10) if cvss_scores else 0
        
        # Component 2: EPSS score (weighted average)
        epss_scores = [v.epss_score for v in vulns if v.epss_score]
        epss_component = (np.mean(epss_scores) * 100) if epss_scores else 0
        
        # Component 3: Exploitability (based on exploit availability)
        exploit_count = sum(1 for v in vulns if v.exploit_available)
        exploitability_component = min(100, (exploit_count / max(len(vulns), 1)) * 100)
        
        # Component 4: Chain potential (number of attack paths)
        chain_component = min(100, len(paths) * 10)
        
        # Component 5: ZDES score
        zdes_component = asset.zdes_score
        
        # Component 6: Path impact (average impact of paths)
        if paths:
            path_impacts = [p.total_impact for p in paths]
            path_component = min(100, np.mean(path_impacts) * 10)
        else:
            path_component = 0
        
        # Calculate weighted score
        risk_score = (
            cvss_component * self.weights['cvss'] +
            epss_component * self.weights['epss'] +
            exploitability_component * self.weights['exploitability'] +
            chain_component * self.weights['chain_potential'] +
            zdes_component * self.weights['zdes'] +
            path_component * self.weights['path_impact']
        )
        
        return min(100.0, risk_score)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'INFO'
    
    def _identify_high_risk_assets(self, asset_risks: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify and rank high-risk assets"""
        
        # Sort by risk score
        sorted_assets = sorted(
            asset_risks.values(),
            key=lambda x: x['risk_score'],
            reverse=True
        )
        
        # Return top assets with risk >= 60
        high_risk = [a for a in sorted_assets if a['risk_score'] >= 60]
        
        return high_risk
    
    def _identify_critical_paths(self, attack_paths: List[AttackPath]) -> List[Dict[str, Any]]:
        """Identify critical attack paths"""
        
        critical_paths = []
        
        for path in attack_paths:
            # Consider critical if high exploitability and impact
            if path.exploitability_score >= 70 and path.total_impact >= 7.0:
                critical_paths.append({
                    'path': path.to_dict(),
                    'criticality_score': (path.exploitability_score + path.total_impact * 10) / 2
                })
        
        # Sort by criticality
        critical_paths.sort(key=lambda x: x['criticality_score'], reverse=True)
        
        return critical_paths
    
    def _generate_kill_chains(self, attack_paths: List[AttackPath]) -> List[Dict[str, Any]]:
        """Generate kill chain sequences from attack paths"""
        
        kill_chains = []
        
        for path in attack_paths:
            if path.path_type == 'chained' and len(path.steps) >= 2:
                kill_chain = {
                    'path_id': path.path_id,
                    'entry_point': path.entry_point,
                    'target': path.target,
                    'stages': []
                }
                
                for i, step in enumerate(path.steps):
                    stage = {
                        'stage_number': i + 1,
                        'technique': step.technique_id,
                        'exploit': step.exploit_used,
                        'source': step.source_asset,
                        'target': step.target_asset,
                        'privilege_gained': step.privilege_gained,
                        'impact': step.impact
                    }
                    kill_chain['stages'].append(stage)
                
                kill_chains.append(kill_chain)
        
        return kill_chains
    
    def _create_zero_day_map(self, assets: List[Asset], indicators: List[ZeroDayIndicator]) -> Dict[str, Any]:
        """Create zero-day exposure heatmap data"""
        
        zd_map = {
            'high_exposure_assets': [],
            'indicators_by_type': defaultdict(int),
            'indicators_by_severity': defaultdict(int)
        }
        
        # Count indicators by type and severity
        for indicator in indicators:
            zd_map['indicators_by_type'][indicator.indicator_type] += 1
            zd_map['indicators_by_severity'][indicator.severity] += 1
        
        # Identify high-exposure assets
        threshold = config.get('zero_day.zdes_threshold', 70)
        
        for asset in assets:
            if asset.zdes_score >= threshold:
                zd_map['high_exposure_assets'].append({
                    'asset_id': asset.asset_id,
                    'hostname': asset.hostname,
                    'ip_address': asset.ip_address,
                    'zdes_score': asset.zdes_score
                })
        
        # Convert defaultdicts to regular dicts
        zd_map['indicators_by_type'] = dict(zd_map['indicators_by_type'])
        zd_map['indicators_by_severity'] = dict(zd_map['indicators_by_severity'])
        
        return zd_map
    
    def _calculate_network_risk(self, asset_risks: Dict[str, Dict[str, Any]], 
                                attack_paths: List[AttackPath]) -> float:
        """Calculate overall network risk score"""
        
        if not asset_risks:
            return 0.0
        
        # Average asset risk
        avg_asset_risk = np.mean([a['risk_score'] for a in asset_risks.values()])
        
        # Path complexity factor
        if attack_paths:
            avg_exploitability = np.mean([p.exploitability_score for p in attack_paths])
            path_factor = avg_exploitability / 100
        else:
            path_factor = 0
        
        # Network risk = weighted combination
        network_risk = (avg_asset_risk * 0.7) + (path_factor * 100 * 0.3)
        
        return min(100.0, network_risk)
