"""
Attack Surface Anomaly Detection
Identifies deviations from baseline that may indicate zero-day activity
"""
from typing import List, Dict, Any
from models.schemas import NormalizedVulnerability, ZeroDayIndicator
from utils.logger import engine_logger
from collections import defaultdict
import json
from pathlib import Path

class AnomalyDetector:
    """Detect anomalies in attack surface that may indicate zero-day exposure"""
    
    def __init__(self, baseline_path: str = 'data/baseline.json'):
        self.logger = engine_logger
        self.baseline_path = baseline_path
        self.baseline = self._load_baseline()
    
    def _load_baseline(self) -> Dict[str, Any]:
        """Load baseline scan data"""
        
        baseline_file = Path(self.baseline_path)
        
        if baseline_file.exists():
            try:
                with open(baseline_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load baseline: {e}")
        
        return {}
    
    def save_baseline(self, vulnerabilities: List[NormalizedVulnerability]):
        """Save current scan as baseline"""
        
        baseline_data = self._create_baseline_data(vulnerabilities)
        
        try:
            Path(self.baseline_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.baseline_path, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            self.logger.info(f"Baseline saved to {self.baseline_path}")
        except Exception as e:
            self.logger.error(f"Failed to save baseline: {e}")
    
    def _create_baseline_data(self, vulnerabilities: List[NormalizedVulnerability]) -> Dict[str, Any]:
        """Create baseline data structure"""
        
        baseline = {
            'assets': {},
            'services': defaultdict(list),
            'ports': defaultdict(list)
        }
        
        for vuln in vulnerabilities:
            asset_id = vuln.asset_id
            
            if asset_id not in baseline['assets']:
                baseline['assets'][asset_id] = {
                    'hostname': vuln.hostname,
                    'ip_address': vuln.ip_address,
                    'ports': [],
                    'services': []
                }
            
            if vuln.port:
                if vuln.port not in baseline['assets'][asset_id]['ports']:
                    baseline['assets'][asset_id]['ports'].append(vuln.port)
            
            if vuln.service_name:
                service_key = f"{vuln.service_name}:{vuln.port}"
                if service_key not in baseline['assets'][asset_id]['services']:
                    baseline['assets'][asset_id]['services'].append(service_key)
        
        # Convert defaultdicts to regular dicts for JSON serialization
        baseline['services'] = dict(baseline['services'])
        baseline['ports'] = dict(baseline['ports'])
        
        return baseline
    
    def detect_anomalies(self, vulnerabilities: List[NormalizedVulnerability]) -> List[ZeroDayIndicator]:
        """Detect anomalies compared to baseline"""
        
        if not self.baseline:
            self.logger.warning("No baseline available for anomaly detection")
            return []
        
        indicators = []
        
        # Detect new ports
        indicators.extend(self._detect_new_ports(vulnerabilities))
        
        # Detect service changes
        indicators.extend(self._detect_service_changes(vulnerabilities))
        
        # Detect scanner disagreements
        indicators.extend(self._detect_scanner_disagreements(vulnerabilities))
        
        # Detect suspicious patterns
        indicators.extend(self._detect_suspicious_patterns(vulnerabilities))
        
        self.logger.info(f"Detected {len(indicators)} anomalies")
        
        return indicators
    
    def _detect_new_ports(self, vulnerabilities: List[NormalizedVulnerability]) -> List[ZeroDayIndicator]:
        """Detect newly opened ports"""
        
        indicators = []
        baseline_assets = self.baseline.get('assets', {})
        
        # Group current vulns by asset
        current_assets = defaultdict(list)
        for vuln in vulnerabilities:
            if vuln.port:
                current_assets[vuln.asset_id].append(vuln.port)
        
        # Compare with baseline
        for asset_id, current_ports in current_assets.items():
            if asset_id in baseline_assets:
                baseline_ports = set(baseline_assets[asset_id].get('ports', []))
                current_ports_set = set(current_ports)
                
                new_ports = current_ports_set - baseline_ports
                
                for port in new_ports:
                    indicators.append(ZeroDayIndicator(
                        asset_id=asset_id,
                        indicator_type='anomaly',
                        description=f'New port opened: {port}',
                        confidence=0.8,
                        severity='MEDIUM',
                        details={'port': port, 'type': 'new_port'}
                    ))
        
        return indicators
    
    def _detect_service_changes(self, vulnerabilities: List[NormalizedVulnerability]) -> List[ZeroDayIndicator]:
        """Detect service banner changes or mismatches"""
        
        indicators = []
        baseline_assets = self.baseline.get('assets', {})
        
        # Group current vulns by asset
        current_services = defaultdict(list)
        for vuln in vulnerabilities:
            if vuln.service_name and vuln.port:
                service_key = f"{vuln.service_name}:{vuln.port}"
                current_services[vuln.asset_id].append(service_key)
        
        # Compare with baseline
        for asset_id, services in current_services.items():
            if asset_id in baseline_assets:
                baseline_services = set(baseline_assets[asset_id].get('services', []))
                current_services_set = set(services)
                
                # Check for changed services on same ports
                for service in current_services_set:
                    if ':' in service:
                        service_name, port = service.split(':')
                        
                        # Check if port existed but with different service
                        for baseline_service in baseline_services:
                            if ':' in baseline_service:
                                baseline_name, baseline_port = baseline_service.split(':')
                                
                                if port == baseline_port and service_name != baseline_name:
                                    indicators.append(ZeroDayIndicator(
                                        asset_id=asset_id,
                                        indicator_type='anomaly',
                                        description=f'Service changed on port {port}: {baseline_name} -> {service_name}',
                                        confidence=0.7,
                                        severity='MEDIUM',
                                        details={
                                            'port': port,
                                            'old_service': baseline_name,
                                            'new_service': service_name
                                        }
                                    ))
        
        return indicators
    
    def _detect_scanner_disagreements(self, vulnerabilities: List[NormalizedVulnerability]) -> List[ZeroDayIndicator]:
        """Detect when different scanners report different services"""
        
        indicators = []
        
        # Group by asset and port
        port_services = defaultdict(lambda: defaultdict(set))
        
        for vuln in vulnerabilities:
            if vuln.port and vuln.service_name:
                key = f"{vuln.asset_id}:{vuln.port}"
                port_services[key]['services'].add(vuln.service_name)
                port_services[key]['scanners'].add(vuln.scanner_source)
        
        # Check for disagreements
        for key, data in port_services.items():
            services = data['services']
            scanners = data['scanners']
            
            # If multiple scanners report different services
            if len(services) > 1 and len(scanners) > 1:
                asset_id, port = key.split(':')
                
                indicators.append(ZeroDayIndicator(
                    asset_id=asset_id,
                    indicator_type='anomaly',
                    description=f'Scanner disagreement on port {port}: {", ".join(services)}',
                    confidence=0.6,
                    severity='LOW',
                    details={
                        'port': port,
                        'services': list(services),
                        'scanners': list(scanners)
                    }
                ))
        
        return indicators
    
    def _detect_suspicious_patterns(self, vulnerabilities: List[NormalizedVulnerability]) -> List[ZeroDayIndicator]:
        """Detect suspicious patterns that may indicate zero-day activity"""
        
        indicators = []
        
        # Pattern 1: High-value services with unknown versions
        for vuln in vulnerabilities:
            if vuln.service_name in ['ssh', 'rdp', 'smb', 'http', 'https']:
                if not vuln.service_version or vuln.service_version == '':
                    indicators.append(ZeroDayIndicator(
                        asset_id=vuln.asset_id,
                        indicator_type='anomaly',
                        description=f'High-value service with unknown version: {vuln.service_name} on port {vuln.port}',
                        confidence=0.5,
                        severity='MEDIUM',
                        details={'service': vuln.service_name, 'port': vuln.port}
                    ))
        
        # Pattern 2: Services on unusual high ports
        for vuln in vulnerabilities:
            if vuln.port and vuln.port > 49152:  # Dynamic/private port range
                if vuln.service_name and vuln.service_name not in ['unknown', 'unidentified']:
                    indicators.append(ZeroDayIndicator(
                        asset_id=vuln.asset_id,
                        indicator_type='anomaly',
                        description=f'Service on unusual high port: {vuln.service_name} on port {vuln.port}',
                        confidence=0.4,
                        severity='LOW',
                        details={'service': vuln.service_name, 'port': vuln.port}
                    ))
        
        return indicators
