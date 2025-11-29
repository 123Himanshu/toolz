"""
Unified data schemas for the Attack Path Intelligence Engine
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackVector(Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"

@dataclass
class NormalizedVulnerability:
    """Unified vulnerability schema across all scanners"""
    
    # Asset identification
    asset_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    
    # Service details
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    os: Optional[str] = None
    
    # Vulnerability details
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    cwe: Optional[str] = None
    misconfiguration: Optional[str] = None
    
    # Exploitability
    exploit_available: bool = False
    epss_score: Optional[float] = None
    attack_vector: Optional[str] = None
    privilege_required: Optional[str] = None
    network_reachability: Optional[str] = None
    
    # Metadata
    scanner_source: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # Enrichment data
    exploit_metadata: Dict[str, Any] = field(default_factory=dict)
    patch_available: bool = False
    mitre_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'asset_id': self.asset_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'port': self.port,
            'protocol': self.protocol,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'tech_stack': self.tech_stack,
            'os': self.os,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'cwe': self.cwe,
            'misconfiguration': self.misconfiguration,
            'exploit_available': self.exploit_available,
            'epss_score': self.epss_score,
            'attack_vector': self.attack_vector,
            'privilege_required': self.privilege_required,
            'network_reachability': self.network_reachability,
            'scanner_source': self.scanner_source,
            'timestamp': self.timestamp.isoformat(),
            'exploit_metadata': self.exploit_metadata,
            'patch_available': self.patch_available,
            'mitre_techniques': self.mitre_techniques
        }

@dataclass
class Asset:
    """Asset representation in the attack graph"""
    
    asset_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    network_segment: Optional[str] = None
    is_external: bool = False
    services: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[NormalizedVulnerability] = field(default_factory=list)
    zdes_score: float = 0.0
    risk_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'asset_id': self.asset_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os': self.os,
            'network_segment': self.network_segment,
            'is_external': self.is_external,
            'services': self.services,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'zdes_score': self.zdes_score,
            'risk_score': self.risk_score
        }

@dataclass
class AttackPathStep:
    """Single step in an attack path"""
    
    source_asset: str
    target_asset: str
    vulnerability: NormalizedVulnerability
    exploit_used: str
    privilege_gained: str
    technique_id: str
    impact: str
    complexity: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'source_asset': self.source_asset,
            'target_asset': self.target_asset,
            'vulnerability': self.vulnerability.to_dict(),
            'exploit_used': self.exploit_used,
            'privilege_gained': self.privilege_gained,
            'technique_id': self.technique_id,
            'impact': self.impact,
            'complexity': self.complexity
        }

@dataclass
class AttackPath:
    """Complete attack path (simple or chained)"""
    
    path_id: str
    steps: List[AttackPathStep]
    total_complexity: float
    total_impact: float
    exploitability_score: float
    path_type: str  # 'simple' or 'chained'
    entry_point: str
    target: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'path_id': self.path_id,
            'steps': [step.to_dict() for step in self.steps],
            'total_complexity': self.total_complexity,
            'total_impact': self.total_impact,
            'exploitability_score': self.exploitability_score,
            'path_type': self.path_type,
            'entry_point': self.entry_point,
            'target': self.target
        }

@dataclass
class ZeroDayIndicator:
    """Zero-day exposure indicator"""
    
    asset_id: str
    indicator_type: str  # 'exposure', 'anomaly', 'behavior'
    description: str
    confidence: float
    severity: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'asset_id': self.asset_id,
            'indicator_type': self.indicator_type,
            'description': self.description,
            'confidence': self.confidence,
            'severity': self.severity,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }
