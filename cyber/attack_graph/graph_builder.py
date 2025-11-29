"""
Attack graph builder using NetworkX
Constructs a directed graph representing possible attack paths
"""
import networkx as nx
from typing import List, Dict, Any
from collections import defaultdict
from models.schemas import NormalizedVulnerability, Asset
from attack_graph.edge_rules import EdgeRuleEngine
from utils.logger import engine_logger
from utils.config import config

class AttackGraphBuilder:
    """Builds attack graph from normalized vulnerabilities"""
    
    def __init__(self):
        self.logger = engine_logger
        self.edge_engine = EdgeRuleEngine()
        self.graph = nx.DiGraph()
        self.assets = {}
    
    def build_graph(self, vulnerabilities: List[NormalizedVulnerability]) -> nx.DiGraph:
        """Build complete attack graph"""
        
        self.logger.info(f"Building attack graph from {len(vulnerabilities)} vulnerabilities")
        
        # Group vulnerabilities by asset
        asset_vulns = self._group_by_asset(vulnerabilities)
        
        # Create asset nodes
        self._create_asset_nodes(asset_vulns)
        
        # Add vulnerability edges
        self._add_vulnerability_edges(vulnerabilities)
        
        # Add reachability edges
        self._add_reachability_edges()
        
        # Add privilege escalation paths
        self._add_privilege_escalation_edges()
        
        # Add lateral movement edges
        self._add_lateral_movement_edges()
        
        self.logger.info(f"Attack graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        
        return self.graph
    
    def _group_by_asset(self, vulnerabilities: List[NormalizedVulnerability]) -> Dict[str, List[NormalizedVulnerability]]:
        """Group vulnerabilities by asset"""
        
        grouped = defaultdict(list)
        for vuln in vulnerabilities:
            grouped[vuln.asset_id].append(vuln)
        return grouped
    
    def _create_asset_nodes(self, asset_vulns: Dict[str, List[NormalizedVulnerability]]):
        """Create nodes for each asset"""
        
        for asset_id, vulns in asset_vulns.items():
            # Get asset info from first vulnerability
            first_vuln = vulns[0]
            
            # Determine if asset is externally accessible
            is_external = self._is_external_asset(vulns)
            
            # Calculate aggregate risk
            max_cvss = max([v.cvss_score for v in vulns if v.cvss_score], default=0)
            
            node_attrs = {
                'type': 'asset',
                'asset_id': asset_id,
                'hostname': first_vuln.hostname,
                'ip_address': first_vuln.ip_address,
                'os': first_vuln.os,
                'is_external': is_external,
                'vuln_count': len(vulns),
                'max_cvss': max_cvss,
                'services': list(set([v.service_name for v in vulns if v.service_name]))
            }
            
            self.graph.add_node(asset_id, **node_attrs)
            self.assets[asset_id] = node_attrs
    
    def _is_external_asset(self, vulns: List[NormalizedVulnerability]) -> bool:
        """Determine if asset is externally accessible"""
        
        # Check if any vulnerability has network attack vector
        for vuln in vulns:
            if vuln.attack_vector == 'NETWORK':
                return True
            
            # Check for common external services
            if vuln.service_name in ['http', 'https', 'ssh', 'ftp', 'smtp']:
                if vuln.port in [80, 443, 22, 21, 25]:
                    return True
        
        return False
    
    def _add_vulnerability_edges(self, vulnerabilities: List[NormalizedVulnerability]):
        """Add edges for each vulnerability"""
        
        for vuln in vulnerabilities:
            # Skip if no exploitable vulnerability
            min_cvss = config.get('attack_graph.min_cvss_threshold', 4.0)
            if vuln.cvss_score and vuln.cvss_score < min_cvss:
                continue
            
            # Create edge attributes
            edge_attrs = self.edge_engine.create_vulnerability_edge(vuln)
            
            # Determine source and target
            # For network vulnerabilities, source is "INTERNET" or "ATTACKER"
            if vuln.attack_vector == 'NETWORK' and self._is_external_asset([vuln]):
                source = 'ATTACKER'
                target = vuln.asset_id
            else:
                # For local vulnerabilities, we'll handle in privilege escalation
                continue
            
            # Add edge
            self.graph.add_edge(source, target, **edge_attrs)
    
    def _add_reachability_edges(self):
        """Add network reachability edges between assets"""
        
        # Simple heuristic: assets in same subnet can reach each other
        # Group by network segment (first 3 octets of IP)
        
        segments = defaultdict(list)
        
        for asset_id, attrs in self.assets.items():
            ip = attrs.get('ip_address')
            if ip:
                # Extract network segment (e.g., 192.168.1.x -> 192.168.1)
                parts = ip.split('.')
                if len(parts) == 4:
                    segment = '.'.join(parts[:3])
                    segments[segment].append(asset_id)
        
        # Add reachability edges within segments
        for segment, asset_list in segments.items():
            for i, source in enumerate(asset_list):
                for target in asset_list[i+1:]:
                    # Bidirectional reachability
                    edge_attrs = self.edge_engine.create_reachability_edge(segment, segment, True)
                    self.graph.add_edge(source, target, **edge_attrs)
                    self.graph.add_edge(target, source, **edge_attrs)
    
    def _add_privilege_escalation_edges(self):
        """Add privilege escalation edges within assets"""
        
        # For each asset, create privilege levels
        for asset_id in self.assets.keys():
            # Create privilege level nodes
            user_node = f"{asset_id}_USER"
            admin_node = f"{asset_id}_ADMIN"
            system_node = f"{asset_id}_SYSTEM"
            
            # Add privilege nodes
            self.graph.add_node(user_node, type='privilege', level='USER', asset=asset_id)
            self.graph.add_node(admin_node, type='privilege', level='ADMIN', asset=asset_id)
            self.graph.add_node(system_node, type='privilege', level='SYSTEM', asset=asset_id)
            
            # Connect asset to user level (initial access)
            self.graph.add_edge(asset_id, user_node, type='INITIAL_ACCESS', weight=0.1)
            
            # Add escalation edges based on vulnerabilities
            # This would be populated from actual LPE vulnerabilities
            # For now, add potential escalation paths
            self.graph.add_edge(user_node, admin_node, type='PRIV_ESC', weight=5.0)
            self.graph.add_edge(admin_node, system_node, type='PRIV_ESC', weight=3.0)
    
    def _add_lateral_movement_edges(self):
        """Add lateral movement edges between assets"""
        
        # Add edges for common lateral movement techniques
        for source_asset in self.assets.keys():
            source_attrs = self.assets[source_asset]
            
            for target_asset in self.assets.keys():
                if source_asset == target_asset:
                    continue
                
                target_attrs = self.assets[target_asset]
                
                # Check if lateral movement is possible
                # Based on services, network proximity, etc.
                
                # Example: If target has SMB, RDP, SSH services
                target_services = target_attrs.get('services', [])
                
                if any(svc in target_services for svc in ['smb', 'rdp', 'ssh', 'winrm']):
                    # Add lateral movement edge with credential reuse
                    edge_attrs = self.edge_engine.create_credential_edge('password', 'weak')
                    edge_attrs['type'] = 'LATERAL_MOVEMENT'
                    self.graph.add_edge(f"{source_asset}_SYSTEM", target_asset, **edge_attrs)
    
    def get_external_entry_points(self) -> List[str]:
        """Get list of externally accessible assets"""
        
        entry_points = []
        for node, attrs in self.graph.nodes(data=True):
            if attrs.get('is_external', False):
                entry_points.append(node)
        
        return entry_points
    
    def get_critical_assets(self) -> List[str]:
        """Identify critical assets (high value targets)"""
        
        critical = []
        for node, attrs in self.graph.nodes(data=True):
            if attrs.get('type') == 'asset':
                # Consider critical if high CVSS or many vulnerabilities
                if attrs.get('max_cvss', 0) >= 9.0 or attrs.get('vuln_count', 0) >= 10:
                    critical.append(node)
        
        return critical
