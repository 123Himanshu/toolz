"""
Attack path generator
Generates simple and chained attack paths through the network
"""
import networkx as nx
from typing import List, Dict, Any, Tuple
from models.schemas import AttackPath, AttackPathStep, NormalizedVulnerability
from utils.logger import engine_logger
from utils.config import config
import uuid

class AttackPathGenerator:
    """Generates attack paths from the attack graph"""
    
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
        self.logger = engine_logger
        self.max_path_length = config.get('attack_graph.max_path_length', 5)
    
    def generate_all_paths(self) -> List[AttackPath]:
        """Generate all possible attack paths"""
        
        self.logger.info("Generating attack paths")
        
        paths = []
        
        # Get entry points and targets
        entry_points = self._get_entry_points()
        targets = self._get_high_value_targets()
        
        self.logger.info(f"Found {len(entry_points)} entry points and {len(targets)} targets")
        
        # Generate paths from each entry point to each target
        for entry in entry_points:
            for target in targets:
                if entry == target:
                    continue
                
                # Find all simple paths
                try:
                    simple_paths = list(nx.all_simple_paths(
                        self.graph, entry, target, cutoff=self.max_path_length
                    ))
                    
                    for path_nodes in simple_paths:
                        attack_path = self._create_attack_path(path_nodes, entry, target)
                        if attack_path:
                            paths.append(attack_path)
                
                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    self.logger.error(f"Error generating path from {entry} to {target}: {e}")
        
        # Sort paths by exploitability score (descending)
        paths.sort(key=lambda p: p.exploitability_score, reverse=True)
        
        self.logger.info(f"Generated {len(paths)} attack paths")
        
        return paths
    
    def generate_shortest_paths(self) -> List[AttackPath]:
        """Generate shortest attack paths"""
        
        paths = []
        entry_points = self._get_entry_points()
        targets = self._get_high_value_targets()
        
        for entry in entry_points:
            for target in targets:
                if entry == target:
                    continue
                
                try:
                    # Find shortest path by weight
                    path_nodes = nx.shortest_path(self.graph, entry, target, weight='weight')
                    attack_path = self._create_attack_path(path_nodes, entry, target)
                    if attack_path:
                        paths.append(attack_path)
                
                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    self.logger.error(f"Error finding shortest path: {e}")
        
        return paths
    
    def generate_highest_impact_paths(self, top_n: int = 10) -> List[AttackPath]:
        """Generate highest impact attack paths"""
        
        all_paths = self.generate_all_paths()
        
        # Sort by total impact
        all_paths.sort(key=lambda p: p.total_impact, reverse=True)
        
        return all_paths[:top_n]
    
    def generate_most_probable_paths(self, top_n: int = 10) -> List[AttackPath]:
        """Generate most probable attack paths based on exploitability"""
        
        all_paths = self.generate_all_paths()
        
        # Sort by exploitability score
        all_paths.sort(key=lambda p: p.exploitability_score, reverse=True)
        
        return all_paths[:top_n]
    
    def _get_entry_points(self) -> List[str]:
        """Get attack entry points"""
        
        entry_points = ['ATTACKER']  # External attacker node
        
        # Add externally accessible assets
        for node, attrs in self.graph.nodes(data=True):
            if attrs.get('is_external', False):
                entry_points.append(node)
        
        return entry_points
    
    def _get_high_value_targets(self) -> List[str]:
        """Get high-value target nodes"""
        
        targets = []
        
        for node, attrs in self.graph.nodes(data=True):
            if attrs.get('type') == 'asset':
                # Consider high-value if high CVSS or many vulns
                if attrs.get('max_cvss', 0) >= 7.0:
                    targets.append(node)
            
            # Include SYSTEM privilege nodes as targets
            if attrs.get('type') == 'privilege' and attrs.get('level') == 'SYSTEM':
                targets.append(node)
        
        return targets
    
    def _create_attack_path(self, path_nodes: List[str], entry: str, target: str) -> AttackPath:
        """Create AttackPath object from node list"""
        
        if len(path_nodes) < 2:
            return None
        
        steps = []
        total_complexity = 0
        total_impact = 0
        
        # Create steps from edges
        for i in range(len(path_nodes) - 1):
            source = path_nodes[i]
            dest = path_nodes[i + 1]
            
            # Get edge data
            edge_data = self.graph.get_edge_data(source, dest)
            
            if not edge_data:
                continue
            
            # Create attack step
            step = self._create_attack_step(source, dest, edge_data)
            if step:
                steps.append(step)
                total_complexity += step.complexity
                
                # Calculate impact score
                impact_score = self._calculate_impact_score(edge_data)
                total_impact += impact_score
        
        if not steps:
            return None
        
        # Calculate exploitability score
        exploitability = self._calculate_exploitability(steps)
        
        # Determine path type
        path_type = 'chained' if len(steps) > 1 else 'simple'
        
        attack_path = AttackPath(
            path_id=str(uuid.uuid4()),
            steps=steps,
            total_complexity=total_complexity,
            total_impact=total_impact,
            exploitability_score=exploitability,
            path_type=path_type,
            entry_point=entry,
            target=target
        )
        
        return attack_path
    
    def _create_attack_step(self, source: str, target: str, edge_data: Dict[str, Any]) -> AttackPathStep:
        """Create AttackPathStep from edge data"""
        
        # Create a minimal vulnerability object for the step
        vuln = NormalizedVulnerability(
            asset_id=target,
            cve_id=edge_data.get('cve_id'),
            cvss_score=edge_data.get('cvss_score'),
            service_name=edge_data.get('service'),
            port=edge_data.get('port'),
            scanner_source='AttackGraph'
        )
        
        step = AttackPathStep(
            source_asset=source,
            target_asset=target,
            vulnerability=vuln,
            exploit_used=edge_data.get('cve_id', edge_data.get('type', 'Unknown')),
            privilege_gained=edge_data.get('privilege_gained', 'USER'),
            technique_id=', '.join(edge_data.get('mitre_techniques', [])) if edge_data.get('mitre_techniques') else 'Unknown',
            impact=edge_data.get('impact', 'MEDIUM'),
            complexity=edge_data.get('weight', 5.0)
        )
        
        return step
    
    def _calculate_impact_score(self, edge_data: Dict[str, Any]) -> float:
        """Calculate impact score for an edge"""
        
        impact_map = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 1.0
        }
        
        impact = edge_data.get('impact', 'MEDIUM')
        return impact_map.get(impact, 5.0)
    
    def _calculate_exploitability(self, steps: List[AttackPathStep]) -> float:
        """
        Calculate overall exploitability score for a path
        Based on EPSS scores, exploit availability, and complexity
        """
        
        if not steps:
            return 0.0
        
        # Factors that increase exploitability
        exploit_factors = []
        
        for step in steps:
            vuln = step.vulnerability
            
            # EPSS score (0-1)
            if vuln.epss_score:
                exploit_factors.append(vuln.epss_score * 100)
            
            # Exploit availability
            if vuln.exploit_available:
                exploit_factors.append(80)
            
            # CVSS score (0-10)
            if vuln.cvss_score:
                exploit_factors.append(vuln.cvss_score * 10)
            
            # Complexity (inverse - lower complexity = higher exploitability)
            complexity_score = max(0, 100 - (step.complexity * 10))
            exploit_factors.append(complexity_score)
        
        # Average exploitability
        if exploit_factors:
            return sum(exploit_factors) / len(exploit_factors)
        
        return 50.0  # Default medium exploitability
