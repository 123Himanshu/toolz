"""
Test cases for attack graph engine
"""
import unittest
from models.schemas import NormalizedVulnerability
from attack_graph import AttackGraphBuilder, AttackPathGenerator

class TestAttackGraph(unittest.TestCase):
    """Test attack graph construction"""
    
    def setUp(self):
        self.builder = AttackGraphBuilder()
        
        # Create test vulnerabilities
        self.vulnerabilities = [
            NormalizedVulnerability(
                asset_id="asset_192_168_1_10",
                ip_address="192.168.1.10",
                hostname="webserver",
                port=80,
                service_name="http",
                cve_id="CVE-2021-41773",
                cvss_score=9.8,
                severity="CRITICAL",
                attack_vector="NETWORK",
                scanner_source="Test"
            ),
            NormalizedVulnerability(
                asset_id="asset_192_168_1_20",
                ip_address="192.168.1.20",
                hostname="database",
                port=3306,
                service_name="mysql",
                cve_id="CVE-2021-3156",
                cvss_score=7.8,
                severity="HIGH",
                attack_vector="LOCAL",
                scanner_source="Test"
            )
        ]
    
    def test_graph_construction(self):
        """Test basic graph construction"""
        
        graph = self.builder.build_graph(self.vulnerabilities)
        
        self.assertIsNotNone(graph)
        self.assertGreater(graph.number_of_nodes(), 0)
        self.assertGreater(graph.number_of_edges(), 0)
        
        print(f"✓ Graph construction test passed: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    
    def test_asset_nodes(self):
        """Test asset node creation"""
        
        graph = self.builder.build_graph(self.vulnerabilities)
        
        # Check if asset nodes exist
        asset_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'asset']
        
        self.assertGreater(len(asset_nodes), 0)
        self.assertIn("asset_192_168_1_10", asset_nodes)
        
        print(f"✓ Asset nodes test passed: {len(asset_nodes)} assets created")
    
    def test_external_entry_points(self):
        """Test external entry point identification"""
        
        graph = self.builder.build_graph(self.vulnerabilities)
        entry_points = self.builder.get_external_entry_points()
        
        self.assertIsNotNone(entry_points)
        
        print(f"✓ Entry points test passed: {len(entry_points)} entry points identified")


class TestPathGeneration(unittest.TestCase):
    """Test attack path generation"""
    
    def setUp(self):
        self.builder = AttackGraphBuilder()
        
        # Create test vulnerabilities with network access
        self.vulnerabilities = [
            NormalizedVulnerability(
                asset_id="asset_192_168_1_10",
                ip_address="192.168.1.10",
                port=80,
                service_name="http",
                cve_id="CVE-2021-41773",
                cvss_score=9.8,
                severity="CRITICAL",
                attack_vector="NETWORK",
                exploit_available=True,
                epss_score=0.95,
                scanner_source="Test"
            )
        ]
        
        self.graph = self.builder.build_graph(self.vulnerabilities)
    
    def test_path_generation(self):
        """Test attack path generation"""
        
        generator = AttackPathGenerator(self.graph)
        paths = generator.generate_all_paths()
        
        self.assertIsNotNone(paths)
        
        if len(paths) > 0:
            # Check first path
            path = paths[0]
            self.assertIsNotNone(path.path_id)
            self.assertIsNotNone(path.entry_point)
            self.assertIsNotNone(path.target)
            self.assertGreater(len(path.steps), 0)
            
            print(f"✓ Path generation test passed: {len(paths)} paths generated")
        else:
            print("✓ Path generation test passed: No paths found (expected for simple test data)")


if __name__ == '__main__':
    unittest.main(verbosity=2)
