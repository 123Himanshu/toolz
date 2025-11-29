"""
Test cases for normalization pipeline
"""
import unittest
from datetime import datetime
from models.schemas import NormalizedVulnerability
from normalizer import VulnerabilityNormalizer

class TestNormalizer(unittest.TestCase):
    """Test vulnerability normalizer"""
    
    def setUp(self):
        self.normalizer = VulnerabilityNormalizer()
    
    def test_deduplication(self):
        """Test deduplication of identical vulnerabilities"""
        
        # Create duplicate vulnerabilities
        vuln1 = NormalizedVulnerability(
            asset_id="asset_192_168_1_10",
            ip_address="192.168.1.10",
            port=80,
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            scanner_source="Nmap"
        )
        
        vuln2 = NormalizedVulnerability(
            asset_id="asset_192_168_1_10",
            ip_address="192.168.1.10",
            port=80,
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            scanner_source="Nuclei"
        )
        
        vulns = [vuln1, vuln2]
        normalized = self.normalizer.normalize(vulns)
        
        # Should merge into one
        self.assertEqual(len(normalized), 1)
        
        # Should combine scanner sources
        self.assertIn("Nmap", normalized[0].scanner_source)
        self.assertIn("Nuclei", normalized[0].scanner_source)
        
        print(f"✓ Deduplication test passed: {len(vulns)} → {len(normalized)}")
    
    def test_conflict_resolution(self):
        """Test conflict resolution (take highest CVSS)"""
        
        vuln1 = NormalizedVulnerability(
            asset_id="asset_192_168_1_10",
            ip_address="192.168.1.10",
            port=80,
            cve_id="CVE-2021-41773",
            cvss_score=7.5,
            severity="HIGH",
            scanner_source="Scanner1"
        )
        
        vuln2 = NormalizedVulnerability(
            asset_id="asset_192_168_1_10",
            ip_address="192.168.1.10",
            port=80,
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            severity="CRITICAL",
            scanner_source="Scanner2"
        )
        
        vulns = [vuln1, vuln2]
        normalized = self.normalizer.normalize(vulns)
        
        # Should take highest CVSS
        self.assertEqual(normalized[0].cvss_score, 9.8)
        self.assertEqual(normalized[0].severity, "CRITICAL")
        
        print("✓ Conflict resolution test passed: highest CVSS selected")
    
    def test_cve_deduplication(self):
        """Test CVE-based deduplication"""
        
        vuln1 = NormalizedVulnerability(
            asset_id="asset_192_168_1_10",
            ip_address="192.168.1.10",
            port=80,
            cve_id="CVE-2021-41773",
            scanner_source="Scanner1"
        )
        
        vuln2 = NormalizedVulnerability(
            asset_id="asset_192_168_1_10",
            ip_address="192.168.1.10",
            port=443,  # Different port
            cve_id="CVE-2021-41773",  # Same CVE
            scanner_source="Scanner2"
        )
        
        vulns = [vuln1, vuln2]
        deduplicated = self.normalizer.deduplicate_by_cve(vulns)
        
        # Should merge same CVE on same asset
        self.assertEqual(len(deduplicated), 1)
        
        print("✓ CVE deduplication test passed")


if __name__ == '__main__':
    unittest.main(verbosity=2)
