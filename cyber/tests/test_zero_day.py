"""
Test cases for zero-day detection
"""
import unittest
from models.schemas import NormalizedVulnerability, Asset
from zero_day import ZDESCalculator, AnomalyDetector

class TestZDESCalculator(unittest.TestCase):
    """Test ZDES calculator"""
    
    def setUp(self):
        self.calculator = ZDESCalculator()
    
    def test_zdes_calculation(self):
        """Test ZDES score calculation"""
        
        asset = Asset(
            asset_id="asset_192_168_1_10",
            ip_address="192.168.1.10",
            hostname="testhost",
            os="Windows 7",  # EOL OS
            is_external=True
        )
        
        vulnerabilities = [
            NormalizedVulnerability(
                asset_id="asset_192_168_1_10",
                ip_address="192.168.1.10",
                port=80,
                service_name="unknown",  # Unknown service
                cve_id="CVE-2021-41773",
                cvss_score=9.8,
                patch_available=False,  # Unpatched
                scanner_source="Test"
            ),
            NormalizedVulnerability(
                asset_id="asset_192_168_1_10",
                ip_address="192.168.1.10",
                port=8080,
                service_name="http",  # Abnormal port
                scanner_source="Test"
            )
        ]
        
        zdes = self.calculator.calculate_zdes(asset, vulnerabilities)
        
        self.assertIsNotNone(zdes)
        self.assertGreaterEqual(zdes, 0)
        self.assertLessEqual(zdes, 100)
        
        # Should have high ZDES due to EOL OS, unknown service, etc.
        self.assertGreater(zdes, 30)
        
        print(f"✓ ZDES calculation test passed: Score = {zdes:.1f}")
    
    def test_low_zdes_score(self):
        """Test low ZDES score for well-configured asset"""
        
        asset = Asset(
            asset_id="asset_192_168_1_20",
            ip_address="192.168.1.20",
            hostname="secure-host",
            os="Ubuntu 22.04",  # Current OS
            is_external=False
        )
        
        vulnerabilities = [
            NormalizedVulnerability(
                asset_id="asset_192_168_1_20",
                ip_address="192.168.1.20",
                port=443,
                service_name="https",
                service_version="nginx 1.20",
                patch_available=True,
                scanner_source="Test"
            )
        ]
        
        zdes = self.calculator.calculate_zdes(asset, vulnerabilities)
        
        # Should have lower ZDES
        self.assertLess(zdes, 50)
        
        print(f"✓ Low ZDES test passed: Score = {zdes:.1f}")


class TestAnomalyDetector(unittest.TestCase):
    """Test anomaly detector"""
    
    def setUp(self):
        self.detector = AnomalyDetector(baseline_path='test_baseline.json')
    
    def test_baseline_creation(self):
        """Test baseline creation"""
        
        vulnerabilities = [
            NormalizedVulnerability(
                asset_id="asset_192_168_1_10",
                ip_address="192.168.1.10",
                port=80,
                service_name="http",
                scanner_source="Test"
            )
        ]
        
        # Should not raise exception
        try:
            self.detector.save_baseline(vulnerabilities)
            print("✓ Baseline creation test passed")
        except Exception as e:
            self.fail(f"Baseline creation failed: {e}")
    
    def test_anomaly_detection_no_baseline(self):
        """Test anomaly detection without baseline"""
        
        vulnerabilities = [
            NormalizedVulnerability(
                asset_id="asset_192_168_1_10",
                ip_address="192.168.1.10",
                port=80,
                service_name="http",
                scanner_source="Test"
            )
        ]
        
        # Should return empty list if no baseline
        anomalies = self.detector.detect_anomalies(vulnerabilities)
        
        self.assertIsNotNone(anomalies)
        self.assertIsInstance(anomalies, list)
        
        print(f"✓ Anomaly detection test passed: {len(anomalies)} anomalies detected")


if __name__ == '__main__':
    unittest.main(verbosity=2)
