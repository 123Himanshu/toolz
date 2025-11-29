"""
Integration tests for complete workflow
"""
import unittest
import tempfile
import os
from main import AttackPathEngine

class TestIntegration(unittest.TestCase):
    """Test complete workflow integration"""
    
    def setUp(self):
        self.engine = AttackPathEngine()
        
        # Create test Nmap file
        self.nmap_xml = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <hostnames>
            <hostname name="webserver.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.6"/>
            </port>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="7.4"/>
            </port>
        </ports>
        <os>
            <osmatch name="Linux 3.X"/>
        </os>
    </host>
    <host>
        <address addr="192.168.1.20" addrtype="ipv4"/>
        <hostnames>
            <hostname name="database.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="3306">
                <state state="open"/>
                <service name="mysql" product="MySQL" version="5.7"/>
            </port>
        </ports>
    </host>
</nmaprun>
"""
    
    def test_complete_workflow(self):
        """Test complete analysis workflow"""
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(self.nmap_xml)
            temp_file = f.name
        
        try:
            # Run analysis
            scan_files = {'nmap': temp_file}
            results = self.engine.run(scan_files, output_formats=['json'])
            
            # Verify results structure
            self.assertIsNotNone(results)
            self.assertIn('network_risk_score', results)
            self.assertIn('total_vulnerabilities', results)
            self.assertIn('total_assets', results)
            self.assertIn('asset_risks', results)
            
            # Verify data
            self.assertGreaterEqual(results['network_risk_score'], 0)
            self.assertLessEqual(results['network_risk_score'], 100)
            self.assertGreater(results['total_assets'], 0)
            
            print("\n" + "="*60)
            print("INTEGRATION TEST RESULTS")
            print("="*60)
            print(f"Network Risk Score: {results['network_risk_score']:.1f}/100")
            print(f"Total Vulnerabilities: {results['total_vulnerabilities']}")
            print(f"Total Assets: {results['total_assets']}")
            print(f"Total Attack Paths: {results['total_attack_paths']}")
            print(f"Zero-Day Indicators: {results['total_zero_day_indicators']}")
            print(f"High-Risk Assets: {len(results.get('high_risk_assets', []))}")
            print("="*60)
            print("✓ Complete workflow test PASSED")
            
        finally:
            os.unlink(temp_file)
    
    def test_multiple_scanners(self):
        """Test with multiple scanner inputs"""
        
        # Create Nmap file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(self.nmap_xml)
            nmap_file = f.name
        
        # Create Nuclei file
        nuclei_json = """{"template-id":"test-vuln","info":{"name":"Test Vulnerability","severity":"high","classification":{"cvss-score":7.5}},"host":"http://192.168.1.10","matched-at":"http://192.168.1.10/test"}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(nuclei_json)
            nuclei_file = f.name
        
        try:
            # Run with multiple scanners
            scan_files = {
                'nmap': nmap_file,
                'nuclei': nuclei_file
            }
            results = self.engine.run(scan_files, output_formats=['json'])
            
            self.assertIsNotNone(results)
            self.assertGreater(results['total_vulnerabilities'], 0)
            
            print("\n✓ Multiple scanner test PASSED")
            print(f"  Processed {len(scan_files)} scanner outputs")
            print(f"  Found {results['total_vulnerabilities']} total vulnerabilities")
            
        finally:
            os.unlink(nmap_file)
            os.unlink(nuclei_file)


if __name__ == '__main__':
    unittest.main(verbosity=2)
