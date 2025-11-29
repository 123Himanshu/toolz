"""
Test cases for scanner parsers
"""
import unittest
import tempfile
import os
from ingestors import NmapParser, NucleiParser, TrivyParser, RustScanParser

class TestNmapParser(unittest.TestCase):
    """Test Nmap parser"""
    
    def setUp(self):
        self.parser = NmapParser()
        self.test_xml = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <hostnames>
            <hostname name="testhost.local"/>
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
</nmaprun>
"""
    
    def test_parse_nmap_xml(self):
        """Test parsing Nmap XML"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(self.test_xml)
            temp_file = f.name
        
        try:
            vulns = self.parser.parse(temp_file)
            
            self.assertIsNotNone(vulns)
            self.assertGreater(len(vulns), 0)
            
            # Check first vulnerability
            vuln = vulns[0]
            self.assertEqual(vuln.ip_address, "192.168.1.10")
            self.assertEqual(vuln.hostname, "testhost.local")
            self.assertIn(vuln.port, [80, 22])
            self.assertEqual(vuln.scanner_source, "Nmap")
            
            print(f"✓ Nmap parser test passed: {len(vulns)} vulnerabilities parsed")
            
        finally:
            os.unlink(temp_file)
    
    def test_invalid_file(self):
        """Test handling of invalid file"""
        vulns = self.parser.parse("nonexistent_file.xml")
        self.assertEqual(len(vulns), 0)
        print("✓ Nmap parser handles invalid files correctly")


class TestNucleiParser(unittest.TestCase):
    """Test Nuclei parser"""
    
    def setUp(self):
        self.parser = NucleiParser()
        self.test_json = """{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal","severity":"critical","classification":{"cve-id":["CVE-2021-41773"],"cvss-score":9.8,"cwe-id":["CWE-22"]}},"host":"http://192.168.1.10","matched-at":"http://192.168.1.10/cgi-bin/.%2e/etc/passwd"}
{"template-id":"sql-injection","info":{"name":"SQL Injection","severity":"high","classification":{"cvss-score":8.5,"cwe-id":["CWE-89"]}},"host":"http://192.168.1.10","matched-at":"http://192.168.1.10/login.php"}
"""
    
    def test_parse_nuclei_json(self):
        """Test parsing Nuclei JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(self.test_json)
            temp_file = f.name
        
        try:
            vulns = self.parser.parse(temp_file)
            
            self.assertIsNotNone(vulns)
            self.assertEqual(len(vulns), 2)
            
            # Check CVE finding
            cve_vuln = [v for v in vulns if v.cve_id == "CVE-2021-41773"][0]
            self.assertEqual(cve_vuln.severity, "CRITICAL")
            self.assertEqual(cve_vuln.cvss_score, 9.8)
            self.assertEqual(cve_vuln.cwe, "CWE-22")
            
            print(f"✓ Nuclei parser test passed: {len(vulns)} vulnerabilities parsed")
            
        finally:
            os.unlink(temp_file)


class TestTrivyParser(unittest.TestCase):
    """Test Trivy parser"""
    
    def setUp(self):
        self.parser = TrivyParser()
        self.test_json = """{
  "ArtifactName": "ubuntu:18.04",
  "Results": [
    {
      "Target": "ubuntu:18.04",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-3156",
          "PkgName": "sudo",
          "InstalledVersion": "1.8.21p2-3ubuntu1",
          "FixedVersion": "1.8.21p2-3ubuntu1.4",
          "Severity": "HIGH",
          "CVSS": {"nvd": {"V3Score": 7.8}},
          "CweIDs": ["CWE-787"]
        }
      ]
    }
  ]
}"""
    
    def test_parse_trivy_json(self):
        """Test parsing Trivy JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(self.test_json)
            temp_file = f.name
        
        try:
            vulns = self.parser.parse(temp_file)
            
            self.assertIsNotNone(vulns)
            self.assertGreater(len(vulns), 0)
            
            vuln = vulns[0]
            self.assertEqual(vuln.cve_id, "CVE-2021-3156")
            self.assertEqual(vuln.service_name, "sudo")
            self.assertEqual(vuln.severity, "HIGH")
            self.assertTrue(vuln.patch_available)
            
            print(f"✓ Trivy parser test passed: {len(vulns)} vulnerabilities parsed")
            
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main(verbosity=2)
