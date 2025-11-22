#!/usr/bin/env python3
"""
Complete Docker Integration Test
Tests all tools inside Docker container
"""

import subprocess
import sys
import json
from datetime import datetime

class DockerToolTester:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": [],
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0
            }
        }
    
    def test_tool(self, name, command, description):
        """Test if a tool is working"""
        print(f"\n{'='*70}")
        print(f"Testing: {name}")
        print(f"Description: {description}")
        print(f"Command: {' '.join(command)}")
        print(f"{'='*70}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0
            status = "✅ PASSED" if success else "❌ FAILED"
            
            print(f"Status: {status}")
            if success:
                print(f"Output: {result.stdout[:200]}")
            else:
                print(f"Error: {result.stderr[:200]}")
            
            self.results["tests"].append({
                "name": name,
                "description": description,
                "command": " ".join(command),
                "status": "passed" if success else "failed",
                "returncode": result.returncode,
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:500]
            })
            
            self.results["summary"]["total"] += 1
            if success:
                self.results["summary"]["passed"] += 1
            else:
                self.results["summary"]["failed"] += 1
            
            return success
            
        except subprocess.TimeoutExpired:
            print("❌ TIMEOUT")
            self.results["tests"].append({
                "name": name,
                "status": "timeout"
            })
            self.results["summary"]["total"] += 1
            self.results["summary"]["failed"] += 1
            return False
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            self.results["tests"].append({
                "name": name,
                "status": "error",
                "error": str(e)
            })
            self.results["summary"]["total"] += 1
            self.results["summary"]["failed"] += 1
            return False
    
    def test_python_module(self, name, module_name, description):
        """Test if a Python module can be imported"""
        print(f"\n{'='*70}")
        print(f"Testing: {name}")
        print(f"Description: {description}")
        print(f"Module: {module_name}")
        print(f"{'='*70}")
        
        try:
            __import__(module_name)
            print("✅ PASSED - Module imported successfully")
            
            self.results["tests"].append({
                "name": name,
                "description": description,
                "module": module_name,
                "status": "passed"
            })
            
            self.results["summary"]["total"] += 1
            self.results["summary"]["passed"] += 1
            return True
            
        except ImportError as e:
            print(f"❌ FAILED - Import error: {str(e)}")
            
            self.results["tests"].append({
                "name": name,
                "module": module_name,
                "status": "failed",
                "error": str(e)
            })
            
            self.results["summary"]["total"] += 1
            self.results["summary"]["failed"] += 1
            return False
    
    def run_all_tests(self):
        """Run all tool tests"""
        print("\n" + "="*70)
        print("🔒 COMPLETE DOCKER INTEGRATION TEST")
        print("="*70)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        
        # Test command-line tools
        tools = [
            ("Nuclei", ["nuclei", "-version"], "Template-based vulnerability scanner"),
            ("Jaeles", ["jaeles", "version"], "Signature-based web scanner"),
            ("Wapiti", ["wapiti", "--version"], "Web application scanner"),
            ("Nmap", ["nmap", "--version"], "Network scanner"),
            ("Masscan", ["masscan", "--version"], "High-speed IP scanner"),
            ("Subfinder", ["subfinder", "-version"], "Subdomain enumeration tool"),
            ("Naabu", ["naabu", "-version"], "Port scanning tool"),
            ("Httpx", ["httpx", "-version"], "HTTP probe tool"),
            ("Python", ["python", "--version"], "Python interpreter"),
            ("Pip", ["pip", "--version"], "Python package manager"),
        ]
        
        print("\n" + "="*70)
        print("TESTING COMMAND-LINE TOOLS")
        print("="*70)
        
        for name, command, description in tools:
            self.test_tool(name, command, description)
        
        # Test Python modules
        print("\n" + "="*70)
        print("TESTING PYTHON MODULES")
        print("="*70)
        
        modules = [
            ("Requests", "requests", "HTTP library"),
            ("DNSPython", "dns.resolver", "DNS toolkit"),
            ("Python-Whois", "whois", "WHOIS library"),
            ("urllib3", "urllib3", "HTTP client"),
            ("Docker SDK", "docker", "Docker Python SDK"),
        ]
        
        for name, module, description in modules:
            self.test_python_module(name, module, description)
        
        # Test scanner modules
        print("\n" + "="*70)
        print("TESTING SCANNER MODULES")
        print("="*70)
        
        scanner_modules = [
            ("Nuclei Scanner", "nuclei_scanner", "Nuclei Python wrapper"),
            ("Jaeles Scanner", "jaeles_scanner", "Jaeles Python wrapper"),
            ("Wapiti Scanner", "wapiti_scanner", "Wapiti Python wrapper"),
            ("ZAP Scanner", "zap_scanner", "ZAP Python wrapper"),
            ("Nikto Scanner", "nikto_scanner", "Nikto Python wrapper"),
            ("Unified Scanner", "unified_scanner", "Unified scanner interface"),
            ("Passive Recon", "passive_recon", "Passive reconnaissance"),
            ("Passive Recon v2", "passive_recon_v2", "Enhanced passive recon"),
        ]
        
        for name, module, description in scanner_modules:
            self.test_python_module(name, module, description)
        
        # Print summary
        self.print_summary()
        
        # Save results
        self.save_results()
        
        return self.results["summary"]["failed"] == 0
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*70)
        print("📊 TEST SUMMARY")
        print("="*70)
        
        total = self.results["summary"]["total"]
        passed = self.results["summary"]["passed"]
        failed = self.results["summary"]["failed"]
        
        print(f"Total Tests:  {total}")
        print(f"✅ Passed:    {passed}")
        print(f"❌ Failed:    {failed}")
        print(f"Success Rate: {(passed/total*100):.1f}%")
        
        print("\n" + "="*70)
        print("DETAILED RESULTS")
        print("="*70)
        
        for test in self.results["tests"]:
            status_icon = "✅" if test["status"] == "passed" else "❌"
            print(f"{status_icon} {test['name']:30} {test['status'].upper()}")
        
        print("\n" + "="*70)
        print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
    
    def save_results(self):
        """Save results to JSON file"""
        try:
            with open('/scanner/test_results.json', 'w') as f:
                json.dump(self.results, f, indent=2)
            print("\n📄 Results saved to: /scanner/test_results.json")
        except Exception as e:
            print(f"\n⚠️  Could not save results: {str(e)}")


def main():
    """Main test function"""
    tester = DockerToolTester()
    success = tester.run_all_tests()
    
    if success:
        print("\n🎉 ALL TESTS PASSED! Docker image is ready to use.")
        sys.exit(0)
    else:
        print("\n⚠️  SOME TESTS FAILED. Please review the results above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
