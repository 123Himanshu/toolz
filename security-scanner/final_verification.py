#!/usr/bin/env python3
"""
Final Verification Script
Comprehensive check of all integrated tools
"""

import subprocess
import sys
import json
from datetime import datetime
from typing import Dict, List, Tuple

class FinalVerification:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "docker_build": False,
            "tools_installed": {},
            "python_modules": {},
            "scanner_modules": {},
            "functional_tests": {},
            "summary": {
                "total_checks": 0,
                "passed": 0,
                "failed": 0
            }
        }
    
    def check_docker_image(self) -> bool:
        """Check if Docker image exists"""
        print("\n" + "="*70)
        print("🐳 CHECKING DOCKER IMAGE")
        print("="*70)
        
        try:
            result = subprocess.run(
                ["docker", "images", "security-scanner", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if "security-scanner" in result.stdout:
                print("✅ Docker image 'security-scanner' found")
                self.results["docker_build"] = True
                return True
            else:
                print("❌ Docker image 'security-scanner' not found")
                print("   Run: docker build -t security-scanner -f Dockerfile.complete .")
                return False
                
        except Exception as e:
            print(f"❌ Error checking Docker image: {str(e)}")
            return False
    
    def verify_tools_in_container(self) -> Dict[str, bool]:
        """Verify all tools are installed in container"""
        print("\n" + "="*70)
        print("🔧 VERIFYING TOOLS IN CONTAINER")
        print("="*70)
        
        tools = [
            ("Nuclei", ["nuclei", "-version"]),
            ("Jaeles", ["jaeles", "version"]),
            ("Nmap", ["nmap", "--version"]),
            ("Masscan", ["masscan", "--version"]),
            ("Subfinder", ["subfinder", "-version"]),
            ("Naabu", ["naabu", "-version"]),
            ("Httpx", ["httpx", "-version"]),
            ("Wapiti", ["wapiti3", "--version"]),
            ("Python", ["python", "--version"]),
        ]
        
        results = {}
        
        for name, cmd in tools:
            try:
                result = subprocess.run(
                    ["docker", "run", "--rm", "security-scanner"] + cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                success = result.returncode == 0
                status = "✅" if success else "❌"
                print(f"{status} {name:15} {'INSTALLED' if success else 'MISSING'}")
                
                results[name] = success
                self.results["summary"]["total_checks"] += 1
                if success:
                    self.results["summary"]["passed"] += 1
                else:
                    self.results["summary"]["failed"] += 1
                    
            except Exception as e:
                print(f"❌ {name:15} ERROR: {str(e)}")
                results[name] = False
                self.results["summary"]["total_checks"] += 1
                self.results["summary"]["failed"] += 1
        
        self.results["tools_installed"] = results
        return results
    
    def verify_python_modules(self) -> Dict[str, bool]:
        """Verify Python modules in container"""
        print("\n" + "="*70)
        print("🐍 VERIFYING PYTHON MODULES")
        print("="*70)
        
        modules = [
            "requests",
            "dns.resolver",
            "whois",
            "urllib3",
            "docker",
            "nuclei_scanner",
            "jaeles_scanner",
            "wapiti_scanner",
            "zap_scanner",
            "nikto_scanner",
            "unified_scanner",
            "passive_recon",
            "passive_recon_v2"
        ]
        
        results = {}
        
        for module in modules:
            try:
                result = subprocess.run(
                    ["docker", "run", "--rm", "security-scanner", 
                     "python", "-c", f"import {module}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                success = result.returncode == 0
                status = "✅" if success else "❌"
                print(f"{status} {module:25} {'AVAILABLE' if success else 'MISSING'}")
                
                results[module] = success
                self.results["summary"]["total_checks"] += 1
                if success:
                    self.results["summary"]["passed"] += 1
                else:
                    self.results["summary"]["failed"] += 1
                    
            except Exception as e:
                print(f"❌ {module:25} ERROR: {str(e)}")
                results[module] = False
                self.results["summary"]["total_checks"] += 1
                self.results["summary"]["failed"] += 1
        
        self.results["python_modules"] = results
        return results
    
    def run_integration_test(self) -> bool:
        """Run the complete integration test"""
        print("\n" + "="*70)
        print("🧪 RUNNING INTEGRATION TEST")
        print("="*70)
        
        try:
            print("Running test_docker_complete.py in container...")
            result = subprocess.run(
                ["docker", "run", "--rm", "security-scanner", 
                 "python", "test_docker_complete.py"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            success = result.returncode == 0
            
            if success:
                print("✅ Integration test PASSED")
                # Try to extract summary from output
                if "Success Rate:" in result.stdout:
                    for line in result.stdout.split('\n'):
                        if "Success Rate:" in line or "Total Tests:" in line or "Passed:" in line:
                            print(f"   {line.strip()}")
            else:
                print("❌ Integration test FAILED")
                print(f"   Error: {result.stderr[:200]}")
            
            self.results["functional_tests"]["integration_test"] = success
            self.results["summary"]["total_checks"] += 1
            if success:
                self.results["summary"]["passed"] += 1
            else:
                self.results["summary"]["failed"] += 1
            
            return success
            
        except subprocess.TimeoutExpired:
            print("❌ Integration test TIMEOUT (>5 minutes)")
            self.results["functional_tests"]["integration_test"] = False
            self.results["summary"]["total_checks"] += 1
            self.results["summary"]["failed"] += 1
            return False
        except Exception as e:
            print(f"❌ Integration test ERROR: {str(e)}")
            self.results["functional_tests"]["integration_test"] = False
            self.results["summary"]["total_checks"] += 1
            self.results["summary"]["failed"] += 1
            return False
    
    def print_final_summary(self):
        """Print final verification summary"""
        print("\n" + "="*70)
        print("📊 FINAL VERIFICATION SUMMARY")
        print("="*70)
        
        total = self.results["summary"]["total_checks"]
        passed = self.results["summary"]["passed"]
        failed = self.results["summary"]["failed"]
        
        print(f"\nTotal Checks: {total}")
        print(f"✅ Passed:    {passed}")
        print(f"❌ Failed:    {failed}")
        print(f"Success Rate: {(passed/total*100):.1f}%")
        
        print("\n" + "="*70)
        print("COMPONENT STATUS")
        print("="*70)
        
        # Docker Image
        docker_status = "✅ READY" if self.results["docker_build"] else "❌ NOT FOUND"
        print(f"Docker Image:        {docker_status}")
        
        # Tools
        tools_passed = sum(self.results["tools_installed"].values())
        tools_total = len(self.results["tools_installed"])
        tools_status = "✅ ALL INSTALLED" if tools_passed == tools_total else f"⚠️  {tools_passed}/{tools_total} INSTALLED"
        print(f"Command-line Tools:  {tools_status}")
        
        # Python Modules
        modules_passed = sum(self.results["python_modules"].values())
        modules_total = len(self.results["python_modules"])
        modules_status = "✅ ALL AVAILABLE" if modules_passed == modules_total else f"⚠️  {modules_passed}/{modules_total} AVAILABLE"
        print(f"Python Modules:      {modules_status}")
        
        # Integration Test
        if "integration_test" in self.results["functional_tests"]:
            test_status = "✅ PASSED" if self.results["functional_tests"]["integration_test"] else "❌ FAILED"
            print(f"Integration Test:    {test_status}")
        
        print("\n" + "="*70)
        
        if failed == 0:
            print("🎉 ALL CHECKS PASSED! System is ready for production use.")
            print("\nNext steps:")
            print("  1. Run: docker run --rm security-scanner python test_quick_scan.py")
            print("  2. Start scanning your targets!")
        else:
            print("⚠️  SOME CHECKS FAILED. Please review the results above.")
            print("\nTroubleshooting:")
            print("  1. Rebuild: docker build --no-cache -t security-scanner -f Dockerfile.complete .")
            print("  2. Check logs: docker logs <container_id>")
            print("  3. Review: BUILD_AND_TEST.md")
        
        print("="*70)
    
    def save_results(self):
        """Save results to JSON file"""
        try:
            with open('final_verification_results.json', 'w') as f:
                json.dump(self.results, f, indent=2)
            print("\n📄 Results saved to: final_verification_results.json")
        except Exception as e:
            print(f"\n⚠️  Could not save results: {str(e)}")
    
    def run_all_checks(self) -> bool:
        """Run all verification checks"""
        print("\n" + "="*70)
        print("🔒 FINAL VERIFICATION - COMPLETE SECURITY SCANNER")
        print("="*70)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        
        # Check 1: Docker image exists
        if not self.check_docker_image():
            print("\n❌ Docker image not found. Build it first:")
            print("   docker build -t security-scanner -f Dockerfile.complete .")
            return False
        
        # Check 2: Verify tools in container
        self.verify_tools_in_container()
        
        # Check 3: Verify Python modules
        self.verify_python_modules()
        
        # Check 4: Run integration test
        self.run_integration_test()
        
        # Print summary
        self.print_final_summary()
        
        # Save results
        self.save_results()
        
        return self.results["summary"]["failed"] == 0


def main():
    """Main verification function"""
    verifier = FinalVerification()
    success = verifier.run_all_checks()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
