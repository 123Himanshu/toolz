#!/usr/bin/env python3
"""
Health Check System - Ensures all tools remain functional
Run this before demos/production to verify everything works
"""

import subprocess
import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple

class HealthCheck:
    def __init__(self):
        self.results = {}
        self.critical_failures = []
        
    def check_binary(self, name: str, command: List[str]) -> bool:
        """Check if binary is available and working"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode in [0, 1]  # Some tools return 1 for --version
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            return False
    
    def check_python_import(self, name: str, module: str, class_name: str) -> bool:
        """Check if Python wrapper can be imported"""
        try:
            exec(f"from {module} import {class_name}")
            return True
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            return False
    
    def run_checks(self) -> Dict:
        """Run all health checks"""
        print("="*70)
        print("HEALTH CHECK - ALL 13 TOOLS")
        print("="*70)
        print(f"Started: {datetime.now()}\n")
        
        # Binary checks
        print("1. Checking Binaries...")
        binaries = {
            'nmap': ['nmap', '--version'],
            'rustscan': ['rustscan', '--version'],
            'masscan': ['masscan', '--version'],

            'nuclei': ['nuclei', '-version'],
            'trivy': ['trivy', '--version'],
            'nikto': ['nikto', '-Version'],
            'naabu': ['naabu', '-version'],
            'subfinder': ['subfinder', '-version'],
            'httpx': ['httpx', '-version'],

            'wapiti': ['wapiti', '--version']
        }
        
        for name, cmd in binaries.items():
            status = self.check_binary(name, cmd)
            self.results[f'{name}_binary'] = status
            icon = "✅" if status else "❌"
            print(f"  {icon} {name}")
            if not status:
                self.critical_failures.append(f"{name} binary not found")
        
        # Python wrapper checks
        print("\n2. Checking Python Wrappers...")
        wrappers = {
            'nmap': ('nmap_wrapper', 'NmapWrapper'),
            'rustscan': ('rustscan_wrapper', 'RustScanWrapper'),
            'masscan': ('masscan_wrapper', 'MasscanWrapper'),

            'nuclei': ('nuclei_scanner', 'NucleiScanner'),
            'trivy': ('trivy_wrapper', 'TrivyScanner'),
            'nikto': ('nikto_scanner', 'NiktoScanner'),
            'naabu': ('naabu_wrapper', 'NaabuWrapper'),
            'wapiti': ('wapiti_scanner', 'WapitiScanner'),

            'openvas': ('openvas_wrapper_simple', 'OpenVASScanner')
        }
        
        for name, (module, class_name) in wrappers.items():
            status = self.check_python_import(name, module, class_name)
            self.results[f'{name}_wrapper'] = status
            icon = "✅" if status else "❌"
            print(f"  {icon} {name} wrapper")
            if not status:
                self.critical_failures.append(f"{name} wrapper import failed")
        
        # Docker check
        print("\n3. Checking Docker...")
        docker_status = self.check_binary('docker', ['docker', '--version'])
        self.results['docker'] = docker_status
        icon = "✅" if docker_status else "❌"
        print(f"  {icon} Docker")
        
        # Image check
        print("\n4. Checking Docker Image...")
        try:
            result = subprocess.run(
                ['docker', 'images', 'security-scanner:latest', '--format', '{{.Repository}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            image_exists = 'security-scanner' in result.stdout
            self.results['docker_image'] = image_exists
            icon = "✅" if image_exists else "❌"
            print(f"  {icon} security-scanner:latest")
            if not image_exists:
                self.critical_failures.append("Docker image not built")
        except Exception as e:
            self.results['docker_image'] = False
            print(f"  ❌ Image check failed: {e}")
        
        # Summary
        print("\n" + "="*70)
        print("HEALTH CHECK SUMMARY")
        print("="*70)
        
        total = len(self.results)
        passed = sum(self.results.values())
        failed = total - passed
        
        print(f"\nTotal Checks: {total}")
        print(f"Passed: {passed} ✅")
        print(f"Failed: {failed} ❌")
        print(f"Success Rate: {int(passed/total*100)}%")
        
        if self.critical_failures:
            print(f"\n⚠️  CRITICAL FAILURES:")
            for failure in self.critical_failures:
                print(f"  - {failure}")
            print("\n🔧 FIX: Rebuild Docker image:")
            print("  cd security-scanner")
            print("  docker build -t security-scanner:latest .")
        
        print(f"\nCompleted: {datetime.now()}")
        
        return {
            'total': total,
            'passed': passed,
            'failed': failed,
            'success_rate': int(passed/total*100),
            'critical_failures': self.critical_failures,
            'all_passed': failed == 0
        }

def main():
    checker = HealthCheck()
    summary = checker.run_checks()
    
    if summary['all_passed']:
        print("\n🎉 ALL HEALTH CHECKS PASSED!")
        print("✅ System is ready for production/demo")
        sys.exit(0)
    else:
        print(f"\n⚠️  {summary['failed']} checks failed")
        print("❌ System needs attention before use")
        sys.exit(1)

if __name__ == '__main__':
    main()
