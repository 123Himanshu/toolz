#!/usr/bin/env python3
"""
Test Real Scanning with Actual Tools
Verifies that tools produce real output
"""

import json
import subprocess
import sys

def test_tool(tool_name, command):
    """Test a single tool"""
    print(f"\n{'='*70}")
    print(f"Testing {tool_name}")
    print(f"{'='*70}")
    
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', 'security-scanner', 'python', '-c', command],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            print(f"❌ {tool_name} FAILED")
            print(f"Error: {result.stderr}")
            return False
        
        if not result.stdout or result.stdout.strip() == '':
            print(f"❌ {tool_name} produced no output")
            return False
        
        # Try to parse JSON
        try:
            data = json.loads(result.stdout)
            print(f"✅ {tool_name} SUCCESS")
            print(f"Output: {json.dumps(data, indent=2)[:500]}...")
            return True
        except json.JSONDecodeError:
            print(f"⚠️  {tool_name} produced non-JSON output")
            print(f"Output: {result.stdout[:200]}...")
            return True
            
    except subprocess.TimeoutExpired:
        print(f"⏱️  {tool_name} timed out (may be working but slow)")
        return False
    except Exception as e:
        print(f"❌ {tool_name} exception: {e}")
        return False

def main():
    print("="*70)
    print("REAL SCAN TEST - Verifying Tools Produce Output")
    print("="*70)
    
    tests = {
        'RustScan': '''
from rustscan_wrapper import RustScanWrapper
import json
scanner = RustScanWrapper(docker_mode=False)
result = scanner.scan('scanme.nmap.org')
print(json.dumps(result, default=str))
''',
        'Nmap': '''
from nmap_wrapper import NmapWrapper
import json
scanner = NmapWrapper(docker_mode=False)
result = scanner.quick_scan('scanme.nmap.org')
print(json.dumps(result, default=str))
''',
        'Nuclei': '''
from nuclei_scanner import NucleiScanner
import json
scanner = NucleiScanner(use_docker=False)
result = scanner.quick_scan('https://httpbin.org')
print(json.dumps(result, default=str))
''',
    }
    
    results = {}
    for tool_name, command in tests.items():
        results[tool_name] = test_tool(tool_name, command)
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for tool_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{tool_name:20} {status}")
    
    total = len(results)
    passed = sum(results.values())
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED - Tools are producing real output!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {total - passed} tests failed - Some tools need fixing")
        sys.exit(1)

if __name__ == '__main__':
    main()
