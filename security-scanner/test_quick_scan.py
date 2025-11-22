#!/usr/bin/env python3
"""
Quick Scan Test - Tests actual scanning functionality
"""

import sys
import json
from datetime import datetime

def test_nuclei_scan():
    """Test Nuclei scanner"""
    print("\n" + "="*70)
    print("🔍 TESTING NUCLEI SCANNER")
    print("="*70)
    
    try:
        from nuclei_scanner import NucleiScanner
        
        scanner = NucleiScanner(use_docker=False)  # Use native in Docker
        print("✅ Nuclei scanner initialized")
        
        # Quick scan on httpbin.org
        print("\n📡 Running quick scan on httpbin.org...")
        result = scanner.quick_scan("https://httpbin.org")
        
        print(f"\n✅ Scan completed!")
        print(f"  Vulnerabilities found: {result['vulnerabilities_found']}")
        print(f"  Duration: {result['duration_seconds']:.2f}s")
        print(f"  Output file: {result['output_file']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Nuclei test failed: {str(e)}")
        return False


def test_jaeles_scan():
    """Test Jaeles scanner"""
    print("\n" + "="*70)
    print("🔍 TESTING JAELES SCANNER")
    print("="*70)
    
    try:
        from jaeles_scanner import JaelesScanner
        
        scanner = JaelesScanner(use_docker=False)  # Use native in Docker
        print("✅ Jaeles scanner initialized")
        
        # Quick scan
        print("\n📡 Running quick scan on httpbin.org...")
        result = scanner.quick_scan("https://httpbin.org")
        
        print(f"\n✅ Scan completed!")
        print(f"  Vulnerabilities found: {result['vulnerabilities_found']}")
        print(f"  Duration: {result['duration_seconds']:.2f}s")
        
        return True
        
    except Exception as e:
        print(f"❌ Jaeles test failed: {str(e)}")
        return False


def test_passive_recon():
    """Test Passive Reconnaissance"""
    print("\n" + "="*70)
    print("🔍 TESTING PASSIVE RECONNAISSANCE")
    print("="*70)
    
    try:
        from passive_recon_v2 import PassiveReconEngine
        
        engine = PassiveReconEngine("example.com")
        print("✅ Passive recon engine initialized")
        
        print("\n📡 Running passive scan on example.com...")
        results = engine.run_full_scan()
        
        print(f"\n✅ Scan completed!")
        print(f"  Subdomains found: {len(results['subdomains'])}")
        print(f"  DNS records: {len(results['dns_records'])}")
        print(f"  Technologies: {len(results['technologies'])}")
        print(f"  Historical URLs: {len(results['historical_urls'])}")
        print(f"  Leaks detected: {len(results['leaks'])}")
        
        return True
        
    except Exception as e:
        print(f"❌ Passive recon test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all quick scan tests"""
    print("\n" + "="*70)
    print("🚀 QUICK SCAN FUNCTIONALITY TEST")
    print("="*70)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    results = {
        "nuclei": False,
        "jaeles": False,
        "passive_recon": False
    }
    
    # Test Nuclei
    results["nuclei"] = test_nuclei_scan()
    
    # Test Jaeles
    results["jaeles"] = test_jaeles_scan()
    
    # Test Passive Recon
    results["passive_recon"] = test_passive_recon()
    
    # Summary
    print("\n" + "="*70)
    print("📊 QUICK SCAN TEST SUMMARY")
    print("="*70)
    
    for tool, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{tool.upper():20} {status}")
    
    passed = sum(results.values())
    total = len(results)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print(f"Success Rate: {(passed/total*100):.1f}%")
    
    print("\n" + "="*70)
    print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    if passed == total:
        print("\n🎉 ALL SCANS WORKING! Ready for production use.")
        sys.exit(0)
    else:
        print("\n⚠️  SOME SCANS FAILED. Please review the results above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
