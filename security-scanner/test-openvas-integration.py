#!/usr/bin/env python3
"""
Test OpenVAS Integration
Verifies connection to external OpenVAS container
"""

import json
import sys
from openvas_wrapper_simple import OpenVASScanner


def test_openvas_connection():
    """Test OpenVAS availability"""
    print("=" * 60)
    print("OpenVAS Integration Test")
    print("=" * 60)
    
    scanner = OpenVASScanner(host="localhost", port=9390)
    
    print("\n1. Testing OpenVAS availability...")
    if scanner.is_available():
        print("   ✅ OpenVAS is available and ready!")
        return True
    else:
        print("   ❌ OpenVAS not available")
        print("\n   To start OpenVAS container:")
        print("   cd security-scanner")
        print("   docker-compose -f docker-compose.openvas.yml up -d")
        print("   Wait 5 minutes for initialization")
        return False


def test_quick_scan(target="scanme.nmap.org"):
    """Test quick scan (async)"""
    print(f"\n2. Testing quick scan on {target}...")
    
    scanner = OpenVASScanner(host="localhost", port=9390)
    result = scanner.quick_scan(target, wait=False)
    
    print(f"\n   Result:")
    print(json.dumps(result, indent=2))
    
    if result['success']:
        if result.get('status') == 'not_configured':
            print("\n   ⚠️  OpenVAS not configured (expected if container not running)")
            return False
        else:
            print(f"\n   ✅ Scan started successfully!")
            print(f"   Task ID: {result.get('task_id')}")
            print(f"   Report ID: {result.get('report_id')}")
            print(f"   Status: {result.get('status')}")
            print(f"   Web UI: {result.get('web_ui')}")
            return True
    else:
        print(f"\n   ❌ Scan failed: {result.get('error')}")
        return False


def test_scan_status(task_id):
    """Test getting scan status"""
    print(f"\n3. Testing scan status for task {task_id}...")
    
    scanner = OpenVASScanner(host="localhost", port=9390)
    result = scanner.get_scan_status(task_id)
    
    print(f"\n   Result:")
    print(json.dumps(result, indent=2))
    
    if result['success']:
        print(f"\n   ✅ Status retrieved successfully!")
        print(f"   Status: {result.get('status')}")
        print(f"   Progress: {result.get('progress')}%")
        print(f"   Vulnerabilities: {result.get('vulnerabilities_found')}")
        return True
    else:
        print(f"\n   ❌ Failed: {result.get('error')}")
        return False


def main():
    """Run all tests"""
    print("\n🔒 OpenVAS Integration Test Suite\n")
    
    # Test 1: Connection
    if not test_openvas_connection():
        print("\n" + "=" * 60)
        print("⚠️  OpenVAS container not running")
        print("=" * 60)
        print("\nSetup instructions:")
        print("1. cd security-scanner")
        print("2. docker-compose -f docker-compose.openvas.yml up -d")
        print("3. Wait 5 minutes for OpenVAS to initialize")
        print("4. Run this test again")
        sys.exit(1)
    
    # Test 2: Quick scan
    print("\n" + "=" * 60)
    scan_result = test_quick_scan("scanme.nmap.org")
    
    if scan_result:
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        print("\nOpenVAS is ready to use!")
        print("You can now run scans from the web UI.")
    else:
        print("\n" + "=" * 60)
        print("⚠️  Tests completed with warnings")
        print("=" * 60)


if __name__ == "__main__":
    main()
