#!/usr/bin/env python3
"""
Test runner for Attack Path Intelligence Engine
Runs all test suites and generates report
"""
import unittest
import sys
import os
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_all_tests():
    """Run all test suites"""
    
    print("="*80)
    print("ATTACK PATH INTELLIGENCE ENGINE - TEST SUITE")
    print("="*80)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    print()
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print()
    print("="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("="*80)
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED")
        print("="*80)
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        print("="*80)
        return 1

if __name__ == '__main__':
    sys.exit(run_all_tests())
