"""
Unified Security Scanner - All 4 Scanners
Nuclei + Jaeles + Wapiti + Nikto
Complete security testing suite
"""

from nuclei_scanner import NucleiScanner, NucleiTemplates
from jaeles_scanner import JaelesScanner, JaelesSignatures
from wapiti_scanner import WapitiScanner
from zap_scanner import ZAPScanner
from nikto_scanner import NiktoScanner
import json
from datetime import datetime
from typing import List, Dict, Optional


class UnifiedScanner:
    """
    Unified scanner combining all 5 security scanners
    """
    
    def __init__(self, use_docker: bool = True):
        """
        Initialize all five scanners
        
        Args:
            use_docker: Use Docker for all scanners
        """
        self.nuclei = NucleiScanner(use_docker=use_docker)
        self.jaeles = JaelesScanner(use_docker=use_docker)
        self.wapiti = WapitiScanner(use_docker=use_docker)
        self.zap = ZAPScanner(use_docker=use_docker)
        self.nikto = NiktoScanner(use_docker=use_docker)
        self.scan_results = []
        print("✅ Unified Scanner initialized (Nuclei + Jaeles + Wapiti + ZAP + Nikto)")
    
    def quick_scan(self, target: str, include_all: bool = False) -> Dict:
        """
        Quick scan with all 5 tools
        
        Args:
            target: Target URL
            include_all: Include all scanners (default: Nuclei + Jaeles + ZAP only)
            
        Returns:
            Combined results from all scanners
        """
        print(f"\n🔍 Quick Scan: {target}")
        print("="*60)
        
        # Nuclei quick scan
        print("\n[1/5] Running Nuclei quick scan...")
        nuclei_result = self.nuclei.quick_scan(target)
        print(f"✅ Nuclei: {nuclei_result['vulnerabilities_found']} issues ({nuclei_result['duration_seconds']:.2f}s)")
        
        # Jaeles quick scan
        print("\n[2/5] Running Jaeles quick scan...")
        jaeles_result = self.jaeles.quick_scan(target)
        print(f"✅ Jaeles: {'Found issues' if jaeles_result['vulnerabilities_found'] else 'No issues'} ({jaeles_result['duration_seconds']:.2f}s)")
        
        # ZAP baseline scan
        print("\n[3/5] Running ZAP baseline scan...")
        zap_result = self.zap.baseline_scan(target, timeout=5)
        print(f"✅ ZAP: {zap_result.get('alerts_found', 0)} alerts ({zap_result.get('duration_seconds', 0):.2f}s)")
        
        # Wapiti (optional)
        wapiti_result = None
        if include_all:
            print("\n[4/5] Running Wapiti XSS scan...")
            wapiti_result = self.wapiti.scan(target, "xss")
            print(f"✅ Wapiti: {'Found issues' if wapiti_result.get('success') else 'Scan failed'}")
        else:
            print("\n[4/5] Wapiti scan skipped")
        
        # Nikto (optional)
        nikto_result = None
        if include_all:
            print("\n[5/5] Running Nikto quick scan...")
            nikto_result = self.nikto.quick_scan(target)
            print(f"✅ Nikto: {nikto_result.get('findings_count', 0)} findings ({nikto_result.get('duration_seconds', 0):.2f}s)")
        else:
            print("\n[5/5] Nikto scan skipped")
        
        # Combine results
        total_vulns = (
            nuclei_result['vulnerabilities_found'] +
            (1 if jaeles_result['vulnerabilities_found'] else 0) +
            zap_result.get('alerts_found', 0) +
            (nikto_result.get('findings_count', 0) if nikto_result else 0)
        )
        
        combined = {
            'target': target,
            'scan_type': 'quick',
            'timestamp': datetime.now().isoformat(),
            'nuclei': nuclei_result,
            'jaeles': jaeles_result,
            'zap': zap_result,
            'wapiti': wapiti_result,
            'nikto': nikto_result,
            'total_vulnerabilities': total_vulns,
            'total_duration': (
                nuclei_result['duration_seconds'] +
                jaeles_result['duration_seconds'] +
                zap_result.get('duration_seconds', 0) +
                (nikto_result.get('duration_seconds', 0) if nikto_result else 0)
            )
        }
        
        self.scan_results.append(combined)
        return combined
    
    def full_scan(self, target: str) -> Dict:
        """
        Comprehensive scan with all 5 tools
        
        Args:
            target: Target URL
            
        Returns:
            Combined results from all scanners
        """
        print(f"\n🔍 Full Scan: {target}")
        print("="*60)
        
        # Nuclei full scan
        print("\n[1/5] Running Nuclei full scan...")
        nuclei_result = self.nuclei.full_scan(target)
        print(f"✅ Nuclei: {nuclei_result['vulnerabilities_found']} issues ({nuclei_result['duration_seconds']:.2f}s)")
        
        # Jaeles deep scan
        print("\n[2/5] Running Jaeles deep scan...")
        jaeles_result = self.jaeles.deep_scan(target)
        print(f"✅ Jaeles: {'Found issues' if jaeles_result['vulnerabilities_found'] else 'No issues'} ({jaeles_result['duration_seconds']:.2f}s)")
        
        # ZAP full scan
        print("\n[3/5] Running ZAP full scan...")
        zap_result = self.zap.full_scan(target, timeout=30)
        print(f"✅ ZAP: {zap_result.get('alerts_found', 0)} alerts ({zap_result.get('duration_seconds', 0):.2f}s)")
        
        # Wapiti comprehensive scan
        print("\n[4/5] Running Wapiti comprehensive scan...")
        wapiti_result = self.wapiti.scan(target, "all", parallel=True, workers=5)
        print(f"✅ Wapiti: Comprehensive scan completed")
        
        # Nikto full scan
        print("\n[5/5] Running Nikto full scan...")
        nikto_result = self.nikto.full_scan(target)
        print(f"✅ Nikto: {nikto_result.get('findings_count', 0)} findings ({nikto_result.get('duration_seconds', 0):.2f}s)")
        
        # Combine results
        total_vulns = (
            nuclei_result['vulnerabilities_found'] +
            (1 if jaeles_result['vulnerabilities_found'] else 0) +
            zap_result.get('alerts_found', 0) +
            nikto_result.get('findings_count', 0)
        )
        
        combined = {
            'target': target,
            'scan_type': 'full',
            'timestamp': datetime.now().isoformat(),
            'nuclei': nuclei_result,
            'jaeles': jaeles_result,
            'zap': zap_result,
            'wapiti': wapiti_result,
            'nikto': nikto_result,
            'total_vulnerabilities': total_vulns,
            'total_duration': (
                nuclei_result['duration_seconds'] +
                jaeles_result['duration_seconds'] +
                zap_result.get('duration_seconds', 0) +
                nikto_result.get('duration_seconds', 0)
            )
        }
        
        self.scan_results.append(combined)
        return combined
    
    def cve_scan(self, target: str, year: Optional[str] = None) -> Dict:
        """
        CVE-focused scan with both tools
        
        Args:
            target: Target URL
            year: Specific CVE year (optional)
            
        Returns:
            Combined CVE scan results
        """
        print(f"\n🔍 CVE Scan: {target}")
        print("="*60)
        
        # Nuclei CVE scan
        print("\n[1/2] Running Nuclei CVE scan...")
        nuclei_result = self.nuclei.cve_scan(target, year=year)
        print(f"✅ Nuclei: {nuclei_result['vulnerabilities_found']} CVEs ({nuclei_result['duration_seconds']:.2f}s)")
        
        # Jaeles CVE scan
        print("\n[2/2] Running Jaeles CVE scan...")
        jaeles_result = self.jaeles.scan(
            target=target,
            signatures='cves',
            timeout=30
        )
        print(f"✅ Jaeles: {'Found CVEs' if jaeles_result['vulnerabilities_found'] else 'No CVEs'} ({jaeles_result['duration_seconds']:.2f}s)")
        
        # Combine results
        combined = {
            'target': target,
            'scan_type': 'cve',
            'timestamp': datetime.now().isoformat(),
            'nuclei': nuclei_result,
            'jaeles': jaeles_result,
            'total_vulnerabilities': nuclei_result['vulnerabilities_found'] + (1 if jaeles_result['vulnerabilities_found'] else 0),
            'total_duration': nuclei_result['duration_seconds'] + jaeles_result['duration_seconds']
        }
        
        self.scan_results.append(combined)
        return combined
    
    def scan_multiple(self, targets: List[str], scan_type: str = 'quick') -> List[Dict]:
        """
        Scan multiple targets with both tools
        
        Args:
            targets: List of target URLs
            scan_type: 'quick' or 'full'
            
        Returns:
            List of combined results
        """
        print(f"\n🔍 Scanning {len(targets)} targets ({scan_type} mode)")
        print("="*60)
        
        results = []
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Scanning {target}")
            
            if scan_type == 'quick':
                result = self.quick_scan(target)
            else:
                result = self.full_scan(target)
            
            results.append(result)
        
        return results
    
    def generate_report(self, output_file: str = "unified_scan_report.json"):
        """
        Generate comprehensive report from all scans
        
        Args:
            output_file: Output file path
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_scans': len(self.scan_results),
            'scans': self.scan_results,
            'summary': {
                'nuclei_scans': len(self.nuclei.get_scan_history()),
                'jaeles_scans': len(self.jaeles.get_scan_history()),
                'total_vulnerabilities': sum(s['total_vulnerabilities'] for s in self.scan_results),
                'total_duration': sum(s['total_duration'] for s in self.scan_results)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Report saved to: {output_file}")
        return report
    
    def generate_summary(self) -> str:
        """Generate summary of all scans"""
        if not self.scan_results:
            return "No scans performed yet"
        
        total_scans = len(self.scan_results)
        total_vulns = sum(s['total_vulnerabilities'] for s in self.scan_results)
        total_duration = sum(s['total_duration'] for s in self.scan_results)
        
        summary = f"""
Unified Security Scanner Summary
{'=' * 60}
Total Scans: {total_scans}
Total Vulnerabilities Found: {total_vulns}
Total Duration: {total_duration:.2f}s ({total_duration/60:.1f} minutes)

Nuclei Summary:
{self.nuclei.generate_summary()}

Jaeles Summary:
{self.jaeles.generate_summary()}
{'=' * 60}
"""
        return summary


# Example usage
if __name__ == "__main__":
    # Initialize unified scanner
    scanner = UnifiedScanner(use_docker=True)
    
    # Quick scan
    print("\n" + "="*60)
    print("UNIFIED SECURITY SCANNER - DEMO")
    print("="*60)
    
    result = scanner.quick_scan("https://httpbin.org")
    
    print(f"\n📊 Results:")
    print(f"  Total vulnerabilities: {result['total_vulnerabilities']}")
    print(f"  Total duration: {result['total_duration']:.2f}s")
    
    # Generate report
    scanner.generate_report()
    
    # Print summary
    print(scanner.generate_summary())
