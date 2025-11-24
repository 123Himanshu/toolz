"""
Target Classifier - Intelligent CSV/TXT Target Classification
Analyzes targets and determines optimal scanning pipeline
"""

import re
import ipaddress
import json
from typing import Dict, List, Tuple
from urllib.parse import urlparse


class TargetType:
    """Target type constants"""
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    UNKNOWN = "unknown"


class TargetClassifier:
    """
    Intelligent target classifier for CSV/TXT uploads
    Determines target type and recommends optimal tools
    """
    
    def __init__(self):
        self.ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        self.cidr_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
        self.domain_pattern = re.compile(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    
    def classify_target(self, target: str) -> Tuple[str, Dict]:
        """
        Classify a single target and recommend tools
        
        Args:
            target: Target string (IP, CIDR, domain, or URL)
            
        Returns:
            Tuple of (target_type, tool_recommendations)
        """
        target = target.strip()
        
        # Check if URL
        if target.startswith(('http://', 'https://')):
            return self._classify_url(target)
        
        # Check if CIDR range
        if self.cidr_pattern.match(target):
            return self._classify_cidr(target)
        
        # Check if IP address
        if self.ip_pattern.match(target):
            return self._classify_ip(target)
        
        # Check if domain
        if self.domain_pattern.match(target):
            return self._classify_domain(target)
        
        return TargetType.UNKNOWN, {
            'error': 'Unknown target format',
            'tools': []
        }
    
    def _classify_ip(self, target: str) -> Tuple[str, Dict]:
        """Classify IP address and recommend tools"""
        return TargetType.IP, {
            'target': target,
            'type': TargetType.IP,
            'tools': {
                'network': ['rustscan', 'nmap', 'naabu'],
                'system': ['openvas', 'trivy'],
                'web': []  # Only if ports 80/443 discovered
            },
            'pipeline': [
                '1. RustScan - Fast port discovery',
                '2. Nmap - Service detection on discovered ports',
                '3. Naabu - Verification',
                '4. OpenVAS - Host vulnerability scan',
                '5. Trivy - Container/package scan (if applicable)'
            ],
            'reasoning': 'Single IP: Use RustScan for speed, NOT Masscan (wrong tool for single IPs)'
        }
    
    def _classify_cidr(self, target: str) -> Tuple[str, Dict]:
        """Classify CIDR range and recommend tools"""
        try:
            network = ipaddress.ip_network(target, strict=False)
            num_hosts = network.num_addresses
            
            return TargetType.CIDR, {
                'target': target,
                'type': TargetType.CIDR,
                'network_size': num_hosts,
                'tools': {
                    'network': ['masscan', 'nmap', 'zmap'],
                    'system': ['openvas'],
                    'web': []  # Only if web ports discovered
                },
                'pipeline': [
                    '1. Masscan - Large range scanning (primary)',
                    '2. ZMap - Optional for huge ranges',
                    '3. Masscan results → RustScan → Nmap',
                    '4. OpenVAS - Host vulnerability scans'
                ],
                'reasoning': f'CIDR range ({num_hosts} hosts): Use Masscan, NOT RustScan (wrong tool for ranges)'
            }
        except ValueError:
            return TargetType.UNKNOWN, {'error': 'Invalid CIDR notation'}
    
    def _classify_domain(self, target: str) -> Tuple[str, Dict]:
        """Classify domain and recommend tools"""
        return TargetType.DOMAIN, {
            'target': target,
            'type': TargetType.DOMAIN,
            'tools': {
                'recon': ['subfinder', 'passive-recon'],
                'network': ['rustscan', 'naabu', 'nmap'],
                'web': ['nuclei', 'zap', 'wapiti', 'nikto'],
                'system': []
            },
            'pipeline': [
                '1. Subfinder - Subdomain discovery',
                '2. Httpx - Probe + fingerprints',
                '3. RustScan + Naabu - Port scanning (clean JSON)',
                '4. Nmap - Service detection',
                '5. Nuclei - CVE scanning',
                '6. ZAP - Comprehensive DAST',
                '7. Wapiti - Quick web checks',
                '8. Nikto - Legacy misconfig checks'
            ],
            'reasoning': 'Domain: Full recon + web scanning. Resolve to IP for port scanning.'
        }
    
    def _classify_url(self, target: str) -> Tuple[str, Dict]:
        """Classify URL and recommend tools"""
        parsed = urlparse(target)
        domain = parsed.netloc
        
        return TargetType.URL, {
            'target': target,
            'type': TargetType.URL,
            'domain': domain,
            'tools': {
                'web': ['zap', 'nuclei', 'wapiti', 'nikto', 'jaeles'],
                'recon': ['httpx'],
                'network': ['rustscan', 'nmap'],  # Optional
                'system': []
            },
            'pipeline': [
                '1. ZAP - Full DAST scan',
                '2. Nuclei - CVE + template scanning',
                '3. Wapiti - Quick XSS/SQLi/LFI checks',
                '4. Nikto - Legacy server checks',
                '5. Jaeles - Custom signatures (optional)',
                '6. Httpx - Fingerprinting',
                '7. Domain → IP → RustScan/Nmap (optional)'
            ],
            'reasoning': 'URL: Focus on web scanning. Extract domain for optional port scanning.'
        }
    
    def classify_csv(self, file_path: str) -> Dict:
        """
        Classify all targets in a CSV/TXT file
        
        Args:
            file_path: Path to CSV/TXT file
            
        Returns:
            Classification results with grouped targets
        """
        results = {
            'total_targets': 0,
            'by_type': {
                TargetType.IP: [],
                TargetType.CIDR: [],
                TargetType.DOMAIN: [],
                TargetType.URL: [],
                TargetType.UNKNOWN: []
            },
            'scan_plan': []
        }
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle CSV format (take first column)
                if ',' in line:
                    line = line.split(',')[0].strip()
                
                target_type, classification = self.classify_target(line)
                results['by_type'][target_type].append({
                    'target': line,
                    'classification': classification
                })
                results['total_targets'] += 1
        
        # Generate scan plan
        results['scan_plan'] = self._generate_scan_plan(results['by_type'])
        
        return results
    
    def _generate_scan_plan(self, targets_by_type: Dict) -> List[Dict]:
        """Generate optimized scan plan for all targets"""
        plan = []
        
        # CIDR ranges first (most efficient)
        if targets_by_type[TargetType.CIDR]:
            plan.append({
                'phase': 1,
                'name': 'CIDR Range Scanning',
                'targets': len(targets_by_type[TargetType.CIDR]),
                'tools': ['masscan', 'zmap', 'nmap', 'openvas'],
                'estimated_time': 'High (depends on range size)',
                'priority': 'High'
            })
        
        # IPs second
        if targets_by_type[TargetType.IP]:
            plan.append({
                'phase': 2,
                'name': 'IP Address Scanning',
                'targets': len(targets_by_type[TargetType.IP]),
                'tools': ['rustscan', 'nmap', 'naabu', 'openvas', 'trivy'],
                'estimated_time': f'{len(targets_by_type[TargetType.IP]) * 2} minutes',
                'priority': 'High'
            })
        
        # Domains third
        if targets_by_type[TargetType.DOMAIN]:
            plan.append({
                'phase': 3,
                'name': 'Domain Reconnaissance',
                'targets': len(targets_by_type[TargetType.DOMAIN]),
                'tools': ['subfinder', 'httpx', 'rustscan', 'nmap', 'nuclei', 'zap'],
                'estimated_time': f'{len(targets_by_type[TargetType.DOMAIN]) * 5} minutes',
                'priority': 'Medium'
            })
        
        # URLs last
        if targets_by_type[TargetType.URL]:
            plan.append({
                'phase': 4,
                'name': 'Web Application Scanning',
                'targets': len(targets_by_type[TargetType.URL]),
                'tools': ['zap', 'nuclei', 'wapiti', 'nikto', 'jaeles'],
                'estimated_time': f'{len(targets_by_type[TargetType.URL]) * 10} minutes',
                'priority': 'High'
            })
        
        return plan
    
    def generate_report(self, classification_results: Dict, output_file: str = "classification_report.txt"):
        """Generate human-readable classification report"""
        with open(output_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("TARGET CLASSIFICATION REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Total Targets: {classification_results['total_targets']}\n\n")
            
            # Summary by type
            f.write("SUMMARY BY TYPE:\n")
            f.write("-"*80 + "\n")
            for target_type, targets in classification_results['by_type'].items():
                if targets:
                    f.write(f"  {target_type.upper()}: {len(targets)} targets\n")
            f.write("\n")
            
            # Scan plan
            f.write("RECOMMENDED SCAN PLAN:\n")
            f.write("-"*80 + "\n")
            for phase in classification_results['scan_plan']:
                f.write(f"\nPhase {phase['phase']}: {phase['name']}\n")
                f.write(f"  Targets: {phase['targets']}\n")
                f.write(f"  Tools: {', '.join(phase['tools'])}\n")
                f.write(f"  Estimated Time: {phase['estimated_time']}\n")
                f.write(f"  Priority: {phase['priority']}\n")
            
            # Detailed breakdown
            f.write("\n" + "="*80 + "\n")
            f.write("DETAILED TARGET BREAKDOWN\n")
            f.write("="*80 + "\n\n")
            
            for target_type, targets in classification_results['by_type'].items():
                if targets:
                    f.write(f"\n{target_type.upper()} TARGETS ({len(targets)}):\n")
                    f.write("-"*80 + "\n")
                    for item in targets:
                        f.write(f"\nTarget: {item['target']}\n")
                        if 'pipeline' in item['classification']:
                            f.write("Pipeline:\n")
                            for step in item['classification']['pipeline']:
                                f.write(f"  {step}\n")
                        if 'reasoning' in item['classification']:
                            f.write(f"Reasoning: {item['classification']['reasoning']}\n")
        
        print(f"✅ Classification report saved to: {output_file}")


# Example usage
if __name__ == "__main__":
    import sys
    
    classifier = TargetClassifier()
    
    # CLI mode
    if len(sys.argv) > 2 and sys.argv[1] == 'classify':
        file_path = sys.argv[2]
        results = classifier.classify_csv(file_path)
        print(json.dumps(results, indent=2))
    else:
        # Test individual targets
        print("="*80)
        print("TARGET CLASSIFIER - DEMO")
        print("="*80)
        
        test_targets = [
            "192.168.1.10",
            "10.0.0.0/24",
            "example.com",
            "https://admin.site.com/login"
        ]
        
        for target in test_targets:
            target_type, classification = classifier.classify_target(target)
            print(f"\n✅ Target: {target}")
            print(f"   Type: {target_type}")
            print(f"   Tools: {classification.get('tools', {})}")
            print(f"   Reasoning: {classification.get('reasoning', 'N/A')}")
