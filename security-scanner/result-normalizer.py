#!/usr/bin/env python3
"""
Result Normalizer - Standardizes all tool outputs for Phase 2 correlation
Handles XML, JSON, CSV, and custom formats from all 13 tools
"""

import json
from typing import Dict, Any, List
from datetime import datetime


class ResultNormalizer:
    """
    Normalizes all tool outputs into a standard format for correlation
    """
    
    def __init__(self):
        self.normalized_results = []
    
    def normalize(self, tool_name: str, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize any tool result into standard format
        
        Standard Format:
        {
            'tool': str,
            'target': str,
            'timestamp': str,
            'success': bool,
            'findings': List[Finding],
            'metadata': Dict,
            'raw_data': Dict
        }
        
        Finding Format:
        {
            'type': 'port' | 'vulnerability' | 'service' | 'subdomain' | 'cve',
            'severity': 'critical' | 'high' | 'medium' | 'low' | 'info',
            'title': str,
            'description': str,
            'location': str (IP, URL, port, etc.),
            'evidence': Dict,
            'cve_id': str (if applicable),
            'cvss_score': float (if applicable)
        }
        """
        
        normalizer_map = {
            'nmap': self._normalize_nmap,
            'rustscan': self._normalize_rustscan,
            'masscan': self._normalize_masscan,
            'zmap': self._normalize_zmap,
            'nuclei': self._normalize_nuclei,
            'trivy': self._normalize_trivy,
            'nikto': self._normalize_nikto,
            'naabu': self._normalize_naabu,
            'wapiti': self._normalize_wapiti,
            'subfinder': self._normalize_subfinder,
            'httpx': self._normalize_httpx,
            'jaeles': self._normalize_jaeles,
            'openvas': self._normalize_openvas
        }
        
        normalizer = normalizer_map.get(tool_name.lower())
        if not normalizer:
            return self._normalize_generic(tool_name, raw_result)
        
        return normalizer(raw_result)
    
    def _normalize_nmap(self, result: Dict) -> Dict:
        """Normalize Nmap output (XML → JSON)"""
        findings = []
        
        if result.get('success') and 'data' in result:
            for ip, host_data in result['data'].get('hosts', {}).items():
                for port_info in host_data.get('ports', []):
                    if port_info['state'] == 'open':
                        findings.append({
                            'type': 'port',
                            'severity': 'info',
                            'title': f"Open Port: {port_info['port']}/{port_info['protocol']}",
                            'description': f"Service: {port_info.get('service', 'unknown')}",
                            'location': f"{ip}:{port_info['port']}",
                            'evidence': {
                                'port': port_info['port'],
                                'protocol': port_info['protocol'],
                                'service': port_info.get('service'),
                                'version': port_info.get('version')
                            }
                        })
        
        return {
            'tool': 'nmap',
            'target': result.get('command', '').split()[-1] if 'command' in result else 'unknown',
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': findings,
            'metadata': {
                'scan_type': 'network',
                'command': result.get('command'),
                'scan_stats': result.get('data', {}).get('scan_stats')
            },
            'raw_data': result
        }
    
    def _normalize_rustscan(self, result: Dict) -> Dict:
        """Normalize RustScan output"""
        findings = []
        
        for port in result.get('ports', []):
            findings.append({
                'type': 'port',
                'severity': 'info',
                'title': f"Open Port: {port}",
                'description': 'Fast port discovery (needs Nmap for service detection)',
                'location': f"port:{port}",
                'evidence': {'port': port, 'discovered_by': 'rustscan'}
            })
        
        return {
            'tool': 'rustscan',
            'target': 'unknown',
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': findings,
            'metadata': {
                'scan_type': 'port_discovery',
                'feed_to_nmap': result.get('feed_to_nmap', True),
                'port_count': result.get('port_count', 0)
            },
            'raw_data': result
        }
    
    def _normalize_nuclei(self, result: Dict) -> Dict:
        """Normalize Nuclei output (CVE/Template based)"""
        findings = []
        
        # Nuclei returns vulnerabilities with CVE IDs
        for vuln in result.get('vulnerabilities', []):
            findings.append({
                'type': 'cve',
                'severity': vuln.get('severity', 'medium'),
                'title': vuln.get('template_id', 'Unknown'),
                'description': vuln.get('info', {}).get('description', ''),
                'location': vuln.get('matched_at', ''),
                'evidence': vuln,
                'cve_id': vuln.get('info', {}).get('classification', {}).get('cve-id'),
                'cvss_score': vuln.get('info', {}).get('classification', {}).get('cvss-score')
            })
        
        return {
            'tool': 'nuclei',
            'target': result.get('target', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': findings,
            'metadata': {
                'scan_type': 'cve_scanning',
                'templates_used': result.get('templates_used', 0),
                'duration': result.get('duration_seconds', 0)
            },
            'raw_data': result
        }
    
    def _normalize_nikto(self, result: Dict) -> Dict:
        """Normalize Nikto output (text based)"""
        findings = []
        
        for finding in result.get('findings', []):
            findings.append({
                'type': 'vulnerability',
                'severity': finding.get('severity', 'low'),
                'title': 'Web Server Misconfiguration',
                'description': finding.get('description', ''),
                'location': result.get('target', ''),
                'evidence': {
                    'osvdb': finding.get('osvdb'),
                    'finding': finding.get('description')
                }
            })
        
        return {
            'tool': 'nikto',
            'target': result.get('target', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': findings,
            'metadata': {
                'scan_type': 'web_server',
                'findings_count': result.get('findings_count', 0),
                'duration': result.get('duration_seconds', 0)
            },
            'raw_data': result
        }
    
    def _normalize_trivy(self, result: Dict) -> Dict:
        """Normalize Trivy output (container/IaC vulnerabilities)"""
        findings = []
        
        for vuln in result.get('vulnerabilities', []):
            findings.append({
                'type': 'cve',
                'severity': vuln.get('Severity', 'unknown').lower(),
                'title': vuln.get('VulnerabilityID', 'Unknown'),
                'description': vuln.get('Description', ''),
                'location': vuln.get('PkgName', ''),
                'evidence': vuln,
                'cve_id': vuln.get('VulnerabilityID'),
                'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score')
            })
        
        return {
            'tool': 'trivy',
            'target': result.get('image', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': findings,
            'metadata': {
                'scan_type': 'container',
                'vulnerabilities_found': result.get('vulnerabilities_found', 0)
            },
            'raw_data': result
        }
    
    def _normalize_masscan(self, result: Dict) -> Dict:
        """Normalize Masscan output"""
        findings = []
        
        for ip_data in result.get('discovered', []):
            for port_info in ip_data.get('open_ports', []):
                findings.append({
                    'type': 'port',
                    'severity': 'info',
                    'title': f"Open Port: {port_info['port']}",
                    'description': f"Protocol: {port_info['protocol']}",
                    'location': f"{ip_data['ip']}:{port_info['port']}",
                    'evidence': {'ip': ip_data['ip'], **port_info}
                })
        
        return {
            'tool': 'masscan',
            'target': result.get('ip_range', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': findings,
            'metadata': {
                'scan_type': 'network_range',
                'total_ips': result.get('total_ips', 0),
                'total_ports': result.get('total_ports', 0)
            },
            'raw_data': result
        }
    
    def _normalize_zmap(self, result: Dict) -> Dict:
        """Normalize ZMap output"""
        return self._normalize_generic('zmap', result)
    
    def _normalize_naabu(self, result: Dict) -> Dict:
        """Normalize Naabu output (clean JSON)"""
        findings = []
        
        for port_info in result.get('open_ports', []):
            findings.append({
                'type': 'port',
                'severity': 'info',
                'title': f"Open Port: {port_info['port']}",
                'description': f"Service: {port_info.get('service_type', 'unknown')}",
                'location': f"{port_info.get('host', '')}:{port_info['port']}",
                'evidence': port_info
            })
        
        return {
            'tool': 'naabu',
            'target': result.get('domain', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': findings,
            'metadata': {
                'scan_type': 'port_discovery',
                'api_friendly': result.get('api_friendly', True)
            },
            'raw_data': result
        }
    
    def _normalize_wapiti(self, result: Dict) -> Dict:
        """Normalize Wapiti output"""
        return self._normalize_generic('wapiti', result)
    
    def _normalize_subfinder(self, result: Dict) -> Dict:
        """Normalize Subfinder output"""
        return self._normalize_generic('subfinder', result)
    
    def _normalize_httpx(self, result: Dict) -> Dict:
        """Normalize Httpx output"""
        return self._normalize_generic('httpx', result)
    
    def _normalize_jaeles(self, result: Dict) -> Dict:
        """Normalize Jaeles output"""
        return self._normalize_generic('jaeles', result)
    
    def _normalize_openvas(self, result: Dict) -> Dict:
        """Normalize OpenVAS output"""
        return self._normalize_generic('openvas', result)
    
    def _normalize_generic(self, tool_name: str, result: Dict) -> Dict:
        """Generic normalizer for tools without specific format"""
        return {
            'tool': tool_name,
            'target': result.get('target', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'success': result.get('success', False),
            'findings': [],
            'metadata': {
                'scan_type': 'generic',
                'note': 'Generic normalization - tool-specific parser needed'
            },
            'raw_data': result
        }
    
    def correlate_findings(self, normalized_results: List[Dict]) -> Dict:
        """
        Correlate findings from multiple tools (Phase 2)
        
        Correlation Rules:
        1. Port correlation: RustScan → Nmap → Nuclei
        2. CVE correlation: Nuclei + Trivy + OpenVAS
        3. Web vuln correlation: Nuclei + Wapiti + Nikto + Jaeles
        4. Service correlation: Nmap + Httpx
        """
        
        correlations = {
            'ports': {},  # IP:Port → [tools that found it]
            'cves': {},   # CVE-ID → [tools that found it]
            'services': {},  # Service → [tools that detected it]
            'hosts': {}   # IP/Domain → all findings
        }
        
        for result in normalized_results:
            tool = result['tool']
            
            for finding in result['findings']:
                # Correlate ports
                if finding['type'] == 'port':
                    location = finding['location']
                    if location not in correlations['ports']:
                        correlations['ports'][location] = {
                            'port': finding['evidence'].get('port'),
                            'found_by': [],
                            'services': []
                        }
                    correlations['ports'][location]['found_by'].append(tool)
                    if 'service' in finding['evidence']:
                        correlations['ports'][location]['services'].append(
                            finding['evidence']['service']
                        )
                
                # Correlate CVEs
                if finding['type'] == 'cve' and finding.get('cve_id'):
                    cve_id = finding['cve_id']
                    if cve_id not in correlations['cves']:
                        correlations['cves'][cve_id] = {
                            'cve_id': cve_id,
                            'found_by': [],
                            'severity': finding['severity'],
                            'cvss_scores': []
                        }
                    correlations['cves'][cve_id]['found_by'].append(tool)
                    if finding.get('cvss_score'):
                        correlations['cves'][cve_id]['cvss_scores'].append(
                            finding['cvss_score']
                        )
        
        return {
            'correlation_timestamp': datetime.now().isoformat(),
            'tools_analyzed': len(normalized_results),
            'correlations': correlations,
            'confidence_scores': self._calculate_confidence(correlations)
        }
    
    def _calculate_confidence(self, correlations: Dict) -> Dict:
        """
        Calculate confidence scores based on tool agreement
        
        Rules:
        - 1 tool = 50% confidence
        - 2 tools = 75% confidence
        - 3+ tools = 95% confidence
        """
        confidence = {}
        
        # Port confidence
        for location, data in correlations['ports'].items():
            tool_count = len(data['found_by'])
            if tool_count == 1:
                conf = 0.5
            elif tool_count == 2:
                conf = 0.75
            else:
                conf = 0.95
            confidence[location] = conf
        
        # CVE confidence
        for cve_id, data in correlations['cves'].items():
            tool_count = len(data['found_by'])
            if tool_count == 1:
                conf = 0.6
            elif tool_count == 2:
                conf = 0.85
            else:
                conf = 0.98
            confidence[cve_id] = conf
        
        return confidence
    
    def save_normalized(self, normalized_result: Dict, output_file: str):
        """Save normalized result for Phase 2"""
        with open(output_file, 'w') as f:
            json.dump(normalized_result, f, indent=2)
        print(f"✓ Saved normalized result: {output_file}")


# Example usage
if __name__ == "__main__":
    normalizer = ResultNormalizer()
    
    # Test with sample Nmap result
    from nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(docker_mode=False)
    nmap_result = nmap.quick_scan('scanme.nmap.org')
    
    normalized = normalizer.normalize('nmap', nmap_result)
    
    print("="*70)
    print("NORMALIZED OUTPUT EXAMPLE")
    print("="*70)
    print(json.dumps(normalized, indent=2))
    
    print(f"\n✓ Tool: {normalized['tool']}")
    print(f"✓ Findings: {len(normalized['findings'])}")
    print(f"✓ Success: {normalized['success']}")
    print(f"✓ Has raw data: {bool(normalized['raw_data'])}")
