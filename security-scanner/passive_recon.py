#!/usr/bin/env python3
"""
Passive Reconnaissance Module
Gathers intelligence without directly interacting with target
"""

import subprocess
import json
import sys
import dns.resolver
import requests
import socket
from typing import Dict, List, Any
import re
from urllib.parse import urlparse
import whois
from datetime import datetime

class PassiveRecon:
    def __init__(self, target: str):
        self.target = target.strip().lower()
        self.results = {
            "job_id": "",
            "target": self.target,
            "subdomains": [],
            "dns_records": [],
            "technologies": {},
            "historical_urls": [],
            "asn": {},
            "leaks": [],
            "status": "running",
            "timestamp": datetime.now().isoformat()
        }
    
    def run_full_scan(self) -> Dict[str, Any]:
        """Execute all passive reconnaissance techniques"""
        try:
            sys.stderr.write(f"[*] Starting passive scan for: {self.target}\n")
            
            # 1. Subdomain Enumeration
            self.results["subdomains"] = self.enumerate_subdomains()
            
            # 2. DNS Records
            self.results["dns_records"] = self.get_dns_records()
            
            # 3. Technology Fingerprinting
            self.results["technologies"] = self.fingerprint_technologies()
            
            # 4. Historical URLs
            self.results["historical_urls"] = self.get_historical_urls()
            
            # 5. ASN/IP Information
            self.results["asn"] = self.get_asn_info()
            
            # 6. Leak Detection
            self.results["leaks"] = self.detect_leaks()
            
            self.results["status"] = "completed"
            sys.stderr.write(f"[+] Passive scan completed for: {self.target}\n")
            
        except Exception as e:
            sys.stderr.write(f"[!] Error during passive scan: {str(e)}\n")
            self.results["status"] = "failed"
            self.results["error"] = str(e)
        
        return self.results
    
    def enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using multiple sources"""
        subdomains = set()
        
        try:
            # Method 1: crt.sh (Certificate Transparency Logs)
            sys.stderr.write("[*] Checking Certificate Transparency logs...\n")
            crt_subdomains = self._crtsh_search()
            subdomains.update(crt_subdomains)
            
            # Method 2: DNS Dumpster API alternative - using common subdomains
            sys.stderr.write("[*] Checking common subdomains...\n")
            common_subdomains = self._check_common_subdomains()
            subdomains.update(common_subdomains)
            
            # Method 3: Subfinder (if available)
            sys.stderr.write("[*] Attempting subfinder...\n")
            subfinder_results = self._run_subfinder()
            subdomains.update(subfinder_results)
            
        except Exception as e:
            sys.stderr.write(f"[!] Subdomain enumeration error: {str(e)}\n")
        
        return sorted(list(subdomains))
    
    def _crtsh_search(self) -> List[str]:
        """Search Certificate Transparency logs via crt.sh"""
        subdomains = []
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Split by newlines (crt.sh returns multiple domains per entry)
                    for domain in name.split('\n'):
                        domain = domain.strip().lower()
                        if domain.endswith(self.target) and '*' not in domain:
                            subdomains.append(domain)
        except Exception as e:
            sys.stderr.write(f"[!] crt.sh error: {str(e)}\n")
        
        return list(set(subdomains))
    
    def _check_common_subdomains(self) -> List[str]:
        """Check common subdomain names"""
        common = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'webdisk', 'ns', 'news', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'api', 'dev', 'staging', 'test', 'admin', 'portal', 'blog', 'shop',
            'store', 'mobile', 'app', 'cdn', 'static', 'assets', 'images', 'img'
        ]
        
        found = []
        for sub in common:
            subdomain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
                sys.stderr.write(f"  [+] Found: {subdomain}\n")
            except socket.gaierror:
                pass
        
        return found
    
    def _run_subfinder(self) -> List[str]:
        """Run subfinder if available"""
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.target, '-silent'],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.split('\n') if line.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            sys.stderr.write("[!] Subfinder not available or timed out\n")
        
        return []
    
    def get_dns_records(self) -> List[Dict[str, str]]:
        """Retrieve DNS records for the target"""
        records = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                for rdata in answers:
                    records.append({
                        'type': record_type,
                        'value': str(rdata)
                    })
                    sys.stderr.write(f"  [+] {record_type}: {str(rdata)}\n")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception as e:
                sys.stderr.write(f"[!] DNS query error for {record_type}: {str(e)}\n")
        
        return records
    
    def fingerprint_technologies(self) -> Dict[str, str]:
        """Detect technologies used by the target"""
        technologies = {}
        
        try:
            # Try to fetch the website
            url = f"http://{self.target}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            # Check server header
            if 'Server' in response.headers:
                technologies['Server'] = response.headers['Server']
            
            # Check X-Powered-By
            if 'X-Powered-By' in response.headers:
                technologies['X-Powered-By'] = response.headers['X-Powered-By']
            
            # Check for common frameworks in HTML
            html = response.text.lower()
            
            # WordPress
            if 'wp-content' in html or 'wordpress' in html:
                technologies['CMS'] = 'WordPress'
            
            # Joomla
            if 'joomla' in html:
                technologies['CMS'] = 'Joomla'
            
            # Drupal
            if 'drupal' in html:
                technologies['CMS'] = 'Drupal'
            
            # React
            if 'react' in html or '__react' in html:
                technologies['Frontend'] = 'React'
            
            # Vue.js
            if 'vue' in html or 'v-app' in html:
                technologies['Frontend'] = 'Vue.js'
            
            # Angular
            if 'ng-app' in html or 'angular' in html:
                technologies['Frontend'] = 'Angular'
            
            # jQuery
            if 'jquery' in html:
                technologies['JavaScript Library'] = 'jQuery'
            
            # Bootstrap
            if 'bootstrap' in html:
                technologies['CSS Framework'] = 'Bootstrap'
            
            # Check for common cookies
            if response.cookies:
                for cookie in response.cookies:
                    if 'PHPSESSID' in cookie.name:
                        technologies['Backend'] = 'PHP'
                    elif 'JSESSIONID' in cookie.name:
                        technologies['Backend'] = 'Java/JSP'
                    elif 'ASP.NET' in cookie.name:
                        technologies['Backend'] = 'ASP.NET'
            
            sys.stderr.write(f"[+] Detected {len(technologies)} technologies\n")
            
        except Exception as e:
            sys.stderr.write(f"[!] Technology fingerprinting error: {str(e)}\n")
        
        return technologies
    
    def get_historical_urls(self) -> List[str]:
        """Fetch historical URLs from Wayback Machine"""
        urls = []
        
        try:
            # Wayback Machine CDX API
            sys.stderr.write("[*] Querying Wayback Machine...\n")
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={self.target}/*&output=json&fl=original&collapse=urlkey&limit=100"
            
            response = requests.get(wayback_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                # Skip header row
                for entry in data[1:]:
                    if entry and entry[0]:
                        urls.append(entry[0])
            
            sys.stderr.write(f"[+] Found {len(urls)} historical URLs\n")
            
        except Exception as e:
            sys.stderr.write(f"[!] Historical URL retrieval error: {str(e)}\n")
        
        return urls[:50]  # Limit to 50 URLs
    
    def get_asn_info(self) -> Dict[str, str]:
        """Get ASN and IP information"""
        asn_info = {}
        
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(self.target)
            asn_info['IP Address'] = ip
            
            # Get IP geolocation info using ip-api.com
            sys.stderr.write(f"[*] Resolving ASN info for {ip}...\n")
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                asn_info['ASN'] = str(data.get('as', 'N/A'))
                asn_info['ISP'] = data.get('isp', 'N/A')
                asn_info['Organization'] = data.get('org', 'N/A')
                asn_info['Country'] = data.get('country', 'N/A')
                asn_info['Region'] = data.get('regionName', 'N/A')
                asn_info['City'] = data.get('city', 'N/A')
            
            # Try WHOIS
            try:
                w = whois.whois(self.target)
                if w.registrar:
                    asn_info['Registrar'] = w.registrar
                if w.creation_date:
                    date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    asn_info['Created'] = str(date)
            except Exception as e:
                sys.stderr.write(f"[!] WHOIS error: {str(e)}\n")
            
            sys.stderr.write(f"[+] Retrieved ASN information\n")
            
        except Exception as e:
            sys.stderr.write(f"[!] ASN info error: {str(e)}\n")
        
        return asn_info
    
    def detect_leaks(self) -> List[str]:
        """Detect potential leaks (GitHub, S3 buckets, etc.)"""
        leaks = []
        
        try:
            # Check for common S3 bucket patterns
            sys.stderr.write("[*] Checking for S3 bucket leaks...\n")
            bucket_patterns = [
                self.target.replace('.', '-'),
                self.target.replace('.', ''),
                self.target.split('.')[0],
                f"{self.target.split('.')[0]}-backup",
                f"{self.target.split('.')[0]}-assets",
                f"{self.target.split('.')[0]}-static"
            ]
            
            for pattern in bucket_patterns:
                bucket_url = f"https://{pattern}.s3.amazonaws.com"
                try:
                    response = requests.head(bucket_url, timeout=5)
                    if response.status_code in [200, 403]:  # 403 means bucket exists but private
                        leaks.append(f"S3 Bucket: {bucket_url}")
                        sys.stderr.write(f"  [+] Found S3 bucket: {bucket_url}\n")
                except:
                    pass
            
            # GitHub search would require API token, so we'll note it as a manual check
            leaks.append(f"Manual Check: Search GitHub for '{self.target}'")
            
            # Check for common exposed files
            sys.stderr.write("[*] Checking for exposed files...\n")
            common_files = [
                '/.git/config',
                '/.env',
                '/config.json',
                '/backup.sql',
                '/.aws/credentials'
            ]
            
            for file_path in common_files:
                try:
                    url = f"http://{self.target}{file_path}"
                    response = requests.head(url, timeout=5)
                    if response.status_code == 200:
                        leaks.append(f"Exposed file: {url}")
                        sys.stderr.write(f"  [!] Exposed file found: {url}\n")
                except:
                    pass
            
        except Exception as e:
            sys.stderr.write(f"[!] Leak detection error: {str(e)}\n")
        
        return leaks


def test_passive_recon():
    """Test function"""
    target = "example.com"
    recon = PassiveRecon(target)
    results = recon.run_full_scan()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    test_passive_recon()
