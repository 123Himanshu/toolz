#!/usr/bin/env python3
"""
Enhanced Passive Reconnaissance Module
Follows the complete workflow with proper tool integration
"""

import subprocess
import json
import dns.resolver
import requests
import socket
from typing import Dict, List, Any, Set
import re
from urllib.parse import urlparse
import whois
from datetime import datetime
import time
import logging
import urllib3

# Disable SSL warnings for passive recon
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class PassiveReconEngine:
    """Complete passive reconnaissance engine with all tools"""
    
    def __init__(self, target: str):
        self.target = self._clean_domain(target)
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
            "timestamp": int(time.time())
        }
        
        # Check available tools
        self.available_tools = self._check_tools()
        logger.info(f"Available tools: {self.available_tools}")
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and validate domain"""
        domain = domain.strip().lower()
        # Remove protocol if present
        domain = re.sub(r'^https?://', '', domain)
        # Remove path if present
        domain = domain.split('/')[0]
        # Remove port if present
        domain = domain.split(':')[0]
        return domain
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available"""
        tools = {}
        
        # Check subfinder
        try:
            subprocess.run(['subfinder', '-version'], 
                         capture_output=True, timeout=5)
            tools['subfinder'] = True
        except:
            tools['subfinder'] = False
        
        # Check assetfinder
        try:
            subprocess.run(['assetfinder', '--help'], 
                         capture_output=True, timeout=5)
            tools['assetfinder'] = True
        except:
            tools['assetfinder'] = False
        
        # Check amass
        try:
            subprocess.run(['amass', 'enum', '-h'], 
                         capture_output=True, timeout=5)
            tools['amass'] = True
        except:
            tools['amass'] = False
        
        return tools
    
    def run_full_scan(self) -> Dict[str, Any]:
        """Execute complete passive reconnaissance workflow"""
        try:
            logger.info(f"[STEP 1] Starting passive scan for: {self.target}")
            
            # STEP 2: Subdomain Enumeration (Passive Only)
            logger.info("[STEP 2] Subdomain Enumeration...")
            self.results["subdomains"] = self._enumerate_subdomains()
            
            # STEP 3: DNS Enumeration (Passive)
            logger.info("[STEP 3] DNS Enumeration...")
            self.results["dns_records"] = self._enumerate_dns()
            
            # STEP 4: Technology Fingerprinting (Passive)
            logger.info("[STEP 4] Technology Fingerprinting...")
            self.results["technologies"] = self._fingerprint_technologies()
            
            # STEP 5: Historical URL Harvesting
            logger.info("[STEP 5] Historical URL Harvesting...")
            self.results["historical_urls"] = self._harvest_historical_urls()
            
            # STEP 6: IP & ASN Discovery
            logger.info("[STEP 6] IP & ASN Discovery...")
            self.results["asn"] = self._discover_asn()
            
            # STEP 7: Leak Detection
            logger.info("[STEP 7] Leak Detection...")
            self.results["leaks"] = self._detect_leaks()
            
            # STEP 8: Normalize results
            self.results["status"] = "completed"
            self.results["timestamp"] = int(time.time())
            
            logger.info(f"[COMPLETE] Passive scan finished for: {self.target}")
            
        except Exception as e:
            logger.error(f"[ERROR] Passive scan failed: {str(e)}")
            self.results["status"] = "failed"
            self.results["error"] = str(e)
        
        return self.results
    
    # ========================================================================
    # STEP 2: SUBDOMAIN ENUMERATION (PASSIVE ONLY)
    # ========================================================================
    
    def _enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using multiple passive sources"""
        subdomains: Set[str] = set()
        
        # Method 1: Subfinder (passive mode)
        if self.available_tools.get('subfinder'):
            logger.info("  → Running Subfinder (passive)...")
            subs = self._run_subfinder_passive()
            subdomains.update(subs)
            logger.info(f"    Found {len(subs)} subdomains via Subfinder")
        
        # Method 2: Assetfinder
        if self.available_tools.get('assetfinder'):
            logger.info("  → Running Assetfinder...")
            subs = self._run_assetfinder()
            subdomains.update(subs)
            logger.info(f"    Found {len(subs)} subdomains via Assetfinder")
        
        # Method 3: Amass (passive)
        if self.available_tools.get('amass'):
            logger.info("  → Running Amass (passive)...")
            subs = self._run_amass_passive()
            subdomains.update(subs)
            logger.info(f"    Found {len(subs)} subdomains via Amass")
        
        # Method 4: crt.sh (Certificate Transparency)
        logger.info("  → Querying crt.sh (CT logs)...")
        subs = self._query_crtsh()
        subdomains.update(subs)
        logger.info(f"    Found {len(subs)} subdomains via crt.sh")
        
        # Method 5: Common subdomains (fallback)
        logger.info("  → Checking common subdomains...")
        subs = self._check_common_subdomains()
        subdomains.update(subs)
        logger.info(f"    Found {len(subs)} common subdomains")
        
        # Unique and sorted
        final_subdomains = sorted(list(subdomains))
        logger.info(f"  ✓ Total unique subdomains: {len(final_subdomains)}")
        
        return final_subdomains
    
    def _run_subfinder_passive(self) -> List[str]:
        """Run subfinder in passive mode"""
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.target, '-silent', '-all'],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.split('\n') 
                       if line.strip() and line.strip().endswith(self.target)]
        except Exception as e:
            logger.warning(f"Subfinder failed: {str(e)}")
        return []
    
    def _run_assetfinder(self) -> List[str]:
        """Run assetfinder"""
        try:
            result = subprocess.run(
                ['assetfinder', '--subs-only', self.target],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.split('\n') 
                       if line.strip()]
        except Exception as e:
            logger.warning(f"Assetfinder failed: {str(e)}")
        return []
    
    def _run_amass_passive(self) -> List[str]:
        """Run amass in passive mode"""
        try:
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', self.target, '-silent'],
                capture_output=True,
                text=True,
                timeout=180
            )
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.split('\n') 
                       if line.strip()]
        except Exception as e:
            logger.warning(f"Amass failed: {str(e)}")
        return []
    
    def _query_crtsh(self) -> List[str]:
        """Query Certificate Transparency logs via crt.sh"""
        subdomains = []
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for domain in name.split('\n'):
                        domain = domain.strip().lower()
                        if domain.endswith(self.target) and '*' not in domain:
                            subdomains.append(domain)
        except Exception as e:
            logger.warning(f"crt.sh query failed: {str(e)}")
        
        return list(set(subdomains))
    
    def _check_common_subdomains(self) -> List[str]:
        """Check common subdomain names"""
        common = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'webdisk', 'ns', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'api', 'dev', 'staging', 'test', 'admin', 'portal', 'blog',
            'shop', 'store', 'mobile', 'app', 'cdn', 'static', 'assets',
            'images', 'img', 'vpn', 'remote', 'secure', 'login', 'dashboard'
        ]
        
        found = []
        for sub in common:
            subdomain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
            except socket.gaierror:
                pass
        
        return found
    
    # ========================================================================
    # STEP 3: DNS ENUMERATION (PASSIVE)
    # ========================================================================
    
    def _enumerate_dns(self) -> List[Dict[str, str]]:
        """Enumerate DNS records"""
        records = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                for rdata in answers:
                    records.append({
                        'type': record_type,
                        'value': str(rdata).rstrip('.')
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
                   dns.exception.Timeout, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                logger.warning(f"DNS query error for {record_type}: {str(e)}")
        
        # Try DNSDumpster API (if available)
        dumpster_records = self._query_dnsdumpster()
        records.extend(dumpster_records)
        
        logger.info(f"  ✓ Found {len(records)} DNS records")
        return records
    
    def _query_dnsdumpster(self) -> List[Dict[str, str]]:
        """Query DNSDumpster (passive DNS)"""
        # DNSDumpster requires CSRF token and session handling
        # For now, we'll skip this or implement if needed
        return []
    
    # ========================================================================
    # STEP 4: TECHNOLOGY FINGERPRINTING (PASSIVE)
    # ========================================================================
    
    def _fingerprint_technologies(self) -> Dict[str, List[str]]:
        """Detect technologies used by the target"""
        technologies = {
            "frontend": [],
            "cms": [],
            "server": [],
            "cdn": [],
            "frameworks": [],
            "tracking": [],
            "javascript": [],
            "css": []
        }
        
        try:
            # Try HTTP and HTTPS
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{self.target}"
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    
                    response = requests.get(url, headers=headers, timeout=10, 
                                          allow_redirects=True, verify=False)
                    
                    # Analyze headers
                    self._analyze_headers(response.headers, technologies)
                    
                    # Analyze HTML content
                    self._analyze_html(response.text, technologies)
                    
                    # Analyze cookies
                    self._analyze_cookies(response.cookies, technologies)
                    
                    break  # Success, no need to try other protocol
                    
                except requests.exceptions.SSLError:
                    continue
                except requests.exceptions.ConnectionError:
                    continue
                except Exception as e:
                    logger.warning(f"Technology fingerprinting error ({protocol}): {str(e)}")
                    continue
        
        except Exception as e:
            logger.warning(f"Technology fingerprinting failed: {str(e)}")
        
        # Clean up empty categories
        technologies = {k: v for k, v in technologies.items() if v}
        
        logger.info(f"  ✓ Detected {sum(len(v) for v in technologies.values())} technologies")
        return technologies
    
    def _analyze_headers(self, headers, technologies):
        """Analyze HTTP headers for technology detection"""
        # Server
        if 'Server' in headers:
            server = headers['Server']
            technologies['server'].append(server)
            
            # Detect specific servers
            if 'nginx' in server.lower():
                technologies['server'].append('Nginx')
            elif 'apache' in server.lower():
                technologies['server'].append('Apache')
            elif 'cloudflare' in server.lower():
                technologies['cdn'].append('Cloudflare')
        
        # X-Powered-By
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            technologies['frameworks'].append(powered_by)
            
            if 'PHP' in powered_by:
                technologies['frameworks'].append('PHP')
            elif 'ASP.NET' in powered_by:
                technologies['frameworks'].append('ASP.NET')
        
        # CDN detection
        if 'CF-Ray' in headers or 'cf-ray' in headers:
            technologies['cdn'].append('Cloudflare')
        if 'X-Amz-Cf-Id' in headers:
            technologies['cdn'].append('Amazon CloudFront')
        if 'X-CDN' in headers:
            technologies['cdn'].append(headers['X-CDN'])
    
    def _analyze_html(self, html, technologies):
        """Analyze HTML content for technology detection"""
        html_lower = html.lower()
        
        # CMS Detection
        if 'wp-content' in html_lower or 'wordpress' in html_lower:
            technologies['cms'].append('WordPress')
        if 'joomla' in html_lower:
            technologies['cms'].append('Joomla')
        if 'drupal' in html_lower:
            technologies['cms'].append('Drupal')
        if 'shopify' in html_lower:
            technologies['cms'].append('Shopify')
        if 'wix.com' in html_lower:
            technologies['cms'].append('Wix')
        
        # Frontend Frameworks
        if 'react' in html_lower or '__react' in html_lower or 'data-reactroot' in html_lower:
            technologies['frontend'].append('React')
        if 'vue' in html_lower or 'v-app' in html_lower or 'data-v-' in html_lower:
            technologies['frontend'].append('Vue.js')
        if 'ng-app' in html_lower or 'angular' in html_lower or 'ng-version' in html_lower:
            technologies['frontend'].append('Angular')
        if 'next.js' in html_lower or '__next' in html_lower:
            technologies['frontend'].append('Next.js')
        if 'nuxt' in html_lower:
            technologies['frontend'].append('Nuxt.js')
        
        # JavaScript Libraries
        if 'jquery' in html_lower:
            technologies['javascript'].append('jQuery')
        if 'bootstrap' in html_lower:
            technologies['css'].append('Bootstrap')
        if 'tailwind' in html_lower:
            technologies['css'].append('Tailwind CSS')
        
        # Tracking & Analytics
        if 'google-analytics' in html_lower or 'gtag' in html_lower or 'ga(' in html_lower:
            technologies['tracking'].append('Google Analytics')
        if 'googletagmanager' in html_lower:
            technologies['tracking'].append('Google Tag Manager')
        if 'facebook.com/tr' in html_lower or 'fbq(' in html_lower:
            technologies['tracking'].append('Facebook Pixel')
        if 'hotjar' in html_lower:
            technologies['tracking'].append('Hotjar')
    
    def _analyze_cookies(self, cookies, technologies):
        """Analyze cookies for technology detection"""
        for cookie in cookies:
            cookie_name = cookie.name.lower()
            
            if 'phpsessid' in cookie_name:
                technologies['frameworks'].append('PHP')
            elif 'jsessionid' in cookie_name:
                technologies['frameworks'].append('Java/JSP')
            elif 'asp.net' in cookie_name:
                technologies['frameworks'].append('ASP.NET')
            elif '__cfduid' in cookie_name or 'cf_' in cookie_name:
                technologies['cdn'].append('Cloudflare')
    
    # ========================================================================
    # STEP 5: HISTORICAL URL HARVESTING
    # ========================================================================
    
    def _harvest_historical_urls(self) -> List[str]:
        """Harvest historical URLs from Wayback Machine and CommonCrawl"""
        urls = []
        
        # Wayback Machine
        logger.info("  → Querying Wayback Machine...")
        wayback_urls = self._query_wayback()
        urls.extend(wayback_urls)
        logger.info(f"    Found {len(wayback_urls)} URLs from Wayback")
        
        # CommonCrawl (optional - requires more complex API)
        # logger.info("  → Querying CommonCrawl...")
        # commoncrawl_urls = self._query_commoncrawl()
        # urls.extend(commoncrawl_urls)
        
        # Unique and limit
        urls = list(set(urls))[:100]  # Limit to 100 URLs
        
        logger.info(f"  ✓ Total historical URLs: {len(urls)}")
        return urls
    
    def _query_wayback(self) -> List[str]:
        """Query Wayback Machine CDX API"""
        urls = []
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={self.target}/*&output=json&fl=original&collapse=urlkey&limit=100"
            
            response = requests.get(wayback_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                # Skip header row
                for entry in data[1:]:
                    if entry and entry[0]:
                        urls.append(entry[0])
        except Exception as e:
            logger.warning(f"Wayback query failed: {str(e)}")
        
        return urls
    
    # ========================================================================
    # STEP 6: IP & ASN DISCOVERY
    # ========================================================================
    
    def _discover_asn(self) -> Dict[str, Any]:
        """Discover IP and ASN information"""
        asn_info = {}
        
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(self.target)
            asn_info['ip'] = ip
            
            # Get ASN info from ipinfo.io
            logger.info(f"  → Querying ipinfo.io for {ip}...")
            ipinfo_data = self._query_ipinfo(ip)
            asn_info.update(ipinfo_data)
            
            # Get WHOIS data
            logger.info("  → Querying WHOIS...")
            whois_data = self._query_whois()
            asn_info.update(whois_data)
            
            logger.info(f"  ✓ ASN discovery complete")
            
        except Exception as e:
            logger.warning(f"ASN discovery failed: {str(e)}")
        
        return asn_info
    
    def _query_ipinfo(self, ip: str) -> Dict[str, Any]:
        """Query ipinfo.io for IP information"""
        info = {}
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract ASN number from org field (e.g., "AS13335 Cloudflare")
                org = data.get('org', '')
                asn_match = re.match(r'AS(\d+)\s+(.*)', org)
                
                if asn_match:
                    info['asn_number'] = int(asn_match.group(1))
                    info['provider'] = asn_match.group(2)
                else:
                    info['provider'] = org
                
                info['country'] = data.get('country', 'N/A')
                info['region'] = data.get('region', 'N/A')
                info['city'] = data.get('city', 'N/A')
                info['hostname'] = data.get('hostname', 'N/A')
                
        except Exception as e:
            logger.warning(f"ipinfo.io query failed: {str(e)}")
        
        return info
    
    def _query_whois(self) -> Dict[str, Any]:
        """Query WHOIS for domain information"""
        info = {}
        try:
            w = whois.whois(self.target)
            
            if w.registrar:
                info['registrar'] = w.registrar
            
            if w.creation_date:
                date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                info['created'] = str(date)
            
            if w.expiration_date:
                date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                info['expires'] = str(date)
            
            if w.name_servers:
                info['nameservers'] = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                
        except Exception as e:
            logger.warning(f"WHOIS query failed: {str(e)}")
        
        return info
    
    # ========================================================================
    # STEP 7: LEAK DETECTION
    # ========================================================================
    
    def _detect_leaks(self) -> List[Dict[str, Any]]:
        """Detect potential leaks (GitHub, S3 buckets, exposed files)"""
        leaks = []
        
        # S3 Bucket Detection
        logger.info("  → Checking for S3 buckets...")
        s3_leaks = self._check_s3_buckets()
        leaks.extend(s3_leaks)
        logger.info(f"    Found {len(s3_leaks)} potential S3 buckets")
        
        # Exposed Files
        logger.info("  → Checking for exposed files...")
        file_leaks = self._check_exposed_files()
        leaks.extend(file_leaks)
        logger.info(f"    Found {len(file_leaks)} exposed files")
        
        # GitHub Dorks (manual check recommendation)
        leaks.append({
            "type": "github",
            "description": f"Manual check: Search GitHub for '{self.target}'",
            "risk": "medium",
            "url": f"https://github.com/search?q={self.target}"
        })
        
        logger.info(f"  ✓ Total leaks detected: {len(leaks)}")
        return leaks
    
    def _check_s3_buckets(self) -> List[Dict[str, Any]]:
        """Check for publicly accessible S3 buckets"""
        leaks = []
        
        bucket_patterns = [
            self.target.replace('.', '-'),
            self.target.replace('.', ''),
            self.target.split('.')[0],
            f"{self.target.split('.')[0]}-backup",
            f"{self.target.split('.')[0]}-assets",
            f"{self.target.split('.')[0]}-static",
            f"{self.target.split('.')[0]}-prod",
            f"{self.target.split('.')[0]}-dev"
        ]
        
        for pattern in bucket_patterns:
            bucket_url = f"https://{pattern}.s3.amazonaws.com"
            try:
                response = requests.head(bucket_url, timeout=5)
                if response.status_code in [200, 403]:
                    risk = "high" if response.status_code == 200 else "medium"
                    leaks.append({
                        "type": "s3_bucket",
                        "url": bucket_url,
                        "status": "public" if response.status_code == 200 else "exists_private",
                        "risk": risk
                    })
            except:
                pass
        
        return leaks
    
    def _check_exposed_files(self) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files"""
        leaks = []
        
        sensitive_files = [
            ('/.git/config', 'git_config', 'high'),
            ('/.env', 'env_file', 'critical'),
            ('/config.json', 'config_file', 'high'),
            ('/backup.sql', 'database_backup', 'critical'),
            ('/.aws/credentials', 'aws_credentials', 'critical'),
            ('/wp-config.php.bak', 'wordpress_backup', 'high'),
            ('/.htaccess', 'htaccess', 'medium'),
            ('/phpinfo.php', 'phpinfo', 'high'),
            ('/admin', 'admin_panel', 'medium'),
            ('/.DS_Store', 'ds_store', 'low')
        ]
        
        for file_path, file_type, risk in sensitive_files:
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{self.target}{file_path}"
                    response = requests.head(url, timeout=5, allow_redirects=False)
                    
                    if response.status_code == 200:
                        leaks.append({
                            "type": "exposed_file",
                            "file_type": file_type,
                            "url": url,
                            "risk": risk
                        })
                        break  # Found, no need to try other protocol
                except:
                    pass
        
        return leaks


def test_passive_recon():
    """Test function"""
    target = "example.com"
    engine = PassiveReconEngine(target)
    results = engine.run_full_scan()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    test_passive_recon()
