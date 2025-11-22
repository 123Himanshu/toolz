"""
Nuclei Security Scanner - Python Wrapper
A professional Python interface for the Nuclei vulnerability scanner

Author: Security Team
Date: 2024
"""

import subprocess
import json
import os
from pathlib import Path
from typing import List, Dict, Optional, Union
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NucleiScanner:
    """
    Python wrapper for Nuclei security scanner
    
    Supports both Docker and binary execution modes
    """
    
    def __init__(self, 
                 use_docker: bool = True,
                 binary_path: Optional[str] = None,
                 docker_image: str = "projectdiscovery/nuclei:latest"):
        """
        Initialize Nuclei scanner
        
        Args:
            use_docker: Use Docker image (recommended)
            binary_path: Path to nuclei binary if not using Docker
            docker_image: Docker image name
        """
        self.use_docker = use_docker
        self.binary_path = binary_path or "nuclei"
        self.docker_image = docker_image
        self.scan_history = []
        
        logger.info(f"Initialized Nuclei Scanner (Docker: {use_docker})")
    
    def scan(self,
             target: str,
             templates: Optional[str] = None,
             severity: Optional[List[str]] = None,
             output_file: Optional[str] = None,
             json_output: bool = True,
             verbose: bool = False,
             rate_limit: Optional[int] = None,
             concurrency: int = 25,
             timeout: int = 5,
             retries: int = 1,
             proxy: Optional[str] = None,
             headers: Optional[List[str]] = None,
             tags: Optional[List[str]] = None,
             exclude_tags: Optional[List[str]] = None,
             author: Optional[List[str]] = None,
             include_templates: Optional[List[str]] = None,
             exclude_templates: Optional[List[str]] = None,
             workflows: Optional[str] = None,
             no_color: bool = True,
             silent: bool = False,
             stats: bool = False,
             update_templates: bool = False,
             # Additional Nuclei features
             follow_redirects: bool = False,
             follow_host_redirects: bool = False,
             max_redirects: int = 10,
             disable_redirects: bool = False,
             report_config: Optional[str] = None,
             variables: Optional[Dict[str, str]] = None,
             system_resolvers: bool = False,
             passive: bool = False,
             env_vars: bool = False,
             client_cert: Optional[str] = None,
             client_key: Optional[str] = None,
             client_ca: Optional[str] = None,
             ztls: bool = False,
             sni: Optional[str] = None,
             sandbox: bool = False,
             interface: Optional[str] = None,
             attack_type: Optional[str] = None,
             source_ip: Optional[str] = None,
             config: Optional[str] = None,
             interactsh_server: Optional[str] = None,
             no_interactsh: bool = False,
             interactions_cache_size: int = 5000,
             interactions_eviction: int = 60,
             interactions_poll_duration: int = 5,
             interactions_cooldown_period: int = 5,
             no_httpx: bool = False,
             no_stdin: bool = False,
             max_host_error: int = 30,
             track_error: Optional[str] = None,
             bulk_size: int = 25,
             template_threads: int = 25) -> Dict:
        """
        Run Nuclei vulnerability scan with FULL feature support
        
        Args:
            target: Target URL or host (e.g., 'https://example.com')
            templates: Template or template directory to use
            severity: Filter by severity (critical, high, medium, low, info)
            output_file: Output file for results
            json_output: Output in JSON format
            verbose: Enable verbose output
            rate_limit: Maximum requests per second
            concurrency: Maximum number of templates to run concurrently
            timeout: Timeout in seconds
            retries: Number of retries for failed requests
            proxy: Proxy URL (e.g., 'http://127.0.0.1:8080')
            headers: Custom headers (e.g., ['X-Custom: value'])
            tags: Filter templates by tags
            exclude_tags: Exclude templates by tags
            author: Filter templates by author
            include_templates: Include specific templates
            exclude_templates: Exclude specific templates
            workflows: Workflow file or directory
            no_color: Disable colored output
            silent: Silent mode (only show findings)
            stats: Show scan statistics
            update_templates: Update templates before scanning
            follow_redirects: Follow all redirects
            follow_host_redirects: Follow redirects on same host
            max_redirects: Maximum redirects to follow
            disable_redirects: Disable redirect following
            report_config: Report configuration file
            variables: Template variables (e.g., {'key': 'value'})
            system_resolvers: Use system DNS resolvers
            passive: Enable passive HTTP response processing
            env_vars: Enable environment variables support
            client_cert: Client certificate file
            client_key: Client key file
            client_ca: Client CA certificate file
            ztls: Use ztls library
            sni: TLS SNI hostname
            sandbox: Enable sandbox mode
            interface: Network interface to use
            attack_type: Attack type (batteringram, pitchfork, clusterbomb)
            source_ip: Source IP address
            config: Nuclei configuration file
            interactsh_server: Interactsh server URL
            no_interactsh: Disable interactsh
            interactions_cache_size: Interactions cache size
            interactions_eviction: Interactions eviction time
            interactions_poll_duration: Interactions poll duration
            interactions_cooldown_period: Interactions cooldown period
            no_httpx: Disable httpx probe
            no_stdin: Disable stdin processing
            max_host_error: Maximum host errors
            track_error: Track error file
            bulk_size: Bulk size for parallel processing
            template_threads: Template threads
            
        Returns:
            Dict containing scan results and metadata
        """
        logger.info(f"Starting Nuclei scan on {target}")
        
        # Build command with ALL parameters
        params = locals().copy()
        params.pop('self', None)
        cmd = self._build_command(**params)
        
        # Execute scan
        start_time = datetime.now()
        logger.debug(f"Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Parse results
        vulnerabilities = []
        if json_output and result.stdout:
            # Parse JSON output (one JSON object per line)
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        pass
        
        scan_result = {
            'success': result.returncode == 0,
            'target': target,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'output_file': output_file
        }
        
        self.scan_history.append(scan_result)
        
        if scan_result['success']:
            logger.info(f"Scan completed in {duration:.2f}s - Found {len(vulnerabilities)} issues")
        else:
            logger.error(f"Scan failed: {result.stderr}")
        
        return scan_result

    
    def scan_multiple(self, 
                     targets: List[str],
                     **kwargs) -> List[Dict]:
        """
        Scan multiple targets
        
        Args:
            targets: List of target URLs
            **kwargs: Additional arguments passed to scan()
            
        Returns:
            List of scan results
        """
        logger.info(f"Starting batch scan of {len(targets)} targets")
        results = []
        
        for i, target in enumerate(targets, 1):
            logger.info(f"[{i}/{len(targets)}] Scanning {target}")
            result = self.scan(target, **kwargs)
            results.append(result)
        
        logger.info(f"Batch scan completed: {len(results)} targets scanned")
        return results
    
    def scan_from_file(self,
                      file_path: str,
                      **kwargs) -> List[Dict]:
        """
        Scan targets from a file (one URL per line)
        
        Args:
            file_path: Path to file containing URLs
            **kwargs: Additional arguments passed to scan()
            
        Returns:
            List of scan results
        """
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        return self.scan_multiple(targets, **kwargs)
    
    def quick_scan(self, target: str) -> Dict:
        """
        Quick vulnerability scan with high/critical severity only
        
        Args:
            target: Target URL
            
        Returns:
            Scan results
        """
        return self.scan(
            target=target,
            severity=['critical', 'high'],
            silent=True,
            json_output=True
        )
    
    def full_scan(self, target: str) -> Dict:
        """
        Comprehensive vulnerability scan with all templates
        
        Args:
            target: Target URL
            
        Returns:
            Scan results
        """
        return self.scan(
            target=target,
            severity=['critical', 'high', 'medium', 'low', 'info'],
            verbose=True,
            json_output=True,
            stats=True
        )
    
    def cve_scan(self, target: str, year: Optional[str] = None) -> Dict:
        """
        Scan for CVE vulnerabilities
        
        Args:
            target: Target URL
            year: Specific CVE year (e.g., '2024', '2023')
            
        Returns:
            Scan results
        """
        tags = ['cve']
        if year:
            tags.append(f'cve-{year}')
        
        return self.scan(
            target=target,
            tags=tags,
            json_output=True
        )
    
    def technology_scan(self, target: str, technology: str) -> Dict:
        """
        Scan for specific technology vulnerabilities
        
        Args:
            target: Target URL
            technology: Technology name (e.g., 'wordpress', 'jira', 'jenkins')
            
        Returns:
            Scan results
        """
        return self.scan(
            target=target,
            tags=[technology],
            json_output=True
        )
    
    def _build_command(self, **kwargs) -> List[str]:
        """Build command line arguments with FULL Nuclei feature support"""
        # Remove 'self' from kwargs if present
        kwargs.pop('self', None)
        
        if self.use_docker:
            cmd = ['docker', 'run', '--rm', self.docker_image]
        else:
            cmd = [self.binary_path]
        
        # Target
        cmd.extend(['-u', kwargs['target']])
        
        # Templates
        if kwargs.get('templates'):
            cmd.extend(['-t', kwargs['templates']])
        
        # Severity
        if kwargs.get('severity'):
            for sev in kwargs['severity']:
                cmd.extend(['-s', sev])
        
        # Output
        if kwargs.get('output_file'):
            cmd.extend(['-o', kwargs['output_file']])
        
        # JSON output
        if kwargs.get('json_output'):
            cmd.append('-jsonl')
        
        # Verbose
        if kwargs.get('verbose'):
            cmd.append('-v')
        
        # Rate limit
        if kwargs.get('rate_limit'):
            cmd.extend(['-rl', str(kwargs['rate_limit'])])
        
        # Concurrency
        if kwargs.get('concurrency'):
            cmd.extend(['-c', str(kwargs['concurrency'])])
        
        # Timeout
        if kwargs.get('timeout'):
            cmd.extend(['-timeout', str(kwargs['timeout'])])
        
        # Retries
        if kwargs.get('retries'):
            cmd.extend(['-retries', str(kwargs['retries'])])
        
        # Proxy
        if kwargs.get('proxy'):
            cmd.extend(['-proxy', kwargs['proxy']])
        
        # Headers
        if kwargs.get('headers'):
            for header in kwargs['headers']:
                cmd.extend(['-H', header])
        
        # Tags
        if kwargs.get('tags'):
            cmd.extend(['-tags', ','.join(kwargs['tags'])])
        
        # Exclude tags
        if kwargs.get('exclude_tags'):
            cmd.extend(['-etags', ','.join(kwargs['exclude_tags'])])
        
        # Author
        if kwargs.get('author'):
            cmd.extend(['-author', ','.join(kwargs['author'])])
        
        # Include templates
        if kwargs.get('include_templates'):
            for template in kwargs['include_templates']:
                cmd.extend(['-it', template])
        
        # Exclude templates
        if kwargs.get('exclude_templates'):
            for template in kwargs['exclude_templates']:
                cmd.extend(['-et', template])
        
        # Workflows
        if kwargs.get('workflows'):
            cmd.extend(['-w', kwargs['workflows']])
        
        # No color
        if kwargs.get('no_color'):
            cmd.append('-nc')
        
        # Silent
        if kwargs.get('silent'):
            cmd.append('-silent')
        
        # Stats
        if kwargs.get('stats'):
            cmd.append('-stats')
        
        # Update templates
        if kwargs.get('update_templates'):
            cmd.append('-update-templates')
        
        # Redirect options
        if kwargs.get('follow_redirects'):
            cmd.append('-follow-redirects')
        
        if kwargs.get('follow_host_redirects'):
            cmd.append('-follow-host-redirects')
        
        if kwargs.get('max_redirects'):
            cmd.extend(['-max-redirects', str(kwargs['max_redirects'])])
        
        if kwargs.get('disable_redirects'):
            cmd.append('-disable-redirects')
        
        # Report config
        if kwargs.get('report_config'):
            cmd.extend(['-rc', kwargs['report_config']])
        
        # Variables
        if kwargs.get('variables'):
            for key, value in kwargs['variables'].items():
                cmd.extend(['-var', f'{key}={value}'])
        
        # System resolvers
        if kwargs.get('system_resolvers'):
            cmd.append('-system-resolvers')
        
        # Passive mode
        if kwargs.get('passive'):
            cmd.append('-passive')
        
        # Environment variables
        if kwargs.get('env_vars'):
            cmd.append('-env-vars')
        
        # TLS options
        if kwargs.get('client_cert'):
            cmd.extend(['-cc', kwargs['client_cert']])
        
        if kwargs.get('client_key'):
            cmd.extend(['-ck', kwargs['client_key']])
        
        if kwargs.get('client_ca'):
            cmd.extend(['-ca', kwargs['client_ca']])
        
        if kwargs.get('ztls'):
            cmd.append('-ztls')
        
        if kwargs.get('sni'):
            cmd.extend(['-sni', kwargs['sni']])
        
        # Sandbox
        if kwargs.get('sandbox'):
            cmd.append('-sandbox')
        
        # Network interface
        if kwargs.get('interface'):
            cmd.extend(['-interface', kwargs['interface']])
        
        # Attack type
        if kwargs.get('attack_type'):
            cmd.extend(['-at', kwargs['attack_type']])
        
        # Source IP
        if kwargs.get('source_ip'):
            cmd.extend(['-sip', kwargs['source_ip']])
        
        # Config file
        if kwargs.get('config'):
            cmd.extend(['-config', kwargs['config']])
        
        # Interactsh options
        if kwargs.get('interactsh_server'):
            cmd.extend(['-iserver', kwargs['interactsh_server']])
        
        if kwargs.get('no_interactsh'):
            cmd.append('-no-interactsh')
        
        if kwargs.get('interactions_cache_size'):
            cmd.extend(['-interactions-cache-size', str(kwargs['interactions_cache_size'])])
        
        if kwargs.get('interactions_eviction'):
            cmd.extend(['-interactions-eviction', str(kwargs['interactions_eviction'])])
        
        if kwargs.get('interactions_poll_duration'):
            cmd.extend(['-interactions-poll-duration', str(kwargs['interactions_poll_duration'])])
        
        if kwargs.get('interactions_cooldown_period'):
            cmd.extend(['-interactions-cooldown-period', str(kwargs['interactions_cooldown_period'])])
        
        # Other options
        if kwargs.get('no_httpx'):
            cmd.append('-no-httpx')
        
        if kwargs.get('no_stdin'):
            cmd.append('-no-stdin')
        
        if kwargs.get('max_host_error'):
            cmd.extend(['-max-host-error', str(kwargs['max_host_error'])])
        
        if kwargs.get('track_error'):
            cmd.extend(['-track-error', kwargs['track_error']])
        
        if kwargs.get('bulk_size'):
            cmd.extend(['-bs', str(kwargs['bulk_size'])])
        
        if kwargs.get('template_threads'):
            cmd.extend(['-headc', str(kwargs['template_threads'])])
        
        return cmd
    
    def get_scan_history(self) -> List[Dict]:
        """Get all scan history"""
        return self.scan_history
    
    def generate_summary(self) -> str:
        """Generate summary of all scans"""
        if not self.scan_history:
            return "No scans performed yet"
        
        total_scans = len(self.scan_history)
        successful = sum(1 for s in self.scan_history if s['success'])
        total_vulns = sum(s['vulnerabilities_found'] for s in self.scan_history)
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for scan in self.scan_history:
            for vuln in scan.get('vulnerabilities', []):
                severity = vuln.get('info', {}).get('severity', 'unknown').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        summary = f"""
Nuclei Scan Summary
{'=' * 50}
Total Scans: {total_scans}
Successful: {successful}
Failed: {total_scans - successful}
Total Vulnerabilities: {total_vulns}

Severity Breakdown:
  Critical: {severity_counts['critical']}
  High:     {severity_counts['high']}
  Medium:   {severity_counts['medium']}
  Low:      {severity_counts['low']}
  Info:     {severity_counts['info']}
{'=' * 50}
"""
        return summary
    
    def update_templates(self) -> bool:
        """Update Nuclei templates to latest version"""
        logger.info("Updating Nuclei templates...")
        
        if self.use_docker:
            cmd = ['docker', 'run', '--rm', self.docker_image, '-update-templates']
        else:
            cmd = [self.binary_path, '-update-templates']
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("Templates updated successfully")
            return True
        else:
            logger.error(f"Template update failed: {result.stderr}")
            return False


class NucleiTemplates:
    """Helper class for template management"""
    
    COMMON_TAGS = {
        'cve': 'CVE vulnerabilities',
        'oast': 'Out-of-band Application Security Testing',
        'xss': 'Cross-Site Scripting',
        'sqli': 'SQL Injection',
        'rce': 'Remote Code Execution',
        'lfi': 'Local File Inclusion',
        'ssrf': 'Server-Side Request Forgery',
        'xxe': 'XML External Entity',
        'wordpress': 'WordPress vulnerabilities',
        'jira': 'Jira vulnerabilities',
        'jenkins': 'Jenkins vulnerabilities',
        'apache': 'Apache vulnerabilities',
        'nginx': 'Nginx vulnerabilities',
        'tomcat': 'Tomcat vulnerabilities',
        'exposure': 'Information exposure',
        'misconfig': 'Misconfiguration',
        'default-login': 'Default credentials',
        'panel': 'Admin panels',
        'tech': 'Technology detection',
    }
    
    @classmethod
    def list_tags(cls) -> Dict[str, str]:
        """List available template tags"""
        return cls.COMMON_TAGS
    
    @classmethod
    def get_tag_description(cls, tag: str) -> str:
        """Get description for a tag"""
        return cls.COMMON_TAGS.get(tag, f"Templates tagged with '{tag}'")


# Example usage
if __name__ == "__main__":
    # Initialize scanner
    scanner = NucleiScanner(use_docker=True)
    
    # Quick scan
    print("Running quick scan...")
    result = scanner.quick_scan("https://example.com")
    
    print(f"\nScan Result:")
    print(f"Success: {result['success']}")
    print(f"Duration: {result['duration_seconds']:.2f}s")
    print(f"Vulnerabilities: {result['vulnerabilities_found']}")
    
    # Print summary
    print(scanner.generate_summary())
