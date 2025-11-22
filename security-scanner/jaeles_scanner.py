"""
Jaeles Security Scanner - Python Wrapper
A professional Python interface for the Jaeles vulnerability scanner

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


class JaelesScanner:
    """
    Python wrapper for Jaeles security scanner
    
    Supports both Docker and binary execution modes
    """
    
    def __init__(self, 
                 use_docker: bool = True,
                 binary_path: Optional[str] = None,
                 docker_image: str = "j3ssie/jaeles"):
        """
        Initialize Jaeles scanner
        
        Args:
            use_docker: Use Docker image (recommended)
            binary_path: Path to jaeles binary if not using Docker
            docker_image: Docker image name
        """
        self.use_docker = use_docker
        self.binary_path = binary_path or "jaeles"
        self.docker_image = docker_image
        self.scan_history = []
        
        logger.info(f"Initialized Jaeles Scanner (Docker: {use_docker})")
    
    def scan(self,
             target: str,
             signatures: str = 'cves',
             output_dir: str = 'jaeles-output',
             timeout: int = 20,
             concurrency: int = 20,
             verbose: bool = False,
             json_output: bool = True,
             proxy: Optional[str] = None,
             headers: Optional[Dict[str, str]] = None,
             cookies: Optional[str] = None,
             custom_signature: Optional[str] = None,
             rate_limit: Optional[int] = None,
             no_ssl_verify: bool = False) -> Dict:
        """
        Run Jaeles vulnerability scan
        
        Args:
            target: Target URL (e.g., 'https://example.com')
            signatures: Signature selector (e.g., 'cves', 'probe', 'cves/grafana')
            output_dir: Output directory for results
            timeout: HTTP timeout in seconds
            concurrency: Number of concurrent requests
            verbose: Enable verbose output
            json_output: Store output as JSON
            proxy: Proxy URL (e.g., 'http://127.0.0.1:8080')
            headers: Custom HTTP headers (e.g., {'Authorization': 'Bearer token'})
            cookies: Cookie string (e.g., 'session=abc123; token=xyz')
            custom_signature: Path to custom signature file
            rate_limit: Requests per second limit
            no_ssl_verify: Disable SSL certificate verification
            
        Returns:
            Dict containing scan results and metadata
        """
        logger.info(f"Starting scan on {target} with signatures: {signatures}")
        
        # Build command
        cmd = self._build_command(
            target=target,
            signatures=signatures,
            output_dir=output_dir,
            timeout=timeout,
            concurrency=concurrency,
            verbose=verbose,
            json_output=json_output,
            proxy=proxy,
            headers=headers,
            cookies=cookies,
            custom_signature=custom_signature,
            rate_limit=rate_limit,
            no_ssl_verify=no_ssl_verify
        )
        
        # Execute scan
        start_time = datetime.now()
        logger.debug(f"Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Log any errors
        if result.stderr:
            logger.debug(f"Stderr: {result.stderr[:200]}")
        
        # Parse results
        scan_result = {
            'success': result.returncode == 0,
            'target': target,
            'signatures': signatures,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'output_dir': output_dir,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'vulnerabilities_found': self._check_vulnerabilities(result.stdout)
        }
        
        # Save output to files on host
        if self.use_docker:
            host_output = os.path.abspath(output_dir)
            os.makedirs(host_output, exist_ok=True)
            
            # Save summary
            summary_file = os.path.join(host_output, 'jaeles-summary.txt')
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(f"Jaeles Scan Report\n")
                f.write(f"{'='*70}\n\n")
                f.write(f"Target: {target}\n")
                f.write(f"Signatures: {signatures}\n")
                f.write(f"Start Time: {start_time}\n")
                f.write(f"Duration: {duration:.2f}s\n")
                f.write(f"Success: {scan_result['success']}\n")
                f.write(f"Vulnerabilities: {scan_result['vulnerabilities_found']}\n\n")
                f.write(f"{'='*70}\n")
                f.write(f"Full Output:\n")
                f.write(f"{'='*70}\n\n")
                f.write(result.stdout)
            
            # Save JSON if requested
            if json_output:
                json_file = os.path.join(host_output, 'jaeles-output.json')
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(scan_result, f, indent=2)
        
        self.scan_history.append(scan_result)
        
        if scan_result['success']:
            logger.info(f"Scan completed in {duration:.2f}s")
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
        Quick vulnerability scan with common signatures
        
        Args:
            target: Target URL
            
        Returns:
            Scan results
        """
        return self.scan(
            target=target,
            signatures='probe',
            timeout=10,
            concurrency=30,
            verbose=False
        )
    
    def deep_scan(self, target: str) -> Dict:
        """
        Deep vulnerability scan with all CVE signatures
        
        Args:
            target: Target URL
            
        Returns:
            Scan results
        """
        return self.scan(
            target=target,
            signatures='cves',
            timeout=30,
            concurrency=20,
            verbose=True
        )
    
    def _build_command(self, **kwargs) -> List[str]:
        """Build command line arguments"""
        if self.use_docker:
            # Create output directory on host
            output_dir = kwargs['output_dir']
            host_output = os.path.abspath(output_dir)
            os.makedirs(host_output, exist_ok=True)
            
            # Convert Windows path to Docker format
            docker_path = host_output.replace('\\', '/')
            if ':' in docker_path:
                # Convert C:/path to /c/path for Docker
                drive = docker_path[0].lower()
                docker_path = f'/{drive}{docker_path[2:]}'
            
            # Map host directory to container
            cmd = [
                'docker', 'run', '--rm',
                '-v', f'{docker_path}:/output',
                self.docker_image, 'scan'
            ]
            # Use /output inside container
            kwargs['output_dir'] = '/output'
        else:
            cmd = [self.binary_path, 'scan']
        
        # Add arguments
        cmd.extend(['-s', kwargs['signatures']])
        cmd.extend(['-u', kwargs['target']])
        cmd.extend(['-o', kwargs['output_dir']])
        cmd.extend(['--timeout', str(kwargs['timeout'])])
        cmd.extend(['-c', str(kwargs['concurrency'])])
        
        if kwargs.get('verbose'):
            cmd.append('-v')
        
        if kwargs.get('json_output'):
            cmd.append('--json')
        
        if kwargs.get('proxy'):
            cmd.extend(['--proxy', kwargs['proxy']])
        
        # Add custom headers
        if kwargs.get('headers'):
            for key, value in kwargs['headers'].items():
                cmd.extend(['-H', f'{key}: {value}'])
        
        # Add cookies
        if kwargs.get('cookies'):
            cmd.extend(['--cookie', kwargs['cookies']])
        
        # Add custom signature
        if kwargs.get('custom_signature'):
            cmd.extend(['--sign', kwargs['custom_signature']])
        
        # Add rate limit
        if kwargs.get('rate_limit'):
            cmd.extend(['--rate-limit', str(kwargs['rate_limit'])])
        
        # Disable SSL verification
        if kwargs.get('no_ssl_verify'):
            cmd.append('--no-ssl-verify')
        
        return cmd
    
    def _check_vulnerabilities(self, output: str) -> bool:
        """Check if vulnerabilities were found in output"""
        keywords = ['vulnerable', 'found', 'detected', 'exploit']
        return any(keyword in output.lower() for keyword in keywords)
    
    def get_scan_history(self) -> List[Dict]:
        """Get all scan history"""
        return self.scan_history
    
    def generate_summary(self) -> str:
        """Generate summary of all scans"""
        if not self.scan_history:
            return "No scans performed yet"
        
        total_scans = len(self.scan_history)
        successful = sum(1 for s in self.scan_history if s['success'])
        with_vulns = sum(1 for s in self.scan_history if s['vulnerabilities_found'])
        
        summary = f"""
Jaeles Scan Summary
{'=' * 50}
Total Scans: {total_scans}
Successful: {successful}
Failed: {total_scans - successful}
Vulnerabilities Found: {with_vulns}
{'=' * 50}
"""
        return summary


class JaelesSignatures:
    """Helper class for signature management"""
    
    COMMON_SIGNATURES = {
        'all_cves': 'cves',
        'probes': 'probe',
        'grafana': 'cves/grafana',
        'jenkins': 'cves/jenkins',
        'apache': 'cves/apache',
        'wordpress': 'cves/wordpress',
        'jira': 'cves/jira',
        'spring': 'cves/spring',
    }
    
    @classmethod
    def list_signatures(cls) -> Dict[str, str]:
        """List available signature shortcuts"""
        return cls.COMMON_SIGNATURES
    
    @classmethod
    def get_signature(cls, name: str) -> str:
        """Get signature path by name"""
        return cls.COMMON_SIGNATURES.get(name, name)


# Example usage
if __name__ == "__main__":
    # Initialize scanner
    scanner = JaelesScanner(use_docker=True)
    
    # Quick scan
    print("Running quick scan...")
    result = scanner.quick_scan("https://httpbin.org")
    
    print(f"\nScan Result:")
    print(f"Success: {result['success']}")
    print(f"Duration: {result['duration_seconds']:.2f}s")
    print(f"Vulnerabilities: {result['vulnerabilities_found']}")
    
    # Print summary
    print(scanner.generate_summary())
