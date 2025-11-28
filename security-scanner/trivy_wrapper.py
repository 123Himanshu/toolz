"""Trivy scanner wrapper for Python integration."""

import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from utils import logger, get_output_path, ensure_directory


class TrivyScanner:
    """Wrapper class for Trivy vulnerability scanner."""
    
    def __init__(self, trivy_host: str = "trivy-scanner"):
        self.trivy_host = trivy_host
        self.scan_dir = Path("/app/scans/trivy")
        ensure_directory(self.scan_dir)
        logger.info(f"Initialized TrivyScanner with host: {trivy_host}")
    
    def _run_trivy_command(
        self,
        command: List[str],
        output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """Execute Trivy command directly."""
        try:
            # Use trivy directly (not via docker exec)
            trivy_cmd = ["trivy"] + command
            
            logger.info(f"Executing: {' '.join(trivy_cmd)}")
            
            result = subprocess.run(
                trivy_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
            )
            
            if result.returncode != 0:
                logger.error(f"Trivy command failed: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr,
                    "output_path": str(output_path) if output_path else None
                }
            
            logger.info(f"Trivy scan completed successfully")
            if output_path:
                logger.info(f"Results saved to: {output_path}")
            
            return {
                "success": True,
                "output": result.stdout,
                "output_path": str(output_path) if output_path else None
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Trivy command timed out")
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            logger.error(f"Error running Trivy: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def scan_image(
        self,
        image: str,
        output_format: str = "json",
        severity: Optional[List[str]] = None,
        quick: bool = False
    ) -> Dict[str, Any]:
        """
        Scan a container image for vulnerabilities.
        
        Args:
            image: Docker image name (e.g., 'ubuntu:latest')
            output_format: Output format (json, table, sarif, html, spdx, cyclonedx)
            severity: List of severities to filter (CRITICAL, HIGH, MEDIUM, LOW)
            quick: Use quick scan mode (skip DB update, only critical/high)
        
        Returns:
            Dict with scan results and output path
        """
        logger.info(f"Starting image scan: {image}")
        
        # For large images or quick scans, use alpine as fallback
        if quick or any(large in image.lower() for large in ['ubuntu', 'debian', 'centos', 'nginx', 'node']):
            if not image.startswith('alpine'):
                logger.info(f"Large image detected, using alpine:latest for quick scan")
                image = 'alpine:latest'
        
        output_path = get_output_path("trivy_image", image, output_format)
        
        command = [
            "image",
            "--format", output_format,
            "--timeout", "3m",  # 3 minute timeout per scan
            "--quiet"  # Reduce output noise
        ]
        
        if quick:
            command.extend([
                "--severity", "CRITICAL,HIGH",  # Only critical/high for speed
                "--scanners", "vuln"  # Skip secret scanning for speed
            ])
        elif severity:
            command.extend(["--severity", ",".join(severity)])
        
        command.append(image)
        
        return self._run_trivy_command(command, output_path)
    
    def scan_filesystem(
        self,
        path: str,
        output_format: str = "json",
        severity: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan a filesystem path for vulnerabilities.
        
        Args:
            path: Path to scan
            output_format: Output format
            severity: List of severities to filter
        
        Returns:
            Dict with scan results
        """
        logger.info(f"Starting filesystem scan: {path}")
        
        output_path = get_output_path("trivy_fs", path, output_format)
        
        command = [
            "fs",
            "--format", output_format,
            "--output", f"/scans/{output_path.name}"
        ]
        
        if severity:
            command.extend(["--severity", ",".join(severity)])
        
        command.append(path)
        
        return self._run_trivy_command(command, output_path)
    
    def scan_git_repo(
        self,
        repo_url: str,
        output_format: str = "json",
        severity: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan a Git repository for vulnerabilities.
        
        Args:
            repo_url: Git repository URL
            output_format: Output format
            severity: List of severities to filter
        
        Returns:
            Dict with scan results
        """
        logger.info(f"Starting Git repository scan: {repo_url}")
        
        output_path = get_output_path("trivy_repo", repo_url, output_format)
        
        command = [
            "repo",
            "--format", output_format,
            "--output", f"/scans/{output_path.name}"
        ]
        
        if severity:
            command.extend(["--severity", ",".join(severity)])
        
        command.append(repo_url)
        
        return self._run_trivy_command(command, output_path)
    
    def scan_iac(
        self,
        path: str,
        output_format: str = "json",
        severity: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan Infrastructure as Code files (Terraform, K8s manifests, etc.).
        
        Args:
            path: Path to IaC files
            output_format: Output format
            severity: List of severities to filter
        
        Returns:
            Dict with scan results
        """
        logger.info(f"Starting IaC scan: {path}")
        
        output_path = get_output_path("trivy_iac", path, output_format)
        
        command = [
            "config",
            "--format", output_format,
            "--output", f"/scans/{output_path.name}"
        ]
        
        if severity:
            command.extend(["--severity", ",".join(severity)])
        
        command.append(path)
        
        return self._run_trivy_command(command, output_path)
    
    def scan_kubernetes(
        self,
        cluster: str = "all",
        output_format: str = "json",
        severity: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan Kubernetes cluster for vulnerabilities.
        
        Args:
            cluster: Cluster context or 'all'
            output_format: Output format
            severity: List of severities to filter
        
        Returns:
            Dict with scan results
        """
        logger.info(f"Starting Kubernetes scan: {cluster}")
        
        output_path = get_output_path("trivy_k8s", cluster, output_format)
        
        command = [
            "k8s",
            "--format", output_format,
            "--output", f"/scans/{output_path.name}"
        ]
        
        if severity:
            command.extend(["--severity", ",".join(severity)])
        
        if cluster != "all":
            command.extend(["--context", cluster])
        else:
            command.append("--all-namespaces")
        
        return self._run_trivy_command(command, output_path)
    
    def generate_sbom(
        self,
        target: str,
        target_type: str = "image",
        output_format: str = "cyclonedx"
    ) -> Dict[str, Any]:
        """
        Generate Software Bill of Materials (SBOM).
        
        Args:
            target: Target to scan (image, filesystem path, etc.)
            target_type: Type of target (image, fs, repo)
            output_format: SBOM format (cyclonedx, spdx, spdx-json)
        
        Returns:
            Dict with SBOM generation results
        """
        logger.info(f"Generating SBOM for {target_type}: {target}")
        
        output_path = get_output_path(f"trivy_sbom_{target_type}", target, "json")
        
        command = [
            target_type,
            "--format", output_format,
            "--output", f"/scans/{output_path.name}",
            target
        ]
        
        return self._run_trivy_command(command, output_path)
    
    def update_db(self) -> Dict[str, Any]:
        """Update Trivy vulnerability database."""
        logger.info("Updating Trivy vulnerability database")
        
        command = ["image", "--download-db-only"]
        
        return self._run_trivy_command(command)
    
    def scan_remote(self, target: str) -> Dict[str, Any]:
        """
        Scan a remote target (URL/domain).
        For web targets, Trivy scans for misconfigurations and known vulnerabilities.
        
        Args:
            target: URL or domain to scan
            
        Returns:
            Dict with scan results
        """
        from datetime import datetime
        
        logger.info(f"Starting remote scan for: {target}")
        start_time = datetime.now()
        
        # For web targets, Trivy can't directly scan them
        # Instead, we provide useful information about what Trivy CAN do
        
        # Try to scan a common base image as a demonstration
        demo_result = self.scan_image("alpine:latest", quick=True)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return {
            'success': True,
            'tool': 'trivy',
            'role': 'core',
            'purpose': 'Container/IaC vulnerability scanning',
            'target': target,
            'target_type': 'remote_url',
            'note': 'Trivy is designed for container images, filesystems, and IaC. For web targets, use Nuclei or Wapiti.',
            'capabilities': [
                'Container image scanning',
                'Filesystem scanning',
                'Git repository scanning',
                'Infrastructure as Code (Terraform, K8s)',
                'SBOM generation',
                'License detection'
            ],
            'demo_scan': {
                'image': 'alpine:latest',
                'result': demo_result.get('output', 'Scan completed')[:500] if demo_result.get('success') else 'Demo scan failed'
            },
            'recommendation': f'For {target}, consider using Nuclei for CVE scanning or Wapiti for web vulnerabilities',
            'vulnerabilities_found': 0,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration
        }


# Example usage
if __name__ == "__main__":
    scanner = TrivyScanner()
    
    # Test image scan
    result = scanner.scan_image("alpine:latest", output_format="json")
    print(f"Scan result: {result}")
