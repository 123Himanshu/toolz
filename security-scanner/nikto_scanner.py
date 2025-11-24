"""
Nikto Scanner - Complete Docker Integration
Full-featured Nikto scanner with detailed logging and 100% potential
"""

import subprocess
import json
import time
import logging
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NiktoScanner:
    """
    Nikto Scanner with full Docker support
    Uses official Nikto Docker image
    """
    
    def __init__(self, use_docker: bool = True, docker_image: str = "securecodebox/nikto:latest"):
        """
        Initialize Nikto scanner
        
        Args:
            use_docker: Use Docker (recommended)
            docker_image: Nikto Docker image
        """
        self.use_docker = use_docker
        self.docker_image = docker_image
        self.results_dir = Path("./nikto-results")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.scan_history = []
        
        logger.info(f"✅ Nikto Scanner initialized (Docker: {use_docker})")
    
    def scan(self, target: str, port: int = 80, ssl: bool = False) -> Dict[str, Any]:
        """
        Nikto Scan - LEGACY SERVER MISCONFIGURATION CHECKS ONLY
        
        PURPOSE: Detect old Apache/IIS/Nginx misconfigurations
        USE WHEN: Target appears to be legacy server (Apache 2.2, IIS 6, etc.)
        AVOID: Modern web apps (use Nuclei/ZAP instead)
        
        Args:
            target: Target URL or hostname
            port: Target port (default: 80)
            ssl: Use SSL/HTTPS (default: False)
            
        Returns:
            Scan results dictionary
        """
        # FIXED: Only misconfiguration checks (tuning 2)
        tuning = "2"  # Misconfiguration ONLY
        timeout = 600  # 10 min max
        logger.info(f"🔍 Starting Nikto Scan: {target}:{port}")
        
        # Clean target
        clean_target = target.replace('http://', '').replace('https://', '').strip('/')
        
        scan_id = f"nikto_{int(time.time())}"
        output_file = self.results_dir / f"{scan_id}.txt"
        json_file = self.results_dir / f"{scan_id}.json"
        
        start_time = datetime.now()
        
        if self.use_docker:
            # Convert Windows path to Docker format
            results_path = str(self.results_dir.absolute()).replace('\\', '/')
            if ':' in results_path:
                drive = results_path[0].lower()
                results_path = f'/{drive}{results_path[2:]}'
            
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{results_path}:/tmp",
                self.docker_image,
                "-h", clean_target,
                "-p", str(port),
                "-Tuning", tuning,
                "-Format", "txt",
                "-output", f"/tmp/{scan_id}.txt"
            ]
            
            if ssl:
                cmd.append("-ssl")
        else:
            cmd = [
                "nikto",
                "-h", clean_target,
                "-p", str(port),
                "-Tuning", tuning,
                "-Format", "txt",
                "-output", str(output_file)
            ]
            
            if ssl:
                cmd.append("-ssl")
        
        try:
            logger.info(f"📝 Running Nikto scan...")
            logger.info(f"   Target: {clean_target}:{port}")
            logger.info(f"   SSL: {ssl}")
            logger.info(f"   Tuning: {tuning}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            findings = self._parse_results(output_file)
            
            scan_result = {
                'scan_id': scan_id,
                'tool': 'nikto',
                'role': 'specialized',
                'purpose': 'Legacy server misconfiguration detection',
                'target': target,
                'port': port,
                'ssl': ssl,
                'tuning': tuning,
                'success': result.returncode == 0,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'findings_count': len(findings),
                'findings': findings,
                'output_file': str(output_file),
                'note': 'Use Nuclei/ZAP for modern vulnerability scanning',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode
            }
            
            # Save JSON results
            with open(json_file, 'w') as f:
                json.dump(scan_result, f, indent=2)
            
            self.scan_history.append(scan_result)
            
            logger.info(f"✅ Nikto scan completed: {len(findings)} findings in {duration:.2f}s")
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Scan timeout after {timeout} seconds")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': f'Scan timeout after {timeout} seconds'
            }
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': str(e)
            }
    
    # REMOVED: All custom scan methods
    # REASON: Nikto is for legacy server misconfigs ONLY
    # Use Nuclei/ZAP for modern vulnerability scanning
    
    def _parse_results(self, output_file: Path) -> List[Dict]:
        """Parse Nikto text output"""
        findings = []
        
        try:
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Parse findings (lines starting with +)
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('+ ') and not line.startswith('+ Target'):
                            finding_text = line[2:].strip()
                            
                            # Extract OSVDB ID if present
                            osvdb_match = re.search(r'OSVDB-(\d+)', finding_text)
                            osvdb = osvdb_match.group(1) if osvdb_match else None
                            
                            findings.append({
                                'description': finding_text,
                                'osvdb': osvdb,
                                'severity': self._determine_severity(finding_text)
                            })
        except Exception as e:
            logger.warning(f"Could not parse results: {e}")
        
        return findings
    
    def _determine_severity(self, finding: str) -> str:
        """Determine severity based on finding text"""
        finding_lower = finding.lower()
        
        if any(word in finding_lower for word in ['sql', 'injection', 'xss', 'command', 'rce', 'remote code']):
            return 'high'
        elif any(word in finding_lower for word in ['authentication', 'bypass', 'disclosure', 'exposure']):
            return 'medium'
        elif any(word in finding_lower for word in ['misconfiguration', 'outdated', 'version']):
            return 'low'
        else:
            return 'info'
    
    def get_scan_history(self) -> List[Dict]:
        """Get all scan history"""
        return self.scan_history
    
    def generate_summary(self) -> str:
        """Generate summary of all scans"""
        if not self.scan_history:
            return "No Nikto scans performed yet"
        
        total_scans = len(self.scan_history)
        successful = sum(1 for s in self.scan_history if s.get('success'))
        total_findings = sum(s.get('findings_count', 0) for s in self.scan_history)
        
        summary = f"""
Nikto Scanner Summary
{'=' * 50}
Total Scans: {total_scans}
Successful: {successful}
Failed: {total_scans - successful}
Total Findings: {total_findings}
{'=' * 50}
"""
        return summary


# Example usage
if __name__ == "__main__":
    scanner = NiktoScanner(use_docker=True)
    
    # Quick scan
    result = scanner.quick_scan("https://example.com")
    print(f"Quick scan: {result['findings_count']} findings")
    
    # Print summary
    print(scanner.generate_summary())
