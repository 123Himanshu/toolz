"""
OWASP ZAP Scanner - Complete Docker Integration
Full-featured ZAP scanner with detailed logging and 100% potential
"""

import subprocess
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ZAPScanner:
    """
    OWASP ZAP Scanner with full Docker support
    Uses official OWASP ZAP Docker image
    """
    
    def __init__(self, use_docker: bool = True, docker_image: str = "zaproxy/zap-stable:latest"):
        """
        Initialize ZAP scanner
        
        Args:
            use_docker: Use Docker (recommended)
            docker_image: ZAP Docker image
        """
        self.use_docker = use_docker
        self.docker_image = docker_image
        self.results_dir = Path("./zap-results")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.scan_history = []
        
        logger.info(f"✅ ZAP Scanner initialized (Docker: {use_docker})")
    
    def baseline_scan(self, target: str, timeout: int = 60) -> Dict[str, Any]:
        """
        ZAP Baseline Scan - Quick passive scan
        
        Args:
            target: Target URL
            timeout: Scan timeout in minutes
            
        Returns:
            Scan results dictionary
        """
        logger.info(f"🔍 Starting ZAP Baseline Scan: {target}")
        
        scan_id = f"zap_baseline_{int(time.time())}"
        output_file = self.results_dir / f"{scan_id}.html"
        json_file = self.results_dir / f"{scan_id}.json"
        
        start_time = datetime.now()
        
        if self.use_docker:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{self.results_dir.absolute()}:/zap/wrk:rw",
                self.docker_image,
                "zap-baseline.py",
                "-t", target,
                "-r", f"{scan_id}.html",
                "-J", f"{scan_id}.json",
                "-m", str(timeout)
            ]
        else:
            cmd = [
                "zap-baseline.py",
                "-t", target,
                "-r", str(output_file),
                "-J", str(json_file),
                "-m", str(timeout)
            ]
        
        try:
            logger.info(f"📝 Running command: {' '.join(cmd[:5])}...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * 60 + 300
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            alerts = self._parse_json_results(json_file)
            
            scan_result = {
                'scan_id': scan_id,
                'scan_type': 'baseline',
                'target': target,
                'success': result.returncode in [0, 1, 2],  # ZAP returns 0-2 for different alert levels
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'alerts_found': len(alerts),
                'alerts': alerts,
                'html_report': str(output_file),
                'json_report': str(json_file),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode
            }
            
            self.scan_history.append(scan_result)
            
            logger.info(f"✅ Baseline scan completed: {len(alerts)} alerts in {duration:.2f}s")
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Scan timeout after {timeout} minutes")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': f'Scan timeout after {timeout} minutes'
            }
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': str(e)
            }
    
    def full_scan(self, target: str, timeout: int = 120) -> Dict[str, Any]:
        """
        ZAP Full Scan - Active + Passive scanning
        
        Args:
            target: Target URL
            timeout: Scan timeout in minutes
            
        Returns:
            Scan results dictionary
        """
        logger.info(f"🔍 Starting ZAP Full Scan: {target}")
        
        scan_id = f"zap_full_{int(time.time())}"
        output_file = self.results_dir / f"{scan_id}.html"
        json_file = self.results_dir / f"{scan_id}.json"
        
        start_time = datetime.now()
        
        if self.use_docker:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{self.results_dir.absolute()}:/zap/wrk:rw",
                self.docker_image,
                "zap-full-scan.py",
                "-t", target,
                "-r", f"{scan_id}.html",
                "-J", f"{scan_id}.json",
                "-m", str(timeout)
            ]
        else:
            cmd = [
                "zap-full-scan.py",
                "-t", target,
                "-r", str(output_file),
                "-J", str(json_file),
                "-m", str(timeout)
            ]
        
        try:
            logger.info(f"📝 Running full scan (this may take a while)...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * 60 + 300
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            alerts = self._parse_json_results(json_file)
            
            scan_result = {
                'scan_id': scan_id,
                'scan_type': 'full',
                'target': target,
                'success': result.returncode in [0, 1, 2],
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'alerts_found': len(alerts),
                'alerts': alerts,
                'html_report': str(output_file),
                'json_report': str(json_file),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode
            }
            
            self.scan_history.append(scan_result)
            
            logger.info(f"✅ Full scan completed: {len(alerts)} alerts in {duration:.2f}s")
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Scan timeout after {timeout} minutes")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': f'Scan timeout after {timeout} minutes'
            }
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': str(e)
            }
    
    def api_scan(self, target: str, api_definition: str, timeout: int = 60) -> Dict[str, Any]:
        """
        ZAP API Scan - Scan API endpoints
        
        Args:
            target: Target URL
            api_definition: Path to OpenAPI/Swagger definition
            timeout: Scan timeout in minutes
            
        Returns:
            Scan results dictionary
        """
        logger.info(f"🔍 Starting ZAP API Scan: {target}")
        
        scan_id = f"zap_api_{int(time.time())}"
        output_file = self.results_dir / f"{scan_id}.html"
        json_file = self.results_dir / f"{scan_id}.json"
        
        start_time = datetime.now()
        
        if self.use_docker:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{self.results_dir.absolute()}:/zap/wrk:rw",
                self.docker_image,
                "zap-api-scan.py",
                "-t", target,
                "-f", "openapi",
                "-r", f"{scan_id}.html",
                "-J", f"{scan_id}.json",
                "-m", str(timeout)
            ]
        else:
            cmd = [
                "zap-api-scan.py",
                "-t", target,
                "-f", "openapi",
                "-r", str(output_file),
                "-J", str(json_file),
                "-m", str(timeout)
            ]
        
        try:
            logger.info(f"📝 Running API scan...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * 60 + 300
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            alerts = self._parse_json_results(json_file)
            
            scan_result = {
                'scan_id': scan_id,
                'scan_type': 'api',
                'target': target,
                'success': result.returncode in [0, 1, 2],
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'alerts_found': len(alerts),
                'alerts': alerts,
                'html_report': str(output_file),
                'json_report': str(json_file),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode
            }
            
            self.scan_history.append(scan_result)
            
            logger.info(f"✅ API scan completed: {len(alerts)} alerts in {duration:.2f}s")
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Scan timeout after {timeout} minutes")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': f'Scan timeout after {timeout} minutes'
            }
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            return {
                'scan_id': scan_id,
                'success': False,
                'error': str(e)
            }
    
    def _parse_json_results(self, json_file: Path) -> List[Dict]:
        """Parse ZAP JSON results"""
        try:
            if json_file.exists():
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    return data.get('site', [{}])[0].get('alerts', [])
        except Exception as e:
            logger.warning(f"Could not parse JSON results: {e}")
        return []
    
    def get_scan_history(self) -> List[Dict]:
        """Get all scan history"""
        return self.scan_history
    
    def generate_summary(self) -> str:
        """Generate summary of all scans"""
        if not self.scan_history:
            return "No ZAP scans performed yet"
        
        total_scans = len(self.scan_history)
        successful = sum(1 for s in self.scan_history if s.get('success'))
        total_alerts = sum(s.get('alerts_found', 0) for s in self.scan_history)
        
        summary = f"""
ZAP Scanner Summary
{'=' * 50}
Total Scans: {total_scans}
Successful: {successful}
Failed: {total_scans - successful}
Total Alerts: {total_alerts}
{'=' * 50}
"""
        return summary


# Example usage
if __name__ == "__main__":
    scanner = ZAPScanner(use_docker=True)
    
    # Baseline scan
    result = scanner.baseline_scan("https://example.com")
    print(f"Baseline scan: {result['alerts_found']} alerts")
    
    # Print summary
    print(scanner.generate_summary())
