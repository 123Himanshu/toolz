#!/usr/bin/env python3
"""
Wapiti Scanner - Consolidated scanning functionality
"""
import subprocess
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

# Configuration - use current directory for results
RESULTS_DIR = Path("./results")
REPORTS_DIR = Path("./reports")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

MODULES = {
    "sql": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "file": "File Inclusion (LFI/RFI)",
    "exec": "Command Injection",
    "ssrf": "Server-Side Request Forgery",
    "path": "Directory Traversal",
    "upload": "File Upload Vulnerabilities",
    "auth": "Weak/Missing Authentication",
    "crlf": "CRLF Injection",
    "redirect": "Open Redirects",
    "methods": "Dangerous HTTP Methods",
    "backup": "Backup File Exposure",
    "cors": "CORS/Cookie Issues"
}


class WapitiScanner:
    """Main scanner class with all functionality"""
    
    def __init__(self, use_docker: bool = True, docker_image: str = "cyberwatch/wapiti:latest"):
        """
        Initialize Wapiti scanner
        
        Args:
            use_docker: Use Docker image (recommended)
            docker_image: Docker image name
        """
        self.use_docker = use_docker
        self.docker_image = docker_image
        self.wapiti_cmd = "wapiti"
    
    def scan(self, target: str, module: str, parallel: bool = False, workers: int = 5) -> Dict[str, Any]:
        """
        Execute a Wapiti scan
        
        Args:
            target: Target URL
            module: Module name (sql, xss, etc.) or 'all'
            parallel: Use parallel scanning for all modules
            workers: Number of parallel workers
            
        Returns:
            Scan results dictionary
        """
        if module == "all":
            if parallel:
                return self._scan_all_parallel(target, workers)
            else:
                return self._scan_all_sequential(target)
        else:
            return self._scan_single(target, module)
    
    def _scan_single(self, target: str, module: str) -> Dict[str, Any]:
        """Scan with a single module"""
        if module not in MODULES:
            return {"success": False, "error": f"Invalid module: {module}"}
        
        print(f"[*] Starting {MODULES[module]} scan on {target}")
        
        # Create results directory if it doesn't exist
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        output_file = str(RESULTS_DIR / f"{module}_scan.json")
        
        if self.use_docker:
            # Use Docker with proper path handling
            results_path = str(RESULTS_DIR.absolute()).replace('\\', '/')
            
            # Convert Windows path to Docker format if needed
            if ':' in results_path:
                drive = results_path[0].lower()
                results_path = f'/{drive}{results_path[2:]}'
            
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{results_path}:/results",
                self.docker_image,
                "-u", target,
                "-m", module,
                "-f", "json",
                "-o", f"/results/{module}_scan.json"
            ]
        else:
            # Use local binary
            cmd = [
                self.wapiti_cmd,
                "-u", target,
                "-m", module,
                "-f", "json",
                "-o", output_file
            ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            scan_result = {
                "success": result.returncode == 0,
                "target": target,
                "module": module,
                "output_file": output_file,
                "timestamp": datetime.now().isoformat()
            }
            
            if Path(output_file).exists():
                try:
                    with open(output_file, 'r') as f:
                        scan_result["findings"] = json.load(f)
                except:
                    scan_result["findings"] = None
            
            if scan_result["success"]:
                print(f"[+] Scan completed successfully")
            else:
                print(f"[-] Scan failed")
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timeout (600s)", "target": target, "module": module}
        except Exception as e:
            return {"success": False, "error": str(e), "target": target, "module": module}
    
    def _scan_all_sequential(self, target: str) -> Dict[str, Any]:
        """Scan with all modules sequentially"""
        print(f"[*] Starting comprehensive scan on {target}")
        print(f"[*] Running {len(MODULES)} modules sequentially")
        
        results = {}
        for i, module in enumerate(MODULES.keys(), 1):
            print(f"\n[*] Module {i}/{len(MODULES)}: {MODULES[module]}")
            results[module] = self._scan_single(target, module)
        
        self._save_comprehensive_report(results, target)
        return results
    
    def _scan_all_parallel(self, target: str, workers: int) -> Dict[str, Any]:
        """Scan with all modules in parallel"""
        print(f"[*] Starting parallel scan on {target}")
        print(f"[*] Running {len(MODULES)} modules with {workers} workers")
        
        results = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_module = {
                executor.submit(self._scan_single, target, module): module
                for module in MODULES.keys()
            }
            
            completed = 0
            for future in as_completed(future_to_module):
                module = future_to_module[future]
                completed += 1
                try:
                    results[module] = future.result()
                    print(f"[+] Completed {module} ({completed}/{len(MODULES)})")
                except Exception as e:
                    results[module] = {"success": False, "error": str(e)}
                    print(f"[-] Failed {module}: {e}")
        
        self._save_comprehensive_report(results, target)
        return results
    
    def batch_scan(self, targets: List[str], module: str, workers: int = 5) -> Dict[str, Any]:
        """Scan multiple targets with one module in parallel"""
        print(f"[*] Batch scanning {len(targets)} targets with {module} module")
        print(f"[*] Using {workers} workers")
        
        results = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_target = {
                executor.submit(self._scan_single, target, module): target
                for target in targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results[target] = future.result()
                    print(f"[+] Completed {target}")
                except Exception as e:
                    results[target] = {"success": False, "error": str(e)}
                    print(f"[-] Failed {target}: {e}")
        
        return results
    
    def generate_html_report(self, results: Dict[str, Any], output_file: str = None) -> str:
        """Generate HTML report from scan results"""
        if output_file is None:
            output_file = str(REPORTS_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        # Calculate statistics
        total_scans = len(results)
        successful = sum(1 for r in results.values() if r.get("success"))
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Wapiti Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .success {{ color: #28a745; }}
        .failed {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Wapiti Security Scan Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{total_scans}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{successful}</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_scans - successful}</div>
                <div class="stat-label">Failed</div>
            </div>
        </div>
        
        <h2>Scan Results</h2>
        <table>
            <tr>
                <th>Module</th>
                <th>Status</th>
                <th>Target</th>
                <th>Timestamp</th>
            </tr>
"""
        
        for module, result in results.items():
            status = "✓ Success" if result.get("success") else "✗ Failed"
            status_class = "success" if result.get("success") else "failed"
            target = result.get("target", "N/A")
            timestamp = result.get("timestamp", "N/A")
            
            html += f"""
            <tr>
                <td>{MODULES.get(module, module)}</td>
                <td class="{status_class}">{status}</td>
                <td>{target}</td>
                <td>{timestamp}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"[+] HTML report saved to {output_file}")
        return output_file
    
    def _save_comprehensive_report(self, results: Dict[str, Any], target: str):
        """Save comprehensive scan results"""
        output = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "results": results
        }
        
        output_file = REPORTS_DIR / f"comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Comprehensive results saved to {output_file}")


def list_modules():
    """List all available modules"""
    print("\nAvailable Wapiti Modules:")
    print("-" * 60)
    for module, description in MODULES.items():
        print(f"  {module:15} - {description}")
    print("-" * 60)
    print(f"\nTotal modules: {len(MODULES)}")
