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
    
    def scan(self, target: str, module: str = "xss,sql,file") -> Dict[str, Any]:
        """
        Execute a Wapiti QUICK vulnerability check
        
        PURPOSE: Web vulnerability scanning
        USE WHEN: Need XSS/SQLi/LFI checks
        AVOID: Large-scale scanning
        
        Args:
            target: Target URL
            module: Quick check modules (default: xss,sql,file)
        
        Returns:
            Scan results dictionary
        """
        # Quick scan with limited modules
        return self._scan_quick(target, module)
    
    def _scan_quick(self, target: str, modules: str) -> Dict[str, Any]:
        """Quick scan with limited modules"""
        sys.stderr.write(f"[*] Starting Wapiti scan on {target}\n")
        sys.stderr.write(f"[*] Modules: {modules}\n")
        
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        output_file = str(RESULTS_DIR / f"wapiti_quick_scan.json")
        
        if self.use_docker:
            results_path = str(RESULTS_DIR.absolute()).replace('\\', '/')
            if ':' in results_path:
                drive = results_path[0].lower()
                results_path = f'/{drive}{results_path[2:]}'
            
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{results_path}:/results",
                self.docker_image,
                "-u", target,
                "-m", modules,  # Multiple modules
                "--scope", "url",  # Quick scope
                "--max-depth", "2",  # Shallow crawl
                "--max-links-per-page", "20",  # Limited links
                "-f", "json",
                "-o", f"/results/wapiti_quick_scan.json"
            ]
        else:
            cmd = [
                self.wapiti_cmd,
                "-u", target,
                "-m", modules,
                "--scope", "url",
                "-d", "2",  # depth
                "-f", "json",
                "-o", output_file
            ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 min max for quick scan
            )
            
            scan_result = {
                "success": result.returncode == 0,
                "tool": "wapiti",
                "role": "speed",
                "purpose": "Web vulnerability scanning",
                "target": target,
                "modules": modules,
                "output_file": output_file,
                "timestamp": datetime.now().isoformat(),
                "note": "Quick web vulnerability checks"
            }
            
            if Path(output_file).exists():
                try:
                    with open(output_file, 'r') as f:
                        scan_result["findings"] = json.load(f)
                except:
                    scan_result["findings"] = None
            
            if scan_result["success"]:
                sys.stderr.write(f"[+] Scan completed successfully\n")
            else:
                sys.stderr.write(f"[-] Scan failed\n")
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Quick scan timeout (300s)", "target": target, "modules": modules}
        except Exception as e:
            return {"success": False, "error": str(e), "target": target, "modules": modules}
    
    # Quick scan method only


def list_modules():
    """List all available modules"""
    print("\nAvailable Wapiti Modules:")
    print("-" * 60)
    for module, description in MODULES.items():
        print(f"  {module:15} - {description}")
    print("-" * 60)
    print(f"\nTotal modules: {len(MODULES)}")
