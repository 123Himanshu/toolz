#!/usr/bin/env python3
"""
RustScan Wrapper - Fast port discovery tool
"""
import subprocess
import re
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class RustScanWrapper:
    """Wrapper for RustScan port scanner"""
    
    def __init__(self, docker_mode: bool = True):
        """
        Initialize RustScan wrapper
        
        Args:
            docker_mode: If True, run RustScan in Docker container
        """
        import os
        # Auto-detect if running inside Docker
        if os.path.exists('/.dockerenv'):
            self.docker_mode = False  # Already in Docker, use local commands
            logger.info("Running inside Docker container - using local RustScan")
        else:
            self.docker_mode = docker_mode
        self.container_name = "multi-tool-scanner"
        
    def is_available(self) -> bool:
        """Check if RustScan is available"""
        try:
            if self.docker_mode:
                result = subprocess.run(
                    ["docker", "exec", self.container_name, "rustscan", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:
                result = subprocess.run(
                    ["rustscan", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"RustScan availability check failed: {e}")
            return False
    
    def scan(self, target: str, ports: Optional[str] = None, 
             batch_size: int = 5000, timeout: int = 3000,
             ulimit: int = 5000, aggressive: bool = False) -> Dict:
        """
        Run RustScan port discovery
        
        Args:
            target: Target IP or hostname
            ports: Port range (e.g., "1-1000" or "80,443")
            batch_size: Batch size for port scanning
            timeout: Timeout in milliseconds
            ulimit: File descriptor limit
            aggressive: Use aggressive mode (higher timeout)
            
        Returns:
            Dict with scan results
        """
        try:
            # Build RustScan command
            cmd = ["rustscan", "-a", target, "-g"]
            
            if ports:
                cmd.extend(["-p", ports])
            
            cmd.extend([
                "--batch-size", str(batch_size),
                "--timeout", str(timeout if not aggressive else 10000),
                "--ulimit", str(ulimit)
            ])
            
            # Execute in Docker or locally
            if self.docker_mode:
                cmd = ["docker", "exec", self.container_name] + cmd
            
            logger.info(f"Running RustScan: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90 if not aggressive else 180
            )
            
            # Parse output
            open_ports = self._parse_output(result.stdout)
            
            return {
                "success": len(open_ports) > 0,
                "ports": open_ports,
                "raw_output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None,
                "command": " ".join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            error_msg = f"RustScan timed out after {90 if not aggressive else 180}s"
            logger.error(error_msg)
            return {
                "success": False,
                "ports": [],
                "raw_output": "",
                "error": error_msg,
                "command": " ".join(cmd)
            }
        except Exception as e:
            logger.error(f"RustScan execution failed: {e}")
            return {
                "success": False,
                "ports": [],
                "raw_output": "",
                "error": str(e),
                "command": " ".join(cmd) if 'cmd' in locals() else "N/A"
            }
    
    def _parse_output(self, output: str) -> List[int]:
        """
        Parse RustScan output to extract open ports
        
        Args:
            output: Raw RustScan output
            
        Returns:
            List of open port numbers
        """
        ports = []
        
        # Pattern: IP -> [port1,port2,port3]
        pattern = r'\d+\.\d+\.\d+\.\d+\s*->\s*\[([0-9,]+)\]'
        matches = re.findall(pattern, output)
        
        for match in matches:
            port_list = match.split(',')
            for port in port_list:
                try:
                    ports.append(int(port.strip()))
                except ValueError:
                    continue
        
        # Remove duplicates and sort
        ports = sorted(list(set(ports)))
        logger.info(f"RustScan found {len(ports)} open ports: {ports}")
        
        return ports
    
    def quick_scan(self, target: str) -> Dict:
        """
        Quick scan with default settings
        
        Args:
            target: Target IP or hostname
            
        Returns:
            Dict with scan results
        """
        return self.scan(target, batch_size=5000, timeout=3000)
    
    def aggressive_scan(self, target: str) -> Dict:
        """
        Aggressive scan with higher timeouts
        
        Args:
            target: Target IP or hostname
            
        Returns:
            Dict with scan results
        """
        return self.scan(target, batch_size=10000, timeout=10000, aggressive=True)
    
    def custom_ports_scan(self, target: str, ports: str) -> Dict:
        """
        Scan specific ports
        
        Args:
            target: Target IP or hostname
            ports: Port range or list (e.g., "1-1000" or "80,443,8080")
            
        Returns:
            Dict with scan results
        """
        return self.scan(target, ports=ports)
