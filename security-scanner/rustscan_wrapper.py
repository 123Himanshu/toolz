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
    
    def scan(self, target: str) -> Dict:
        """
        Run RustScan FAST port discovery ONLY
        
        PURPOSE: Ultra-fast port discovery (3 sec for 65535 ports)
        FEEDS TO: Nmap for service detection
        
        Args:
            target: Target IP or hostname
            
        Returns:
            Dict with discovered ports ONLY (no service detection)
        """
        # FIXED SETTINGS for speed optimization
        batch_size = 10000  # Maximum speed
        timeout = 1500      # Fast timeout
        ulimit = 5000       # Standard limit
        try:
            # Build RustScan command - SPEED OPTIMIZED ONLY
            cmd = [
                "rustscan",
                "-a", target,
                "-g",  # Greppable output
                "--batch-size", str(batch_size),
                "--timeout", str(timeout),
                "--ulimit", str(ulimit)
            ]
            
            # Execute in Docker or locally
            if self.docker_mode:
                cmd = ["docker", "exec", self.container_name] + cmd
            
            logger.info(f"Running RustScan: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90  # Fixed timeout for speed
            )
            
            # Parse output
            open_ports = self._parse_output(result.stdout)
            
            return {
                "success": len(open_ports) > 0,
                "tool": "rustscan",
                "role": "speed",
                "purpose": "Fast port discovery for Nmap",
                "ports": open_ports,  # ONLY ports, no service info
                "port_count": len(open_ports),
                "feed_to_nmap": True,  # Indicates this feeds to Nmap
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
    
    # REMOVED: All custom scan methods
    # REASON: RustScan has ONE job - fast port discovery
    # Use Nmap for everything else
