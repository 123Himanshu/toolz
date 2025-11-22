#!/usr/bin/env python3
"""
Nmap Wrapper - Network scanning and service detection
"""
import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class NmapWrapper:
    """Wrapper for Nmap network scanner"""
    
    def __init__(self, docker_mode: bool = True):
        """
        Initialize Nmap wrapper
        
        Args:
            docker_mode: If True, run Nmap in Docker container
        """
        import os
        # Auto-detect if running inside Docker
        if os.path.exists('/.dockerenv'):
            self.docker_mode = False  # Already in Docker, use local commands
            logger.info("Running inside Docker container - using local Nmap")
        else:
            self.docker_mode = docker_mode
        self.container_name = "multi-tool-scanner"
        
    def is_available(self) -> bool:
        """Check if Nmap is available"""
        try:
            if self.docker_mode:
                result = subprocess.run(
                    ["docker", "exec", self.container_name, "nmap", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:
                result = subprocess.run(
                    ["nmap", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Nmap availability check failed: {e}")
            return False
    
    def scan(self, target: str, arguments: str = "-sV", 
             ports: Optional[List[int]] = None) -> Dict:
        """
        Run Nmap scan
        
        Args:
            target: Target IP or hostname
            arguments: Nmap arguments (e.g., "-sV -O")
            ports: List of ports to scan (optional)
            
        Returns:
            Dict with scan results
        """
        try:
            # Build Nmap command
            cmd = ["nmap", "-oX", "-"]
            
            # Add custom arguments
            if arguments:
                cmd.extend(arguments.split())
            
            # Add ports if specified
            if ports:
                port_str = ",".join(map(str, ports))
                cmd.extend(["-p", port_str])
            
            cmd.append(target)
            
            # Execute in Docker or locally
            if self.docker_mode:
                cmd = ["docker", "exec", self.container_name] + cmd
            
            logger.info(f"Running Nmap: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse XML output
            scan_data = self._parse_xml(result.stdout)
            
            return {
                "success": result.returncode == 0,
                "data": scan_data,
                "raw_output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None,
                "command": " ".join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            error_msg = "Nmap scan timed out after 300s"
            logger.error(error_msg)
            return {
                "success": False,
                "data": {},
                "raw_output": "",
                "error": error_msg,
                "command": " ".join(cmd)
            }
        except Exception as e:
            logger.error(f"Nmap execution failed: {e}")
            return {
                "success": False,
                "data": {},
                "raw_output": "",
                "error": str(e),
                "command": " ".join(cmd) if 'cmd' in locals() else "N/A"
            }
    
    def _parse_xml(self, xml_output: str) -> Dict:
        """
        Parse Nmap XML output
        
        Args:
            xml_output: Raw XML output from Nmap
            
        Returns:
            Dict with parsed scan data
        """
        try:
            root = ET.fromstring(xml_output)
            
            scan_data = {
                "hosts": {},
                "scan_stats": {},
                "command_line": root.get("args", "")
            }
            
            # Parse scan stats
            runstats = root.find("runstats")
            if runstats is not None:
                finished = runstats.find("finished")
                if finished is not None:
                    scan_data["scan_stats"] = {
                        "elapsed": finished.get("elapsed", "0"),
                        "exit": finished.get("exit", "unknown")
                    }
            
            # Parse hosts
            for host in root.findall("host"):
                host_data = self._parse_host(host)
                if host_data:
                    ip = host_data.get("ip", "unknown")
                    scan_data["hosts"][ip] = host_data
            
            return scan_data
            
        except Exception as e:
            logger.error(f"XML parsing failed: {e}")
            return {"error": str(e)}
    
    def _parse_host(self, host_elem) -> Dict:
        """Parse individual host element"""
        host_data = {
            "ip": "",
            "hostname": "",
            "state": "",
            "ports": []
        }
        
        # Get IP address
        address = host_elem.find("address[@addrtype='ipv4']")
        if address is not None:
            host_data["ip"] = address.get("addr", "")
        
        # Get hostname
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hostname = hostnames.find("hostname")
            if hostname is not None:
                host_data["hostname"] = hostname.get("name", "")
        
        # Get host state
        status = host_elem.find("status")
        if status is not None:
            host_data["state"] = status.get("state", "")
        
        # Get ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_data = self._parse_port(port)
                if port_data:
                    host_data["ports"].append(port_data)
        
        return host_data
    
    def _parse_port(self, port_elem) -> Dict:
        """Parse individual port element"""
        port_data = {
            "port": port_elem.get("portid", ""),
            "protocol": port_elem.get("protocol", ""),
            "state": "",
            "service": "",
            "version": ""
        }
        
        # Get port state
        state = port_elem.find("state")
        if state is not None:
            port_data["state"] = state.get("state", "")
        
        # Get service info
        service = port_elem.find("service")
        if service is not None:
            port_data["service"] = service.get("name", "")
            port_data["version"] = service.get("version", "")
            if service.get("product"):
                port_data["product"] = service.get("product", "")
        
        return port_data
    
    # Predefined scan types
    def quick_scan(self, target: str) -> Dict:
        """Quick scan - Top 100 ports"""
        return self.scan(target, "-T4 --top-ports 100")
    
    def service_scan(self, target: str, ports: Optional[List[int]] = None) -> Dict:
        """Service version detection"""
        return self.scan(target, "-sV", ports)
    
    def os_scan(self, target: str) -> Dict:
        """OS detection scan"""
        return self.scan(target, "-O")
    
    def aggressive_scan(self, target: str) -> Dict:
        """Aggressive scan with OS, version, script, traceroute"""
        return self.scan(target, "-A")
    
    def stealth_scan(self, target: str, ports: Optional[List[int]] = None) -> Dict:
        """Stealth SYN scan"""
        return self.scan(target, "-sS", ports)
    
    def udp_scan(self, target: str) -> Dict:
        """UDP scan"""
        return self.scan(target, "-sU --top-ports 20")
    
    def vulnerability_scan(self, target: str, ports: Optional[List[int]] = None) -> Dict:
        """Vulnerability detection with scripts"""
        return self.scan(target, "-sV --script vuln", ports)
    
    def full_scan(self, target: str) -> Dict:
        """Full port scan (all 65535 ports)"""
        return self.scan(target, "-p- -T4")
