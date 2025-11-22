"""OpenVAS scanner wrapper using python-gvm."""

import time
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List
from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv224 import Gmp as Gmpv224
from gvm.transforms import EtreeTransform
from gvm.errors import GvmError
import socket
from utils import logger, get_output_path, ensure_directory


class OpenVASScanner:
    """Wrapper class for OpenVAS/Greenbone vulnerability scanner."""
    
    def __init__(
        self,
        host: str = "openvas",
        port: int = 9390,
        username: str = "admin",
        password: str = "admin"
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.scan_dir = Path("/app/scans/openvas")
        ensure_directory(self.scan_dir)
        logger.info(f"Initialized OpenVASScanner for {host}:{port}")
    
    def _connect(self):
        """Create GMP connection."""
        try:
            # Try TLS connection with GMP v22.4 (compatible with this OpenVAS version)
            connection = TLSConnection(
                hostname=self.host,
                port=self.port,
                timeout=60
            )
            transform = EtreeTransform()
            
            with Gmpv224(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                logger.info("Successfully authenticated to OpenVAS")
                return gmp
                
        except Exception as e:
            logger.error(f"Failed to connect to OpenVAS: {str(e)}")
            raise
    
    def create_target(
        self,
        name: str,
        hosts: List[str],
        port_list_id: Optional[str] = None,
        alive_test: str = "ICMP Ping"
    ) -> Dict[str, Any]:
        """
        Create a scan target.
        
        Args:
            name: Target name
            hosts: List of hosts/IPs to scan
            port_list_id: Port list UUID (default: All IANA assigned TCP)
            alive_test: Alive test method
        
        Returns:
            Dict with target_id and status
        """
        logger.info(f"Creating target: {name} for hosts: {hosts}")
        
        try:
            with Gmpv224(
                connection=TLSConnection(hostname=self.host, port=self.port),
                transform=EtreeTransform()
            ) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Get default port list if not provided
                if not port_list_id:
                    port_lists = gmp.get_port_lists()
                    for port_list in port_lists.xpath('port_list'):
                        if 'All IANA' in port_list.find('name').text:
                            port_list_id = port_list.get('id')
                            break
                
                # Create target
                response = gmp.create_target(
                    name=name,
                    hosts=hosts,
                    port_list_id=port_list_id
                )
                
                target_id = response.get('id')
                logger.info(f"Target created successfully: {target_id}")
                
                return {
                    "success": True,
                    "target_id": target_id,
                    "name": name,
                    "hosts": hosts
                }
                
        except GvmError as e:
            logger.error(f"GVM Error creating target: {str(e)}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Error creating target: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def create_task(
        self,
        name: str,
        target_id: str,
        scanner_id: Optional[str] = None,
        config_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a scan task.
        
        Args:
            name: Task name
            target_id: Target UUID
            scanner_id: Scanner UUID (default: OpenVAS Default)
            config_id: Scan config UUID (default: Full and fast)
        
        Returns:
            Dict with task_id and status
        """
        logger.info(f"Creating task: {name} for target: {target_id}")
        
        try:
            with Gmpv224(
                connection=TLSConnection(hostname=self.host, port=self.port),
                transform=EtreeTransform()
            ) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Get default scanner if not provided
                if not scanner_id:
                    scanners = gmp.get_scanners()
                    for scanner in scanners.xpath('scanner'):
                        if 'OpenVAS' in scanner.find('name').text:
                            scanner_id = scanner.get('id')
                            break
                
                # Get default config if not provided
                if not config_id:
                    configs = gmp.get_scan_configs()
                    for config in configs.xpath('config'):
                        if 'Full and fast' in config.find('name').text:
                            config_id = config.get('id')
                            break
                
                # Create task
                response = gmp.create_task(
                    name=name,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id
                )
                
                task_id = response.get('id')
                logger.info(f"Task created successfully: {task_id}")
                
                return {
                    "success": True,
                    "task_id": task_id,
                    "name": name,
                    "target_id": target_id
                }
                
        except GvmError as e:
            logger.error(f"GVM Error creating task: {str(e)}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Error creating task: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def start_scan(self, task_id: str) -> Dict[str, Any]:
        """
        Start a scan task.
        
        Args:
            task_id: Task UUID
        
        Returns:
            Dict with report_id and status
        """
        logger.info(f"Starting scan for task: {task_id}")
        
        try:
            with Gmpv224(
                connection=TLSConnection(hostname=self.host, port=self.port),
                transform=EtreeTransform()
            ) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.start_task(task_id)
                report_id = response.find('report_id').text
                
                logger.info(f"Scan started successfully. Report ID: {report_id}")
                
                return {
                    "success": True,
                    "task_id": task_id,
                    "report_id": report_id,
                    "status": "running"
                }
                
        except GvmError as e:
            logger.error(f"GVM Error starting scan: {str(e)}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def get_scan_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get scan task status.
        
        Args:
            task_id: Task UUID
        
        Returns:
            Dict with status and progress
        """
        try:
            with Gmpv224(
                connection=TLSConnection(hostname=self.host, port=self.port),
                transform=EtreeTransform()
            ) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.get_task(task_id)
                task = response.find('task')
                
                status = task.find('status').text
                progress = task.find('progress').text if task.find('progress') is not None else "0"
                
                logger.info(f"Task {task_id} status: {status} ({progress}%)")
                
                return {
                    "success": True,
                    "task_id": task_id,
                    "status": status,
                    "progress": progress
                }
                
        except GvmError as e:
            logger.error(f"GVM Error getting status: {str(e)}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Error getting status: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def wait_for_scan(self, task_id: str, timeout: int = 3600) -> Dict[str, Any]:
        """
        Wait for scan to complete.
        
        Args:
            task_id: Task UUID
            timeout: Maximum wait time in seconds
        
        Returns:
            Dict with final status
        """
        logger.info(f"Waiting for scan {task_id} to complete...")
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_scan_status(task_id)
            
            if not status["success"]:
                return status
            
            if status["status"] in ["Done", "Stopped", "Interrupted"]:
                logger.info(f"Scan completed with status: {status['status']}")
                return status
            
            time.sleep(10)
        
        logger.warning(f"Scan timeout after {timeout} seconds")
        return {"success": False, "error": "Scan timeout"}
    
    def fetch_report(
        self,
        report_id: str,
        output_format: str = "xml"
    ) -> Dict[str, Any]:
        """
        Fetch scan report.
        
        Args:
            report_id: Report UUID
            output_format: Report format (xml, pdf, html, csv)
        
        Returns:
            Dict with report content
        """
        logger.info(f"Fetching report: {report_id} in format: {output_format}")
        
        try:
            with Gmpv224(
                connection=TLSConnection(hostname=self.host, port=self.port),
                transform=EtreeTransform()
            ) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Get report format ID
                formats = gmp.get_report_formats()
                format_id = None
                
                format_map = {
                    "xml": "XML",
                    "pdf": "PDF",
                    "html": "HTML",
                    "csv": "CSV"
                }
                
                search_name = format_map.get(output_format, "XML")
                
                for fmt in formats.xpath('report_format'):
                    if search_name in fmt.find('name').text:
                        format_id = fmt.get('id')
                        break
                
                if not format_id:
                    logger.warning(f"Format {output_format} not found, using XML")
                    format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"  # XML format
                
                # Get report
                response = gmp.get_report(
                    report_id=report_id,
                    report_format_id=format_id
                )
                
                # Save report
                output_path = get_output_path("openvas_report", report_id, output_format)
                
                # Convert XML element to bytes if needed
                from lxml import etree
                if hasattr(response, 'tag'):  # It's an XML element
                    report_content = etree.tostring(response, pretty_print=True)
                else:
                    report_content = response
                
                with open(output_path, 'wb') as f:
                    f.write(report_content)
                
                logger.info(f"Report saved to: {output_path}")
                
                return {
                    "success": True,
                    "report_id": report_id,
                    "output_path": str(output_path),
                    "format": output_format
                }
                
        except GvmError as e:
            logger.error(f"GVM Error fetching report: {str(e)}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Error fetching report: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def export_report(
        self,
        task_id: str,
        output_format: str = "xml"
    ) -> Dict[str, Any]:
        """
        Export report for a completed task.
        
        Args:
            task_id: Task UUID
            output_format: Report format
        
        Returns:
            Dict with export status and path
        """
        logger.info(f"Exporting report for task: {task_id}")
        
        try:
            # Get task to find report ID
            with Gmpv224(
                connection=TLSConnection(hostname=self.host, port=self.port),
                transform=EtreeTransform()
            ) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.get_task(task_id)
                task = response.find('task')
                
                # Get last report
                last_report = task.find('.//last_report/report')
                if last_report is None:
                    return {"success": False, "error": "No report found for task"}
                
                report_id = last_report.get('id')
                
                # Fetch the report
                return self.fetch_report(report_id, output_format)
                
        except Exception as e:
            logger.error(f"Error exporting report: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def quick_scan(
        self,
        target_name: str,
        hosts: List[str],
        wait: bool = True
    ) -> Dict[str, Any]:
        """
        Perform a quick scan (create target, task, and start scan).
        
        Args:
            target_name: Name for the target
            hosts: List of hosts to scan
            wait: Wait for scan to complete
        
        Returns:
            Dict with scan results
        """
        logger.info(f"Starting quick scan for: {hosts}")
        
        # Create target
        target_result = self.create_target(target_name, hosts)
        if not target_result["success"]:
            return target_result
        
        target_id = target_result["target_id"]
        
        # Create task
        task_name = f"Scan_{target_name}"
        task_result = self.create_task(task_name, target_id)
        if not task_result["success"]:
            return task_result
        
        task_id = task_result["task_id"]
        
        # Start scan
        scan_result = self.start_scan(task_id)
        if not scan_result["success"]:
            return scan_result
        
        if wait:
            # Wait for completion
            status = self.wait_for_scan(task_id)
            if status["success"] and status["status"] == "Done":
                # Export report
                return self.export_report(task_id, "xml")
        
        return scan_result


# Example usage
if __name__ == "__main__":
    scanner = OpenVASScanner()
    
    # Test quick scan
    result = scanner.quick_scan("test_target", ["192.168.1.1"], wait=False)
    print(f"Scan result: {result}")
