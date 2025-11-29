"""
OpenVAS Scanner Wrapper - GMP Protocol Integration
Connects to OpenVAS container via GMP (Greenbone Management Protocol)
"""

import json
import sys
import time
import socket
import ssl
from typing import Dict, Any, Optional
from datetime import datetime


class OpenVASScanner:
    """
    OpenVAS scanner wrapper using GMP protocol
    Connects to OpenVAS container running separately
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 9390,
        username: str = "admin",
        password: str = "admin"
    ):
        """
        Initialize OpenVAS scanner
        
        Args:
            host: OpenVAS hostname (default: localhost for external container)
            port: OpenVAS GMP port (default: 9390)
            username: OpenVAS username
            password: OpenVAS password
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._gvm_available = None
    
    def _get_connection(self):
        """Get the appropriate GMP connection with TLS (self-signed cert support)"""
        from gvm.connections import TLSConnection
        
        # TLSConnection with certfile/cafile=None accepts self-signed certs
        connection = TLSConnection(
            hostname=self.host,
            port=self.port,
            timeout=30,
            certfile=None,
            cafile=None,
            keyfile=None
        )
        return connection
        
    def is_available(self) -> bool:
        """Check if OpenVAS is available via GMP"""
        if self._gvm_available is not None:
            return self._gvm_available
        
        # First check if port is open
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((self.host, self.port))
            s.close()
            if result != 0:
                sys.stderr.write(f"OpenVAS not available: Port {self.port} not open\n")
                self._gvm_available = False
                return False
        except Exception as e:
            sys.stderr.write(f"OpenVAS not available: {e}\n")
            self._gvm_available = False
            return False
        
        # Try GMP connection
        try:
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = self._get_connection()
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                self._gvm_available = True
                return True
                
        except ImportError:
            sys.stderr.write("python-gvm not installed. Install with: pip install python-gvm\n")
            self._gvm_available = False
            return False
        except Exception as e:
            sys.stderr.write(f"OpenVAS GMP error: {e}\n")
            # Port is open but GMP failed - still mark as available for basic connectivity
            self._gvm_available = True
            return True
    
    def scan(
        self,
        target: str,
        scan_type: str = "full",
        timeout: int = 3600,
        wait_for_completion: bool = False
    ) -> Dict[str, Any]:
        """
        Run OpenVAS scan using GMP protocol
        
        Args:
            target: Target IP or hostname
            scan_type: Scan type (full, fast, discovery)
            timeout: Scan timeout in seconds
            wait_for_completion: Wait for scan to complete (default: False for async)
            
        Returns:
            Dict with scan results
        """
        start_time = datetime.now()
        
        # Check if OpenVAS is available
        if not self.is_available():
            return {
                'success': True,  # Not an error, just not configured
                'tool': 'openvas',
                'role': 'core',
                'target': target,
                'status': 'not_configured',
                'message': 'OpenVAS requires separate container setup',
                'note': 'OpenVAS requires separate container with PostgreSQL and Redis',
                'setup_instructions': [
                    '1. cd security-scanner',
                    '2. docker-compose -f docker-compose.openvas.yml up -d',
                    '3. Wait 5 minutes for OpenVAS to initialize',
                    '4. Access web UI: http://localhost:9390',
                    '5. Login: admin/admin'
                ],
                'vulnerabilities_found': 0,
                'executed_at': start_time.isoformat(),
                'completed_at': datetime.now().isoformat(),
                'duration': 0
            }
        
        # Run actual scan using GMP
        try:
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            from gvm.errors import GvmError
            
            connection = self._get_connection()
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Get default port list
                port_lists = gmp.get_port_lists()
                port_list_id = None
                for port_list in port_lists.xpath('port_list'):
                    if 'All IANA' in port_list.find('name').text:
                        port_list_id = port_list.get('id')
                        break
                
                # Create target
                target_name = f"target_{target}_{int(time.time())}"
                target_response = gmp.create_target(
                    name=target_name,
                    hosts=[target],
                    port_list_id=port_list_id
                )
                target_id = target_response.get('id')
                
                # Get scanner and config based on scan type
                scanners = gmp.get_scanners()
                scanner_id = None
                for scanner in scanners.xpath('scanner'):
                    if 'OpenVAS' in scanner.find('name').text:
                        scanner_id = scanner.get('id')
                        break
                
                configs = gmp.get_scan_configs()
                config_id = None
                config_name = 'Full and fast' if scan_type == 'full' else 'Discovery'
                for config in configs.xpath('config'):
                    if config_name in config.find('name').text:
                        config_id = config.get('id')
                        break
                
                # Create task
                task_name = f"scan_{target}_{int(time.time())}"
                task_response = gmp.create_task(
                    name=task_name,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id
                )
                task_id = task_response.get('id')
                
                # Start scan
                start_response = gmp.start_task(task_id)
                report_id = start_response.find('report_id').text
                
                # If wait_for_completion, poll for results
                vulnerabilities_found = 0
                scan_status = 'running'
                
                if wait_for_completion:
                    sys.stderr.write(f"Waiting for scan to complete (timeout: {timeout}s)...\n")
                    start_wait = time.time()
                    
                    while time.time() - start_wait < timeout:
                        task_status = gmp.get_task(task_id)
                        task = task_status.find('task')
                        status = task.find('status').text
                        progress = task.find('progress').text if task.find('progress') is not None else "0"
                        
                        sys.stderr.write(f"Scan progress: {progress}% (status: {status})\n")
                        
                        if status in ["Done", "Stopped", "Interrupted"]:
                            scan_status = status.lower()
                            
                            # Get report
                            report = gmp.get_report(report_id)
                            results = report.xpath('//result')
                            vulnerabilities_found = len(results)
                            break
                        
                        time.sleep(10)
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                return {
                    'success': True,
                    'tool': 'openvas',
                    'role': 'core',
                    'purpose': 'Enterprise vulnerability scanning (50,000+ tests)',
                    'target': target,
                    'scan_type': scan_type,
                    'task_id': task_id,
                    'report_id': report_id,
                    'status': scan_status,
                    'vulnerabilities_found': vulnerabilities_found,
                    'executed_at': start_time.isoformat(),
                    'completed_at': end_time.isoformat(),
                    'duration': duration,
                    'web_ui': f'https://{self.host}:9390',
                    'note': 'Scan started successfully. View progress in web UI or wait for completion.'
                }
            
        except ImportError as e:
            return {
                'success': False,
                'tool': 'openvas',
                'target': target,
                'error': f'Missing dependency: {e}. Install with: pip install python-gvm'
            }
        except GvmError as e:
            return {
                'success': False,
                'tool': 'openvas',
                'target': target,
                'error': f'GVM Error: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'tool': 'openvas',
                'target': target,
                'error': str(e)
            }
    
    def quick_scan(self, target: str, wait: bool = False) -> Dict[str, Any]:
        """
        Quick OpenVAS scan (Discovery mode)
        
        Args:
            target: Target IP or hostname
            wait: Wait for scan completion
        """
        return self.scan(target, scan_type='discovery', timeout=600, wait_for_completion=wait)
    
    def full_scan(self, target: str, wait: bool = False) -> Dict[str, Any]:
        """
        Full OpenVAS scan (Full and fast mode)
        
        Args:
            target: Target IP or hostname
            wait: Wait for scan completion
        """
        return self.scan(target, scan_type='full', timeout=3600, wait_for_completion=wait)
    
    def get_scan_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get status of a running scan
        
        Args:
            task_id: Task ID from scan() result
            
        Returns:
            Dict with scan status and progress
        """
        try:
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = self._get_connection()
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                task_status = gmp.get_task(task_id)
                task = task_status.find('task')
                
                status = task.find('status').text
                progress = task.find('progress').text if task.find('progress') is not None else "0"
                
                # Get report if done
                vulnerabilities = 0
                if status == "Done":
                    last_report = task.find('.//last_report/report')
                    if last_report is not None:
                        report_id = last_report.get('id')
                        report = gmp.get_report(report_id)
                        results = report.xpath('//result')
                        vulnerabilities = len(results)
                
                return {
                    'success': True,
                    'task_id': task_id,
                    'status': status.lower(),
                    'progress': progress,
                    'vulnerabilities_found': vulnerabilities
                }
                
        except Exception as e:
            return {
                'success': False,
                'task_id': task_id,
                'error': str(e)
            }
    
    def get_report(self, task_id: str, format: str = 'json') -> Dict[str, Any]:
        """
        Get scan report
        
        Args:
            task_id: Task ID from scan() result
            format: Report format (json, xml, pdf, html)
            
        Returns:
            Dict with report data
        """
        try:
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = self._get_connection()
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Get task to find report
                task_status = gmp.get_task(task_id)
                task = task_status.find('task')
                last_report = task.find('.//last_report/report')
                
                if last_report is None:
                    return {
                        'success': False,
                        'error': 'No report found for this task'
                    }
                
                report_id = last_report.get('id')
                report = gmp.get_report(report_id)
                
                # Parse vulnerabilities
                results = report.xpath('//result')
                vulnerabilities = []
                
                for result in results:
                    vuln = {
                        'name': result.find('name').text if result.find('name') is not None else 'Unknown',
                        'severity': result.find('severity').text if result.find('severity') is not None else '0',
                        'host': result.find('host').text if result.find('host') is not None else '',
                        'port': result.find('port').text if result.find('port') is not None else '',
                        'description': result.find('description').text if result.find('description') is not None else ''
                    }
                    vulnerabilities.append(vuln)
                
                return {
                    'success': True,
                    'task_id': task_id,
                    'report_id': report_id,
                    'vulnerabilities_found': len(vulnerabilities),
                    'vulnerabilities': vulnerabilities,
                    'format': format
                }
                
        except Exception as e:
            return {
                'success': False,
                'task_id': task_id,
                'error': str(e)
            }


# Example usage
if __name__ == "__main__":
    scanner = OpenVASScanner()
    
    print("Testing OpenVAS availability...")
    if scanner.is_available():
        print("✓ OpenVAS is available!")
        result = scanner.quick_scan("scanme.nmap.org")
        print(json.dumps(result, indent=2))
    else:
        print("✗ OpenVAS not available")
        print("\nTo start OpenVAS:")
        print("  docker-compose -f docker-compose.openvas.yml up -d")
