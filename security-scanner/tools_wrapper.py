"""
Multi-Tool Scanner Wrapper
Integrates: RustScan + Nmap + Masscan + Naabu + ZMap
"""

from rustscan_wrapper import RustScanWrapper
from nmap_wrapper import NmapWrapper
from masscan_wrapper import MasscanWrapper
from naabu_wrapper import NaabuWrapper
from zmap_wrapper import ZMapWrapper
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class MultiToolScanner:
    """
    Multi-Tool Scanner - RustScan + Nmap + Masscan + Naabu + ZMap Integration
    Provides unified interface for all tools
    """
    
    def __init__(self, docker_mode: bool = True):
        """
        Initialize multi-tool scanner
        
        Args:
            docker_mode: If True, run tools in Docker container
        """
        self.docker_mode = docker_mode
        self.rustscan = RustScanWrapper(docker_mode=docker_mode)
        self.nmap = NmapWrapper(docker_mode=docker_mode)
        self.masscan = MasscanWrapper()
        self.naabu = NaabuWrapper()
        self.zmap = ZMapWrapper()
        
        # Check which tools are available
        self.available_tools = {
            'rustscan': self.rustscan.is_available(),
            'nmap': self.nmap.is_available(),
            'masscan': True,  # Masscan installed via apt
            'naabu': True,  # Naabu installed from binary
            'zmap': True  # ZMap installed via apt
        }
        
        logger.info(f"Docker mode: {docker_mode}")
        logger.info(f"Available tools: {self.available_tools}")
    
    def scan(self, target: str, tool: str = 'both', mode: str = 'pipeline',
             nmap_args: str = '-sV', rustscan_config: Dict = None) -> Dict:
        """
        Unified scan interface
        
        Args:
            target: Target IP or hostname
            tool: 'rustscan', 'nmap', or 'both'
            mode: 'pipeline', 'parallel', or 'independent' (only for 'both')
            nmap_args: Nmap arguments
            rustscan_config: RustScan configuration dict
            
        Returns:
            Dict with scan results
        """
        if tool == 'rustscan':
            return self._rustscan_only(target, rustscan_config or {})
        elif tool == 'nmap':
            return self._nmap_only(target, nmap_args)
        elif tool == 'both':
            if mode == 'pipeline':
                return self._pipeline_scan(target, nmap_args, rustscan_config or {})
            elif mode == 'parallel':
                return self._parallel_scan(target, nmap_args, rustscan_config or {})
            elif mode == 'independent':
                return self._independent_scan(target, nmap_args, rustscan_config or {})
        
        return {'error': f'Invalid tool: {tool}'}
    
    def _rustscan_only(self, target: str, config: Dict) -> Dict:
        """RustScan only - Fast port discovery"""
        logger.info(f"RustScan-only scan on {target}")
        
        result = self.rustscan.scan(
            target,
            ports=config.get('ports'),
            batch_size=config.get('batch_size', 5000),
            timeout=config.get('timeout', 3000),
            ulimit=config.get('ulimit', 5000),
            aggressive=config.get('aggressive', False)
        )
        
        return {
            'tool': 'rustscan',
            'mode': 'standalone',
            'target': target,
            'success': result['success'],
            'ports': result['ports'],
            'command': result['command'],
            'raw_output': result['raw_output'],
            'error': result.get('error')
        }
    
    def _nmap_only(self, target: str, arguments: str) -> Dict:
        """Nmap only - Full featured scanning"""
        logger.info(f"Nmap-only scan on {target}")
        
        result = self.nmap.scan(target, arguments)
        
        return {
            'tool': 'nmap',
            'mode': 'standalone',
            'target': target,
            'success': result['success'],
            'data': result['data'],
            'command': result['command'],
            'raw_output': result['raw_output'],
            'error': result.get('error')
        }
    
    def _pipeline_scan(self, target: str, nmap_args: str, rustscan_config: Dict) -> Dict:
        """Pipeline: RustScan finds ports → Nmap scans those ports (NO FALLBACK)"""
        logger.info(f"Pipeline scan on {target}")
        
        # Step 1: RustScan port discovery
        rustscan_result = self.rustscan.scan(
            target,
            ports=rustscan_config.get('ports'),
            batch_size=rustscan_config.get('batch_size', 5000),
            timeout=rustscan_config.get('timeout', 3000),
            aggressive=rustscan_config.get('aggressive', False)
        )
        
        # Step 2: Nmap detailed scan on discovered ports
        ports = rustscan_result['ports']
        
        if not rustscan_result['success']:
            # RustScan failed - return error, NO FALLBACK
            logger.error(f"RustScan failed: {rustscan_result.get('error')}")
            return {
                'tool': 'both',
                'mode': 'pipeline',
                'target': target,
                'success': False,
                'error': f"RustScan failed: {rustscan_result.get('error')}. Pipeline cannot continue.",
                'rustscan': {
                    'success': False,
                    'ports': [],
                    'command': rustscan_result['command'],
                    'error': rustscan_result.get('error')
                },
                'nmap': {
                    'success': False,
                    'data': {},
                    'command': 'Not executed - RustScan failed',
                    'error': 'Skipped due to RustScan failure'
                }
            }
        
        if not ports:
            # RustScan succeeded but found no ports
            logger.warning("RustScan found no open ports")
            return {
                'tool': 'both',
                'mode': 'pipeline',
                'target': target,
                'success': True,
                'message': 'RustScan completed successfully but found no open ports',
                'rustscan': {
                    'success': True,
                    'ports': [],
                    'command': rustscan_result['command'],
                    'error': None
                },
                'nmap': {
                    'success': False,
                    'data': {},
                    'command': 'Not executed - no ports to scan',
                    'error': 'No ports found by RustScan'
                }
            }
        
        # RustScan found ports - scan them with Nmap
        nmap_result = self.nmap.scan(target, nmap_args, ports)
        
        return {
            'tool': 'both',
            'mode': 'pipeline',
            'target': target,
            'rustscan': {
                'success': rustscan_result['success'],
                'ports': rustscan_result['ports'],
                'command': rustscan_result['command'],
                'error': rustscan_result.get('error')
            },
            'nmap': {
                'success': nmap_result['success'],
                'data': nmap_result['data'],
                'command': nmap_result['command'],
                'error': nmap_result.get('error')
            },
            'success': rustscan_result['success'] and nmap_result['success']
        }
    
    def _parallel_scan(self, target: str, nmap_args: str, rustscan_config: Dict) -> Dict:
        """Parallel: Run RustScan and Nmap simultaneously"""
        logger.info(f"Parallel scan on {target}")
        
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            # Submit both scans
            rustscan_future = executor.submit(
                self.rustscan.scan,
                target,
                rustscan_config.get('ports'),
                rustscan_config.get('batch_size', 5000),
                rustscan_config.get('timeout', 3000),
                rustscan_config.get('ulimit', 5000),
                rustscan_config.get('aggressive', False)
            )
            
            nmap_future = executor.submit(
                self.nmap.scan,
                target,
                nmap_args
            )
            
            # Wait for results
            rustscan_result = rustscan_future.result()
            nmap_result = nmap_future.result()
        
        return {
            'tool': 'both',
            'mode': 'parallel',
            'target': target,
            'rustscan': {
                'success': rustscan_result['success'],
                'ports': rustscan_result['ports'],
                'command': rustscan_result['command'],
                'error': rustscan_result.get('error')
            },
            'nmap': {
                'success': nmap_result['success'],
                'data': nmap_result['data'],
                'command': nmap_result['command'],
                'error': nmap_result.get('error')
            },
            'success': rustscan_result['success'] or nmap_result['success']
        }
    
    def _independent_scan(self, target: str, nmap_args: str, rustscan_config: Dict) -> Dict:
        """Independent: Run both tools separately, return both results"""
        logger.info(f"Independent scan on {target}")
        
        # Run RustScan
        rustscan_result = self.rustscan.scan(
            target,
            ports=rustscan_config.get('ports'),
            batch_size=rustscan_config.get('batch_size', 5000),
            timeout=rustscan_config.get('timeout', 3000),
            aggressive=rustscan_config.get('aggressive', False)
        )
        
        # Run Nmap independently
        nmap_result = self.nmap.scan(target, nmap_args)
        
        return {
            'tool': 'both',
            'mode': 'independent',
            'target': target,
            'rustscan': {
                'success': rustscan_result['success'],
                'ports': rustscan_result['ports'],
                'command': rustscan_result['command'],
                'raw_output': rustscan_result['raw_output'],
                'error': rustscan_result.get('error')
            },
            'nmap': {
                'success': nmap_result['success'],
                'data': nmap_result['data'],
                'command': nmap_result['command'],
                'raw_output': nmap_result['raw_output'],
                'error': nmap_result.get('error')
            },
            'success': rustscan_result['success'] or nmap_result['success']
        }

    
    def masscan_scan(self, ip_range: str, ports: str = "1-1000", rate: int = None,
                     max_rate: int = None, exclude_ports: str = None) -> Dict:
        """
        Masscan IP range scan - ONLY for large-scale port discovery
        
        Args:
            ip_range: IP range (e.g., "192.168.1.0/24", "10.0.0.0/16")
            ports: Port range (e.g., "80,443", "1-1000", "1-65535")
            rate: Packets per second (auto-calculated if None)
            max_rate: Maximum rate limit (optional)
            exclude_ports: Ports to exclude (optional)
        
        Returns:
            Dict with discovered IPs and their open ports
        """
        logger.info(f"Masscan scan on IP range: {ip_range}")
        
        # Validate IP range
        if not self.masscan.validate_ip_range(ip_range):
            return {
                'success': False,
                'error': 'Invalid IP range format. Use CIDR (e.g., 192.168.1.0/24)'
            }
        
        # Auto-calculate rate if not provided
        if rate is None:
            # Extract CIDR size
            cidr_size = int(ip_range.split('/')[-1]) if '/' in ip_range else 32
            rate = self.masscan.get_recommended_rate(cidr_size)
            logger.info(f"Auto-calculated rate: {rate} pps for /{cidr_size}")
        
        # Run masscan
        result = self.masscan.scan(
            ip_range=ip_range,
            ports=ports,
            rate=rate,
            max_rate=max_rate,
            exclude_ports=exclude_ports
        )
        
        return result
    
    def masscan_then_nmap(self, ip_range: str, ports: str = "1-1000", 
                          nmap_args: str = "-sV", rate: int = None) -> Dict:
        """
        Pipeline: Masscan discovers IPs/ports → Nmap scans them for details
        
        This is the BEST PRACTICE for large IP ranges:
        1. Masscan quickly finds all IPs with open ports
        2. Nmap does detailed service detection on discovered targets
        
        Args:
            ip_range: IP range to scan
            ports: Ports to scan
            nmap_args: Nmap arguments for detailed scanning
            rate: Masscan scan rate (auto if None)
        
        Returns:
            Dict with masscan discovery + nmap details
        """
        logger.info(f"Masscan→Nmap pipeline on {ip_range}")
        
        # Step 1: Masscan discovery
        masscan_result = self.masscan_scan(ip_range, ports, rate)
        
        if not masscan_result['success']:
            return {
                'success': False,
                'tool': 'masscan',
                'error': masscan_result['error']
            }
        
        discovered = masscan_result['discovered']
        
        if not discovered:
            return {
                'success': True,
                'tool': 'masscan_nmap_pipeline',
                'masscan': masscan_result,
                'nmap': {'message': 'No targets discovered by Masscan'},
                'total_ips_scanned': 0
            }
        
        # Step 2: Nmap detailed scan on discovered targets
        nmap_results = []
        
        for target_data in discovered:
            ip = target_data['ip']
            open_ports = [str(p['port']) for p in target_data['open_ports']]
            ports_str = ','.join(open_ports)
            
            logger.info(f"Nmap scanning {ip} on ports {ports_str}")
            
            # Scan this IP with Nmap
            nmap_result = self.nmap.scan(
                target=ip,
                arguments=f"{nmap_args} -p {ports_str}"
            )
            
            nmap_results.append({
                'ip': ip,
                'masscan_ports': open_ports,
                'nmap_result': nmap_result
            })
        
        return {
            'success': True,
            'tool': 'masscan_nmap_pipeline',
            'ip_range': ip_range,
            'masscan': {
                'total_ips_found': len(discovered),
                'total_ports_found': masscan_result['total_ports'],
                'rate': masscan_result['rate'],
                'discovered': discovered
            },
            'nmap': {
                'targets_scanned': len(nmap_results),
                'results': nmap_results
            },
            'pipeline_mode': 'masscan_discovery_then_nmap_details'
        }
    
    def naabu_scan(self, domain: str, ports: str = None, top_ports: int = None,
                   rate: int = 1000) -> Dict:
        """
        Naabu domain scan - ONLY for web-focused domain reconnaissance
        
        Args:
            domain: Domain name (e.g., "example.com")
            ports: Specific ports (defaults to web ports)
            top_ports: Scan top N ports
            rate: Scan rate
        
        Returns:
            Dict with domain and open ports
        """
        logger.info(f"Naabu scan on domain: {domain}")
        
        # Validate it's a domain, not an IP
        if not self.naabu._is_valid_domain(domain):
            return {
                'success': False,
                'error': 'Naabu is for DOMAINS only. Use RustScan or Masscan for IP addresses.',
                'domain': domain
            }
        
        # Run naabu
        result = self.naabu.scan_domain(
            domain=domain,
            ports=ports,
            top_ports=top_ports,
            rate=rate
        )
        
        return result
    
    def naabu_then_nmap(self, domain: str, ports: str = None, 
                        nmap_args: str = "-sV", rate: int = 1000) -> Dict:
        """
        Pipeline: Naabu discovers web ports → Nmap scans them for details
        
        This is the BEST PRACTICE for domain-based web reconnaissance:
        1. Naabu quickly finds open web ports on domain
        2. Nmap does detailed service detection on discovered ports
        
        Args:
            domain: Domain name to scan
            ports: Ports to scan (defaults to web ports)
            nmap_args: Nmap arguments for detailed scanning
            rate: Naabu scan rate
        
        Returns:
            Dict with naabu discovery + nmap details
        """
        logger.info(f"Naabu→Nmap pipeline on {domain}")
        
        # Step 1: Naabu discovery
        naabu_result = self.naabu_scan(domain, ports, rate=rate)
        
        if not naabu_result['success']:
            return {
                'success': False,
                'tool': 'naabu',
                'error': naabu_result['error'],
                'domain': domain
            }
        
        open_ports = naabu_result.get('open_ports', [])
        
        if not open_ports:
            return {
                'success': True,
                'tool': 'naabu_nmap_pipeline',
                'naabu': naabu_result,
                'nmap': {'message': 'No ports discovered by Naabu'},
                'domain': domain
            }
        
        # Step 2: Nmap detailed scan on discovered ports
        ports_str = self.naabu.format_for_nmap(naabu_result)
        
        logger.info(f"Nmap scanning {domain} on ports {ports_str}")
        
        nmap_result = self.nmap.scan(
            target=domain,
            arguments=f"{nmap_args} -p {ports_str}"
        )
        
        return {
            'success': True,
            'tool': 'naabu_nmap_pipeline',
            'domain': domain,
            'naabu': {
                'total_ports_found': len(open_ports),
                'open_ports': open_ports,
                'rate': naabu_result['rate']
            },
            'nmap': {
                'scan_result': nmap_result
            },
            'pipeline_mode': 'naabu_discovery_then_nmap_details'
        }
    
    def naabu_subdomain_scan(self, domains: List[str], ports: str = None,
                            rate: int = 1000) -> Dict:
        """
        Scan multiple subdomains for open web ports
        Perfect for subdomain enumeration workflows
        
        Args:
            domains: List of domain/subdomain names
            ports: Ports to scan (defaults to web ports)
            rate: Scan rate
        
        Returns:
            Dict with results for all subdomains
        """
        logger.info(f"Naabu subdomain scan on {len(domains)} domains")
        
        result = self.naabu.scan_subdomains(
            domains=domains,
            ports=ports,
            rate=rate
        )
        
        return result
    
    def zmap_scan(self, port: int, target_range: str = "0.0.0.0/0",
                  bandwidth: str = "10M", max_targets: int = None) -> Dict:
        """
        ZMap single-port scan - ONLY for internet-wide single-port scanning
        
        Args:
            port: Single port to scan (e.g., 443, 22, 80)
            target_range: IP range (default: "0.0.0.0/0" = entire internet)
            bandwidth: Scan bandwidth (e.g., "10M", "100M", "1G")
            max_targets: Maximum IPs to scan (optional limit)
        
        Returns:
            Dict with port and discovered IPs
        """
        logger.info(f"ZMap scan on port {port}, range: {target_range}")
        
        # Validate single port
        if not isinstance(port, int) or port < 1 or port > 65535:
            return {
                'success': False,
                'error': 'ZMap requires a SINGLE port. For multi-port, use Masscan.',
                'port': port
            }
        
        # Run zmap
        result = self.zmap.scan_single_port(
            port=port,
            target_range=target_range,
            bandwidth=bandwidth,
            max_targets=max_targets
        )
        
        return result
    
    def zmap_then_nmap(self, port: int, target_range: str = "0.0.0.0/0",
                       bandwidth: str = "10M", max_targets: int = 1000,
                       nmap_args: str = "-sV") -> Dict:
        """
        Pipeline: ZMap discovers IPs with port open → Nmap scans them for details
        
        This is the BEST PRACTICE for internet-wide research:
        1. ZMap quickly finds all IPs with specific port open
        2. Nmap does detailed service detection on discovered IPs
        
        Args:
            port: Single port to scan
            target_range: IP range to scan
            bandwidth: ZMap bandwidth
            max_targets: Limit number of IPs (recommended for safety)
            nmap_args: Nmap arguments for detailed scanning
        
        Returns:
            Dict with zmap discovery + nmap details
        """
        logger.info(f"ZMap→Nmap pipeline on port {port}, range: {target_range}")
        
        # Step 1: ZMap discovery
        zmap_result = self.zmap_scan(port, target_range, bandwidth, max_targets)
        
        if not zmap_result['success']:
            return {
                'success': False,
                'tool': 'zmap',
                'error': zmap_result['error'],
                'port': port
            }
        
        discovered_ips = zmap_result.get('discovered_ips', [])
        
        if not discovered_ips:
            return {
                'success': True,
                'tool': 'zmap_nmap_pipeline',
                'zmap': zmap_result,
                'nmap': {'message': 'No IPs discovered by ZMap'},
                'port': port
            }
        
        # Step 2: Nmap detailed scan on discovered IPs (limit for safety)
        nmap_results = []
        scan_limit = min(len(discovered_ips), 100)  # Safety limit
        
        logger.info(f"Nmap scanning {scan_limit} discovered IPs on port {port}")
        
        for ip in discovered_ips[:scan_limit]:
            nmap_result = self.nmap.scan(
                target=ip,
                arguments=f"{nmap_args} -p {port}"
            )
            
            nmap_results.append({
                'ip': ip,
                'nmap_result': nmap_result
            })
        
        return {
            'success': True,
            'tool': 'zmap_nmap_pipeline',
            'port': port,
            'target_range': target_range,
            'zmap': {
                'total_ips_found': len(discovered_ips),
                'bandwidth': zmap_result['bandwidth'],
                'statistics': zmap_result.get('statistics', {})
            },
            'nmap': {
                'targets_scanned': len(nmap_results),
                'scan_limit': scan_limit,
                'results': nmap_results
            },
            'pipeline_mode': 'zmap_discovery_then_nmap_details',
            'note': f'Scanned {scan_limit} of {len(discovered_ips)} discovered IPs'
        }


# Singleton instance
scanner = MultiToolScanner(docker_mode=True)
