#!/usr/bin/env python3
"""
Subfinder Wrapper - Subdomain enumeration
"""
import subprocess
import json
from datetime import datetime

class SubfinderWrapper:
    def __init__(self):
        self.tool = "subfinder"
        
    def scan(self, domain: str) -> dict:
        """
        Enumerate subdomains for a domain
        """
        try:
            # Clean domain
            domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
            
            cmd = ['subfinder', '-d', domain, '-json', '-silent']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse JSON output (one JSON per line)
            subdomains = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            subdomains.append(data.get('host', ''))
                        except:
                            pass
            
            return {
                'success': True,
                'tool': 'subfinder',
                'domain': domain,
                'subdomains': subdomains,
                'count': len(subdomains),
                'command': ' '.join(cmd),
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'tool': 'subfinder',
                'error': 'Scan timeout after 5 minutes'
            }
        except Exception as e:
            return {
                'success': False,
                'tool': 'subfinder',
                'error': str(e)
            }
