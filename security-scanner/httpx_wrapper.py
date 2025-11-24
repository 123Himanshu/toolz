#!/usr/bin/env python3
"""
Httpx Wrapper - HTTP probe
"""
import subprocess
import json
from datetime import datetime

class HttpxWrapper:
    def __init__(self):
        self.tool = "httpx"
        
    def scan(self, target: str) -> dict:
        """
        Probe HTTP/HTTPS services
        """
        try:
            # Clean target
            target = target.replace('https://', '').replace('http://', '').split('/')[0]
            
            cmd = ['httpx', '-u', target, '-json', '-silent', '-status-code', '-title', '-tech-detect']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse JSON output
            hosts = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            hosts.append({
                                'url': data.get('url', ''),
                                'status_code': data.get('status_code', 0),
                                'title': data.get('title', ''),
                                'tech': data.get('tech', [])
                            })
                        except:
                            pass
            
            return {
                'success': True,
                'tool': 'httpx',
                'target': target,
                'hosts': hosts,
                'count': len(hosts),
                'command': ' '.join(cmd),
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'tool': 'httpx',
                'error': 'Scan timeout after 1 minute'
            }
        except Exception as e:
            return {
                'success': False,
                'tool': 'httpx',
                'error': str(e)
            }
