"""
Test script to demonstrate the Attack Path Intelligence Engine
Creates sample data and runs a complete analysis
"""
import json
from pathlib import Path
from datetime import datetime

def create_sample_nmap_scan():
    """Create sample Nmap XML output"""
    
    nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1234567890">
    <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <hostnames>
            <hostname name="webserver.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="7.4"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.6"/>
            </port>
            <port protocol="tcp" portid="3306">
                <state state="open"/>
                <service name="mysql" product="MySQL" version="5.7.30"/>
            </port>
        </ports>
        <os>
            <osmatch name="Linux 3.X"/>
        </os>
    </host>
    <host>
        <address addr="192.168.1.20" addrtype="ipv4"/>
        <hostnames>
            <hostname name="database.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="7.4"/>
            </port>
            <port protocol="tcp" portid="5432">
                <state state="open"/>
                <service name="postgresql" product="PostgreSQL" version="9.6"/>
            </port>
        </ports>
        <os>
            <osmatch name="Linux 3.X"/>
        </os>
    </host>
    <host>
        <address addr="192.168.1.30" addrtype="ipv4"/>
        <hostnames>
            <hostname name="fileserver.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="445">
                <state state="open"/>
                <service name="smb" product="Samba" version="4.4.4"/>
            </port>
            <port protocol="tcp" portid="139">
                <state state="open"/>
                <service name="netbios-ssn"/>
            </port>
        </ports>
        <os>
            <osmatch name="Linux 3.X"/>
        </os>
    </host>
</nmaprun>
"""
    
    Path('test_data').mkdir(exist_ok=True)
    with open('test_data/sample_nmap.xml', 'w') as f:
        f.write(nmap_xml)
    
    print("✓ Created sample Nmap scan: test_data/sample_nmap.xml")

def create_sample_nuclei_scan():
    """Create sample Nuclei JSON output"""
    
    nuclei_findings = [
        {
            "template-id": "CVE-2021-41773",
            "info": {
                "name": "Apache HTTP Server 2.4.49 - Path Traversal",
                "severity": "critical",
                "classification": {
                    "cve-id": ["CVE-2021-41773"],
                    "cvss-score": 9.8,
                    "cwe-id": ["CWE-22"]
                }
            },
            "host": "http://192.168.1.10",
            "matched-at": "http://192.168.1.10/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"
        },
        {
            "template-id": "sql-injection",
            "info": {
                "name": "SQL Injection Detected",
                "severity": "high",
                "classification": {
                    "cvss-score": 8.5,
                    "cwe-id": ["CWE-89"]
                }
            },
            "host": "http://192.168.1.10",
            "matched-at": "http://192.168.1.10/login.php?id=1"
        },
        {
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "medium",
                "classification": {
                    "cvss-score": 5.3
                }
            },
            "host": "http://192.168.1.10",
            "matched-at": "http://192.168.1.10/admin/"
        }
    ]
    
    Path('test_data').mkdir(exist_ok=True)
    with open('test_data/sample_nuclei.json', 'w') as f:
        for finding in nuclei_findings:
            f.write(json.dumps(finding) + '\n')
    
    print("✓ Created sample Nuclei scan: test_data/sample_nuclei.json")

def create_sample_trivy_scan():
    """Create sample Trivy JSON output"""
    
    trivy_output = {
        "ArtifactName": "webserver.local",
        "Results": [
            {
                "Target": "webserver.local (ubuntu 18.04)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-3156",
                        "PkgName": "sudo",
                        "InstalledVersion": "1.8.21p2-3ubuntu1",
                        "FixedVersion": "1.8.21p2-3ubuntu1.4",
                        "Severity": "HIGH",
                        "CVSS": {
                            "nvd": {
                                "V3Score": 7.8
                            }
                        },
                        "CweIDs": ["CWE-787"],
                        "References": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"
                        ]
                    },
                    {
                        "VulnerabilityID": "CVE-2019-18634",
                        "PkgName": "sudo",
                        "InstalledVersion": "1.8.21p2-3ubuntu1",
                        "FixedVersion": "1.8.21p2-3ubuntu1.2",
                        "Severity": "CRITICAL",
                        "CVSS": {
                            "nvd": {
                                "V3Score": 9.8
                            }
                        },
                        "CweIDs": ["CWE-120"]
                    }
                ]
            }
        ]
    }
    
    Path('test_data').mkdir(exist_ok=True)
    with open('test_data/sample_trivy.json', 'w') as f:
        json.dump(trivy_output, f, indent=2)
    
    print("✓ Created sample Trivy scan: test_data/sample_trivy.json")

def run_test_analysis():
    """Run the engine with sample data"""
    
    print("\n" + "="*80)
    print("ATTACK PATH INTELLIGENCE ENGINE - TEST RUN")
    print("="*80 + "\n")
    
    # Create sample data
    print("Creating sample scan data...")
    create_sample_nmap_scan()
    create_sample_nuclei_scan()
    create_sample_trivy_scan()
    
    print("\nSample data created successfully!")
    print("\nTo run the analysis, execute:")
    print("\npython main.py \\")
    print("    --nmap test_data/sample_nmap.xml \\")
    print("    --nuclei test_data/sample_nuclei.json \\")
    print("    --trivy test_data/sample_trivy.json \\")
    print("    --output all")
    
    print("\n" + "="*80)
    print("NOTE: This is a demonstration with sample data.")
    print("For real analysis, use actual scanner output files.")
    print("="*80 + "\n")

if __name__ == '__main__':
    run_test_analysis()
