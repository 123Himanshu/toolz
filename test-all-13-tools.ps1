# Test ALL 13 Security Tools
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "TESTING ALL 13 SECURITY TOOLS" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$results = @()
$target = "scanme.nmap.org"

# Test each tool
Write-Host "1. Nmap..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from nmap_wrapper import NmapWrapper; import json; s=NmapWrapper(docker_mode=False); r=s.quick_scan('$target'); print(json.dumps({'success': r['success'], 'data': len(r.get('data', {}).get('hosts', {}))}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Nmap"; success=$r.success; data=$r.data}
if ($r.success) { Write-Host "   ✅ Found $($r.data) hosts" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "2. RustScan..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from rustscan_wrapper import RustScanWrapper; import json; s=RustScanWrapper(docker_mode=False); r=s.scan('$target'); print(json.dumps({'success': r['success'], 'ports': r.get('port_count', 0)}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="RustScan"; success=$r.success; data=$r.ports}
if ($r.success) { Write-Host "   ✅ Found $($r.ports) ports" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "3. Masscan..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from masscan_wrapper import MasscanWrapper; import json; s=MasscanWrapper(); r=s.scan('192.168.1.0/28', '80'); print(json.dumps({'success': r['success'], 'ips': r.get('total_ips', 0)}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Masscan"; success=$r.success; data=$r.ips}
if ($r.success) { Write-Host "   ✅ Scanned $($r.ips) IPs" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "4. Naabu..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from naabu_wrapper import NaabuWrapper; import json; s=NaabuWrapper(); r=s.scan_domain('$target'); print(json.dumps({'success': r['success'], 'ports': len(r.get('ports', []))}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Naabu"; success=$r.success; data=$r.ports}
if ($r.success) { Write-Host "   ✅ Found $($r.ports) ports" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "5. Nuclei (30s scan)..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from nuclei_scanner import NucleiScanner; import json; s=NucleiScanner(use_docker=False); r=s.quick_scan('https://$target'); print(json.dumps({'success': r['success'], 'vulns': r.get('vulnerabilities_found', 0)}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Nuclei"; success=$r.success; data=$r.vulns}
if ($r.success) { Write-Host "   ✅ Found $($r.vulns) vulnerabilities" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "6. Wapiti..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from wapiti_scanner import WapitiScanner; import json; s=WapitiScanner(use_docker=False); r=s.scan('https://$target'); print(json.dumps({'success': r['success']}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Wapiti"; success=$r.success}
if ($r.success) { Write-Host "   ✅ Scan completed" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "7. Nikto..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from nikto_scanner import NiktoScanner; import json; s=NiktoScanner(use_docker=False); r=s.scan('https://$target'); print(json.dumps({'success': r['success']}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Nikto"; success=$r.success}
if ($r.success) { Write-Host "   ✅ Scan completed" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "8. Jaeles..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from jaeles_scanner import JaelesScanner; import json; s=JaelesScanner(use_docker=False); r=s.quick_scan('https://$target'); print(json.dumps({'success': r['success']}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Jaeles"; success=$r.success}
if ($r.success) { Write-Host "   ✅ Scan completed" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "9. Trivy..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from trivy_wrapper import TrivyScanner; import json; s=TrivyScanner(); r=s.scan_image('nginx:latest'); print(json.dumps({'success': r['success']}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Trivy"; success=$r.success}
if ($r.success) { Write-Host "   ✅ Scan completed" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "10. Subfinder..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from subfinder_wrapper import SubfinderWrapper; import json; s=SubfinderWrapper(); r=s.scan('hackerone.com'); print(json.dumps({'success': r['success'], 'count': r.get('count', 0)}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Subfinder"; success=$r.success; data=$r.count}
if ($r.success) { Write-Host "   ✅ Found $($r.count) subdomains" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "11. Httpx..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from httpx_wrapper import HttpxWrapper; import json; s=HttpxWrapper(); r=s.scan('$target'); print(json.dumps({'success': r['success'], 'count': r.get('count', 0)}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="Httpx"; success=$r.success; data=$r.count}
if ($r.success) { Write-Host "   ✅ Found $($r.count) hosts" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "12. ZMap..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from zmap_wrapper import ZmapWrapper; import json; s=ZmapWrapper(); r=s.scan('$target', '80'); print(json.dumps({'success': r['success']}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="ZMap"; success=$r.success}
if ($r.success) { Write-Host "   ✅ Scan completed" -ForegroundColor Green } else { Write-Host "   ❌ Failed" -ForegroundColor Red }

Write-Host "13. OpenVAS..." -ForegroundColor Yellow
$r = docker run --rm security-scanner python3 -c "from openvas_wrapper_simple import OpenVASScanner; import json; s=OpenVASScanner(); r=s.scan('$target'); print(json.dumps({'success': r.get('success', False)}))" 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
$results += @{tool="OpenVAS"; success=$r.success}
if ($r.success) { Write-Host "   ✅ Scan completed" -ForegroundColor Green } else { Write-Host "   ⚠️  Requires setup" -ForegroundColor Yellow }

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$passed = ($results | Where-Object { $_.success -eq $true }).Count
$total = $results.Count

Write-Host "Passed: $passed/$total" -ForegroundColor $(if ($passed -eq $total) { "Green" } elseif ($passed -ge 10) { "Yellow" } else { "Red" })
Write-Host ""

if ($passed -eq $total) {
    Write-Host "🏆 ALL TOOLS WORKING!" -ForegroundColor Green
} elseif ($passed -ge 10) {
    Write-Host "✅ Most tools working!" -ForegroundColor Green
} else {
    Write-Host "⚠️  Some tools need attention" -ForegroundColor Yellow
}
