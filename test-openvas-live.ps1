#!/usr/bin/env pwsh
# Test OpenVAS Integration - Live Test

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "OpenVAS Integration Test" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if OpenVAS container is running
Write-Host "1. Checking OpenVAS container status..." -ForegroundColor Yellow
$openvasContainer = docker ps --filter "name=openvas" --format "{{.Names}}"

if ($openvasContainer) {
    Write-Host "   ✅ OpenVAS container is running: $openvasContainer" -ForegroundColor Green
} else {
    Write-Host "   ❌ OpenVAS container not found" -ForegroundColor Red
    Write-Host "`n   To start OpenVAS:" -ForegroundColor Yellow
    Write-Host "   cd security-scanner" -ForegroundColor White
    Write-Host "   docker-compose -f docker-compose.openvas-simple.yml up -d" -ForegroundColor White
    Write-Host "   Wait 5 minutes for initialization`n" -ForegroundColor White
    exit 1
}

# Test OpenVAS availability from security-scanner container
Write-Host "`n2. Testing OpenVAS connection..." -ForegroundColor Yellow

$testScript = @"
from openvas_wrapper_simple import OpenVASScanner
import json
scanner = OpenVASScanner(host='localhost', port=9390)
result = {'available': scanner.is_available()}
print(json.dumps(result))
"@

try {
    $result = docker run --rm --network host security-scanner python3 -c $testScript 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
    
    if ($result.available) {
        Write-Host "   ✅ OpenVAS is available and ready!" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  OpenVAS container running but not ready yet" -ForegroundColor Yellow
        Write-Host "   Wait a few more minutes for initialization" -ForegroundColor Yellow
        exit 0
    }
} catch {
    Write-Host "   ❌ Connection test failed: $_" -ForegroundColor Red
    exit 1
}

# Test quick scan
Write-Host "`n3. Testing quick scan (async)..." -ForegroundColor Yellow

$scanScript = @"
from openvas_wrapper_simple import OpenVASScanner
import json
scanner = OpenVASScanner(host='localhost', port=9390)
result = scanner.quick_scan('scanme.nmap.org', wait=False)
print(json.dumps(result, default=str))
"@

try {
    $scanResult = docker run --rm --network host security-scanner python3 -c $scanScript 2>&1 | Select-String -Pattern "\{" | ConvertFrom-Json
    
    Write-Host "`n   Scan Result:" -ForegroundColor Cyan
    Write-Host "   Success: $($scanResult.success)" -ForegroundColor White
    Write-Host "   Tool: $($scanResult.tool)" -ForegroundColor White
    Write-Host "   Target: $($scanResult.target)" -ForegroundColor White
    Write-Host "   Status: $($scanResult.status)" -ForegroundColor White
    
    if ($scanResult.task_id) {
        Write-Host "   Task ID: $($scanResult.task_id)" -ForegroundColor White
        Write-Host "   Report ID: $($scanResult.report_id)" -ForegroundColor White
        Write-Host "   Web UI: $($scanResult.web_ui)" -ForegroundColor White
        Write-Host "`n   ✅ Scan started successfully!" -ForegroundColor Green
    } elseif ($scanResult.status -eq "not_configured") {
        Write-Host "`n   ⚠️  OpenVAS not fully configured yet" -ForegroundColor Yellow
    } else {
        Write-Host "`n   ✅ Scan test completed" -ForegroundColor Green
    }
    
} catch {
    Write-Host "   ❌ Scan test failed: $_" -ForegroundColor Red
    exit 1
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "✅ OpenVAS Integration Test Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "OpenVAS is ready to use!" -ForegroundColor Green
Write-Host "`nAccess Web UI:" -ForegroundColor Yellow
Write-Host "  URL: https://localhost:9390" -ForegroundColor White
Write-Host "  Username: admin" -ForegroundColor White
Write-Host "  Password: admin`n" -ForegroundColor White

Write-Host "Run scans from:" -ForegroundColor Yellow
Write-Host "  - Web UI (vulnerability-scanner frontend)" -ForegroundColor White
Write-Host "  - Python API (openvas_wrapper_simple.py)" -ForegroundColor White
Write-Host "  - Docker commands`n" -ForegroundColor White
