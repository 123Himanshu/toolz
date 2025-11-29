#!/usr/bin/env pwsh
# OpenVAS Status Check

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "OpenVAS Status Check" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check container
Write-Host "1. Checking OpenVAS container..." -ForegroundColor Yellow
$container = docker ps --filter "name=openvas-gvm" --format "{{.Names}}"

if ($container) {
    Write-Host "   ✅ Container running: $container" -ForegroundColor Green
    
    # Check health
    $health = docker inspect openvas-gvm --format "{{.State.Health.Status}}" 2>&1
    Write-Host "   Health: $health" -ForegroundColor $(if ($health -eq "healthy") { "Green" } else { "Yellow" })
} else {
    Write-Host "   ❌ Container not running" -ForegroundColor Red
    Write-Host "`n   Start with:" -ForegroundColor Yellow
    Write-Host "   cd security-scanner" -ForegroundColor White
    Write-Host "   docker-compose -f docker-compose.openvas-simple.yml up -d`n" -ForegroundColor White
    exit 1
}

# Check ports
Write-Host "`n2. Checking port mappings..." -ForegroundColor Yellow
$ports = docker port openvas-gvm
Write-Host "   $ports" -ForegroundColor White

# Check if gvmd is running
Write-Host "`n3. Checking gvmd process..." -ForegroundColor Yellow
$gvmd = docker exec openvas-gvm ps aux 2>&1 | Select-String -Pattern "gvmd.*9390"

if ($gvmd) {
    Write-Host "   ✅ gvmd is running" -ForegroundColor Green
    Write-Host "   $gvmd" -ForegroundColor White
} else {
    Write-Host "   ⚠️  gvmd not started yet (still initializing)" -ForegroundColor Yellow
    Write-Host "   This is normal on first run - wait 5-10 minutes" -ForegroundColor Yellow
}

# Check logs
Write-Host "`n4. Recent logs..." -ForegroundColor Yellow
docker logs openvas-gvm --tail 5 2>&1 | ForEach-Object {
    Write-Host "   $_" -ForegroundColor Gray
}

# Test connection
Write-Host "`n5. Testing GMP connection..." -ForegroundColor Yellow
$testResult = docker run --rm --network host security-scanner python3 -c "
from openvas_wrapper_simple import OpenVASScanner
scanner = OpenVASScanner(host='localhost', port=9390)
print(f'Available: {scanner.is_available()}')
" 2>&1

Write-Host "   $testResult" -ForegroundColor White

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($gvmd) {
    Write-Host "✅ OpenVAS is ready!" -ForegroundColor Green
    Write-Host "`nYou can now run scans:" -ForegroundColor Yellow
    Write-Host "  - Web UI: https://localhost:443" -ForegroundColor White
    Write-Host "  - GMP API: localhost:9390" -ForegroundColor White
    Write-Host "  - Python: OpenVASScanner(host='localhost', port=9390)`n" -ForegroundColor White
} else {
    Write-Host "⏳ OpenVAS is still initializing..." -ForegroundColor Yellow
    Write-Host "`nThis is normal on first run. Wait 5-10 minutes." -ForegroundColor White
    Write-Host "Check status again with: pwsh test-openvas-status.ps1`n" -ForegroundColor White
}
