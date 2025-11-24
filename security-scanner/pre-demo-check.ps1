################################################################################
# Pre-Demo Checklist - Run this before any demo/presentation
# Ensures 100% reliability
################################################################################

$ErrorActionPreference = "Continue"

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "PRE-DEMO CHECKLIST" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

$checks = @()

# Check 1: Docker Running
Write-Host "1. Checking Docker..." -NoNewline
try {
    docker ps | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " ✓" -ForegroundColor Green
        $checks += $true
    } else {
        Write-Host " ✗" -ForegroundColor Red
        Write-Host "   Docker is not running!" -ForegroundColor Yellow
        $checks += $false
    }
} catch {
    Write-Host " ✗" -ForegroundColor Red
    $checks += $false
}

# Check 2: Docker Image Exists
Write-Host "2. Checking Docker Image..." -NoNewline
$image = docker images security-scanner:latest --format "{{.Repository}}"
if ($image -eq "security-scanner") {
    Write-Host " ✓" -ForegroundColor Green
    $checks += $true
} else {
    Write-Host " ✗" -ForegroundColor Red
    Write-Host "   Image not found! Run: docker build -t security-scanner:latest ." -ForegroundColor Yellow
    $checks += $false
}

# Check 3: Health Check
Write-Host "3. Running Health Check..." -ForegroundColor Cyan
docker run --rm security-scanner:latest python3 health-check.py
if ($LASTEXITCODE -eq 0) {
    $checks += $true
} else {
    Write-Host "   Health check failed!" -ForegroundColor Red
    $checks += $false
}

# Check 4: Test Suite
Write-Host "4. Running Test Suite (this takes 5-10 min)..." -ForegroundColor Cyan
docker run --rm security-scanner:latest python3 test-all-tools.py
if ($LASTEXITCODE -eq 0) {
    $checks += $true
} else {
    Write-Host "   Test suite failed!" -ForegroundColor Red
    $checks += $false
}

# Check 5: Next.js Dev Server
Write-Host "5. Checking Next.js Dev Server..." -NoNewline
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 5 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host " ✓" -ForegroundColor Green
        $checks += $true
    } else {
        Write-Host " ✗" -ForegroundColor Red
        $checks += $false
    }
} catch {
    Write-Host " ✗" -ForegroundColor Red
    Write-Host "   Dev server not running! Run: cd vulnerability-scanner && pnpm dev" -ForegroundColor Yellow
    $checks += $false
}

# Check 6: API Endpoint
Write-Host "6. Checking API Endpoint..." -NoNewline
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000/api/scan" -Method Get -TimeoutSec 5 -UseBasicParsing
    Write-Host " ✓" -ForegroundColor Green
    $checks += $true
} catch {
    Write-Host " ✗" -ForegroundColor Red
    $checks += $false
}

# Summary
Write-Host ""
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "CHECKLIST SUMMARY" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$total = $checks.Count
$passed = ($checks | Where-Object { $_ -eq $true }).Count
$failed = $total - $passed

Write-Host ""
Write-Host "Total Checks: $total" -ForegroundColor White
Write-Host "Passed: $passed ✓" -ForegroundColor Green
Write-Host "Failed: $failed ✗" -ForegroundColor Red
Write-Host "Success Rate: $([math]::Round($passed/$total*100))%" -ForegroundColor White

if ($failed -eq 0) {
    Write-Host ""
    Write-Host "🎉 ALL CHECKS PASSED!" -ForegroundColor Green
    Write-Host "✅ System is ready for demo/presentation" -ForegroundColor Green
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Cyan
    Write-Host "  1. Open browser: http://localhost:3000" -ForegroundColor Gray
    Write-Host "  2. Enter target: scanme.nmap.org" -ForegroundColor Gray
    Write-Host "  3. Select tools: Nmap, RustScan, Nuclei" -ForegroundColor Gray
    Write-Host "  4. Click 'Start Scan'" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "⚠️  $failed checks failed!" -ForegroundColor Yellow
    Write-Host "❌ Fix issues before demo" -ForegroundColor Red
    Write-Host ""
    Write-Host "Common Fixes:" -ForegroundColor Cyan
    Write-Host "  - Start Docker Desktop" -ForegroundColor Gray
    Write-Host "  - Rebuild image: docker build -t security-scanner:latest ." -ForegroundColor Gray
    Write-Host "  - Start dev server: cd vulnerability-scanner && pnpm dev" -ForegroundColor Gray
    Write-Host ""
    exit 1
}
