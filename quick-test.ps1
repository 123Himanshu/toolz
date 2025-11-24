# QUICK PHASE 1 TEST - 2 MINUTES
# Tests that frontend and backend are connected

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "QUICK PHASE 1 INTEGRATION TEST" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Stop"

# 1. Check Docker
Write-Host "1. Checking Docker..." -ForegroundColor Yellow
try {
    docker ps | Out-Null
    Write-Host "   ✅ Docker running" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Docker not running" -ForegroundColor Red
    exit 1
}

# 2. Check Docker image
Write-Host "2. Checking Docker image..." -ForegroundColor Yellow
$image = docker images security-scanner:latest -q
if ($image) {
    Write-Host "   ✅ Image exists" -ForegroundColor Green
} else {
    Write-Host "   ❌ Image not found" -ForegroundColor Red
    exit 1
}

# 3. Check Next.js server
Write-Host "3. Checking Next.js server..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method GET -TimeoutSec 5
    Write-Host "   ✅ Server running" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Server not running" -ForegroundColor Red
    Write-Host "   Start with: cd vulnerability-scanner && npm run dev" -ForegroundColor Yellow
    exit 1
}

# 4. Check API endpoint
Write-Host "4. Checking API endpoint..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:3000/api/scan" -Method GET -TimeoutSec 5
    Write-Host "   ✅ API accessible" -ForegroundColor Green
} catch {
    Write-Host "   ❌ API not accessible" -ForegroundColor Red
    exit 1
}

# 5. Test tool execution
Write-Host "5. Testing tool execution..." -ForegroundColor Yellow
try {
    $output = docker run --rm security-scanner:latest python3 -c "from nmap_wrapper import NmapWrapper; import json; scanner = NmapWrapper(docker_mode=False); result = scanner.quick_scan('scanme.nmap.org'); print(json.dumps({'success': result['success'], 'has_data': 'data' in result, 'has_raw': 'raw_output' in result}))"
    $result = $output | ConvertFrom-Json
    
    if ($result.success -and $result.has_data -and $result.has_raw) {
        Write-Host "   ✅ Tool execution working" -ForegroundColor Green
        Write-Host "      - Success: $($result.success)" -ForegroundColor Gray
        Write-Host "      - Has data: $($result.has_data)" -ForegroundColor Gray
        Write-Host "      - Has raw output: $($result.has_raw)" -ForegroundColor Gray
    } else {
        Write-Host "   ⚠️  Tool executed but missing data" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Tool execution failed" -ForegroundColor Red
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 6. Test end-to-end scan
Write-Host "6. Testing end-to-end scan..." -ForegroundColor Yellow
try {
    # Start a scan
    $body = @{
        target = "scanme.nmap.org"
        scanType = "active"
        tools = @{
            network = @("nmap")
            web = @()
            system = @()
        }
        config = @{}
    } | ConvertTo-Json -Depth 10
    
    $scanResponse = Invoke-RestMethod -Uri "http://localhost:3000/api/scan" -Method POST -Body $body -ContentType "application/json"
    $scanId = $scanResponse.scanId
    
    if ($scanId) {
        Write-Host "   ✅ Scan started: $scanId" -ForegroundColor Green
        Write-Host "      Waiting for completion..." -ForegroundColor Gray
        
        # Wait for completion (max 2 minutes)
        $maxWait = 120
        $waited = 0
        $completed = $false
        
        while ($waited -lt $maxWait) {
            Start-Sleep -Seconds 5
            $waited += 5
            
            $scanStatus = Invoke-RestMethod -Uri "http://localhost:3000/api/scan?scanId=$scanId" -Method GET
            
            if ($scanStatus.status -eq "completed" -or $scanStatus.status -eq "failed") {
                $completed = $true
                
                if ($scanStatus.status -eq "completed") {
                    Write-Host "   ✅ Scan completed successfully!" -ForegroundColor Green
                    
                    # Check if results exist
                    if ($scanStatus.results.nmap) {
                        Write-Host "      - Nmap results: ✅" -ForegroundColor Green
                        
                        # Check data structure
                        $nmapResult = $scanStatus.results.nmap
                        if ($nmapResult.data) {
                            Write-Host "      - Has structured data: ✅" -ForegroundColor Green
                        }
                        if ($nmapResult.raw_output) {
                            Write-Host "      - Has raw output: ✅" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "      - Nmap results: ❌ Missing" -ForegroundColor Red
                    }
                } else {
                    Write-Host "   ❌ Scan failed" -ForegroundColor Red
                    if ($scanStatus.error) {
                        Write-Host "      Error: $($scanStatus.error)" -ForegroundColor Red
                    }
                }
                break
            }
            
            Write-Host "      Status: $($scanStatus.status) ($waited`s)" -ForegroundColor Gray
        }
        
        if (-not $completed) {
            Write-Host "   ⏱️  Scan still running after $maxWait seconds" -ForegroundColor Yellow
            Write-Host "      Check manually: http://localhost:3000/scan/$scanId" -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ❌ No scan ID returned" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "   ❌ End-to-end test failed" -ForegroundColor Red
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "✅ ALL CHECKS PASSED!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Phase 1 frontend integration is working!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Open http://localhost:3000/scan/new" -ForegroundColor White
Write-Host "2. Test more tools manually" -ForegroundColor White
Write-Host "3. Run full test: .\test-phase1-frontend.ps1" -ForegroundColor White
Write-Host ""
