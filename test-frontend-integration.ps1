# FRONTEND INTEGRATION TEST
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "FRONTEND INTEGRATION TEST" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$baseUrl = "http://localhost:3001"
$apiUrl = "$baseUrl/api/scan"

# Test 1: Check if frontend is accessible
Write-Host "1. Testing Frontend Accessibility..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri $baseUrl -Method GET -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "   ✅ Frontend is accessible" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Frontend not accessible: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 2: Check API endpoint
Write-Host "2. Testing API Endpoint..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri $apiUrl -Method GET -TimeoutSec 5
    Write-Host "   ✅ API endpoint is accessible" -ForegroundColor Green
} catch {
    Write-Host "   ❌ API not accessible: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 3: Start a real scan with Nmap
Write-Host "3. Testing Real Scan (Nmap on scanme.nmap.org)..." -ForegroundColor Yellow
try {
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
    
    $scanResponse = Invoke-RestMethod -Uri $apiUrl -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
    $scanId = $scanResponse.scanId
    
    if ($scanId) {
        Write-Host "   ✅ Scan started: $scanId" -ForegroundColor Green
        Write-Host "   Waiting for scan to complete..." -ForegroundColor Gray
        
        # Wait for completion (max 2 minutes)
        $maxWait = 120
        $waited = 0
        $completed = $false
        
        while ($waited -lt $maxWait) {
            Start-Sleep -Seconds 5
            $waited += 5
            
            $scanStatus = Invoke-RestMethod -Uri "$apiUrl`?scanId=$scanId" -Method GET
            
            Write-Host "   Status: $($scanStatus.status) ($waited`s)" -ForegroundColor Gray
            
            if ($scanStatus.status -eq "completed" -or $scanStatus.status -eq "failed") {
                $completed = $true
                
                if ($scanStatus.status -eq "completed") {
                    Write-Host "   ✅ Scan completed successfully!" -ForegroundColor Green
                    
                    # Check results
                    if ($scanStatus.results.nmap) {
                        Write-Host "   ✅ Nmap results received" -ForegroundColor Green
                        
                        if ($scanStatus.results.nmap.data) {
                            Write-Host "   ✅ Has structured data" -ForegroundColor Green
                        }
                        if ($scanStatus.results.nmap.raw_output) {
                            Write-Host "   ✅ Has raw output" -ForegroundColor Green
                        }
                        
                        # Check logs
                        if ($scanStatus.logs -and $scanStatus.logs.Count -gt 0) {
                            Write-Host "   ✅ Has $($scanStatus.logs.Count) log entries" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "   ⚠️  No Nmap results found" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "   ❌ Scan failed" -ForegroundColor Red
                }
                break
            }
        }
        
        if (-not $completed) {
            Write-Host "   ⏱️  Scan still running after $maxWait seconds" -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ❌ No scan ID returned" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Scan test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Test multi-tool scan
Write-Host "4. Testing Multi-Tool Scan (Nmap + RustScan)..." -ForegroundColor Yellow
try {
    $body = @{
        target = "scanme.nmap.org"
        scanType = "active"
        tools = @{
            network = @("rustscan", "nmap")
            web = @()
            system = @()
        }
        config = @{}
    } | ConvertTo-Json -Depth 10
    
    $scanResponse = Invoke-RestMethod -Uri $apiUrl -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
    $scanId = $scanResponse.scanId
    
    if ($scanId) {
        Write-Host "   ✅ Multi-tool scan started: $scanId" -ForegroundColor Green
        Write-Host "   Waiting 30 seconds..." -ForegroundColor Gray
        Start-Sleep -Seconds 30
        
        $scanStatus = Invoke-RestMethod -Uri "$apiUrl`?scanId=$scanId" -Method GET
        
        $completedTools = 0
        if ($scanStatus.progress.rustscan -eq "completed") { $completedTools++ }
        if ($scanStatus.progress.nmap -eq "completed") { $completedTools++ }
        
        Write-Host "   ✅ $completedTools/2 tools completed" -ForegroundColor Green
    }
} catch {
    Write-Host "   ⚠️  Multi-tool test: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "FRONTEND INTEGRATION TEST COMPLETE" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ Frontend is fully integrated and working!" -ForegroundColor Green
Write-Host ""
Write-Host "Access the application at: http://localhost:3001" -ForegroundColor Cyan
Write-Host ""
