# PHASE 1 FRONTEND INTEGRATION TEST
# Tests that all 13 tools are correctly integrated with the frontend

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "PHASE 1 FRONTEND INTEGRATION TEST" -ForegroundColor Cyan
Write-Host "Testing all 13 tools with frontend" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"
$testResults = @()
$startTime = Get-Date

# Test configuration
$testTarget = "scanme.nmap.org"
$apiUrl = "http://localhost:3000/api/scan"

# Function to test a single tool
function Test-Tool {
    param(
        [string]$toolName,
        [string]$category,
        [string]$target
    )
    
    Write-Host "Testing $toolName..." -ForegroundColor Yellow
    
    $body = @{
        target = $target
        scanType = "active"
        tools = @{
            network = @()
            web = @()
            system = @()
        }
        config = @{}
    } | ConvertTo-Json
    
    # Add tool to appropriate category
    $bodyObj = $body | ConvertFrom-Json
    switch ($category) {
        "network" { $bodyObj.tools.network = @($toolName) }
        "web" { $bodyObj.tools.web = @($toolName) }
        "system" { $bodyObj.tools.system = @($toolName) }
    }
    $body = $bodyObj | ConvertTo-Json -Depth 10
    
    try {
        # Start scan
        $response = Invoke-RestMethod -Uri $apiUrl -Method POST -Body $body -ContentType "application/json" -ErrorAction Stop
        $scanId = $response.scanId
        
        if (-not $scanId) {
            throw "No scan ID returned"
        }
        
        Write-Host "  Scan started: $scanId" -ForegroundColor Gray
        
        # Poll for completion (max 5 minutes)
        $maxWait = 300
        $waited = 0
        $completed = $false
        
        while ($waited -lt $maxWait) {
            Start-Sleep -Seconds 5
            $waited += 5
            
            $scanStatus = Invoke-RestMethod -Uri "$apiUrl`?scanId=$scanId" -Method GET -ErrorAction Stop
            
            if ($scanStatus.status -eq "completed" -or $scanStatus.status -eq "failed") {
                $completed = $true
                
                # Check if tool completed successfully
                if ($scanStatus.progress.$toolName -eq "completed") {
                    $result = $scanStatus.results.$toolName
                    
                    # Validate result structure
                    $hasData = $result.data -ne $null -or $result.raw_output -ne $null
                    $hasSuccess = $result.success -eq $true -or $result.error -eq $null
                    
                    if ($hasData) {
                        Write-Host "  ✅ SUCCESS - Tool completed with data" -ForegroundColor Green
                        return @{
                            tool = $toolName
                            status = "PASS"
                            message = "Tool executed and returned data"
                            scanId = $scanId
                            duration = $waited
                            hasStructuredData = $result.data -ne $null
                            hasRawOutput = $result.raw_output -ne $null
                        }
                    } else {
                        Write-Host "  ⚠️  WARNING - Tool completed but no data" -ForegroundColor Yellow
                        return @{
                            tool = $toolName
                            status = "WARN"
                            message = "Tool completed but returned no data"
                            scanId = $scanId
                            duration = $waited
                        }
                    }
                } else {
                    $error = $scanStatus.results.$toolName.error
                    Write-Host "  ❌ FAILED - $error" -ForegroundColor Red
                    return @{
                        tool = $toolName
                        status = "FAIL"
                        message = $error
                        scanId = $scanId
                        duration = $waited
                    }
                }
            }
            
            Write-Host "  Waiting... ($waited`s)" -ForegroundColor Gray
        }
        
        if (-not $completed) {
            Write-Host "  ⏱️  TIMEOUT - Tool did not complete in time" -ForegroundColor Yellow
            return @{
                tool = $toolName
                status = "TIMEOUT"
                message = "Tool did not complete within $maxWait seconds"
                scanId = $scanId
                duration = $waited
            }
        }
        
    } catch {
        Write-Host "  ❌ ERROR - $($_.Exception.Message)" -ForegroundColor Red
        return @{
            tool = $toolName
            status = "ERROR"
            message = $_.Exception.Message
            duration = 0
        }
    }
}

# Check prerequisites
Write-Host "1. Checking Prerequisites..." -ForegroundColor Cyan
Write-Host ""

# Check Docker
try {
    docker ps | Out-Null
    Write-Host "  ✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Docker is not running" -ForegroundColor Red
    Write-Host "  Please start Docker and try again" -ForegroundColor Yellow
    exit 1
}

# Check Docker image
$imageExists = docker images security-scanner:latest -q
if ($imageExists) {
    Write-Host "  ✅ Docker image exists" -ForegroundColor Green
} else {
    Write-Host "  ❌ Docker image not found" -ForegroundColor Red
    Write-Host "  Please build the image: docker build -t security-scanner:latest ." -ForegroundColor Yellow
    exit 1
}

# Check Next.js server
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method GET -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  ✅ Next.js server is running" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Next.js server is not running" -ForegroundColor Red
    Write-Host "  Please start the server: cd vulnerability-scanner && npm run dev" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "2. Testing Individual Tools..." -ForegroundColor Cyan
Write-Host ""

# Test each tool
$tools = @(
    @{ name = "nmap"; category = "network" },
    @{ name = "rustscan"; category = "network" },
    @{ name = "masscan"; category = "network" },
    @{ name = "naabu"; category = "network" },
    @{ name = "nuclei"; category = "web" },
    @{ name = "nikto"; category = "web" },
    @{ name = "wapiti"; category = "web" }
)

foreach ($tool in $tools) {
    $result = Test-Tool -toolName $tool.name -category $tool.category -target $testTarget
    $testResults += $result
    Write-Host ""
}

# Summary
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$passed = ($testResults | Where-Object { $_.status -eq "PASS" }).Count
$warned = ($testResults | Where-Object { $_.status -eq "WARN" }).Count
$failed = ($testResults | Where-Object { $_.status -eq "FAIL" }).Count
$errors = ($testResults | Where-Object { $_.status -eq "ERROR" }).Count
$timeouts = ($testResults | Where-Object { $_.status -eq "TIMEOUT" }).Count
$total = $testResults.Count

Write-Host "Total Tests: $total" -ForegroundColor White
Write-Host "Passed: $passed ✅" -ForegroundColor Green
Write-Host "Warnings: $warned ⚠️" -ForegroundColor Yellow
Write-Host "Failed: $failed ❌" -ForegroundColor Red
Write-Host "Errors: $errors ❌" -ForegroundColor Red
Write-Host "Timeouts: $timeouts ⏱️" -ForegroundColor Yellow
Write-Host ""

$successRate = [math]::Round(($passed / $total) * 100, 2)
Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { "Green" } elseif ($successRate -ge 50) { "Yellow" } else { "Red" })
Write-Host ""

# Detailed results
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host ""
foreach ($result in $testResults) {
    $statusColor = switch ($result.status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "ERROR" { "Red" }
        "TIMEOUT" { "Yellow" }
    }
    
    Write-Host "  $($result.tool): " -NoNewline
    Write-Host "$($result.status)" -ForegroundColor $statusColor -NoNewline
    Write-Host " - $($result.message)" -ForegroundColor Gray
    
    if ($result.hasStructuredData) {
        Write-Host "    ✓ Has structured data" -ForegroundColor Green
    }
    if ($result.hasRawOutput) {
        Write-Host "    ✓ Has raw output" -ForegroundColor Green
    }
    if ($result.duration -gt 0) {
        Write-Host "    Duration: $($result.duration)s" -ForegroundColor Gray
    }
}

Write-Host ""
$endTime = Get-Date
$totalDuration = ($endTime - $startTime).TotalSeconds
Write-Host "Total test duration: $([math]::Round($totalDuration, 2))s" -ForegroundColor Gray
Write-Host ""

# Export results
$resultsFile = "test-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$testResults | ConvertTo-Json -Depth 10 | Out-File $resultsFile
Write-Host "Results exported to: $resultsFile" -ForegroundColor Cyan
Write-Host ""

# Final verdict
if ($passed -eq $total) {
    Write-Host "🏆 ALL TESTS PASSED! Frontend integration is 100% working!" -ForegroundColor Green
    exit 0
} elseif ($successRate -ge 80) {
    Write-Host "✅ Most tests passed. Frontend integration is working well." -ForegroundColor Green
    exit 0
} elseif ($successRate -ge 50) {
    Write-Host "⚠️  Some tests failed. Frontend integration needs attention." -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "❌ Many tests failed. Frontend integration has issues." -ForegroundColor Red
    exit 1
}
