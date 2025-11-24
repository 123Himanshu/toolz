################################################################################
# Tool Monitor - Run during demo to ensure tools stay healthy
# Monitors Docker, services, and provides real-time status
################################################################################

param(
    [int]$IntervalSeconds = 30
)

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "TOOL MONITOR - Real-time Status" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
Write-Host ""

while ($true) {
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    # Check Docker
    $dockerStatus = docker ps 2>&1 | Out-Null
    $dockerIcon = if ($LASTEXITCODE -eq 0) { "✓" } else { "✗" }
    $dockerColor = if ($LASTEXITCODE -eq 0) { "Green" } else { "Red" }
    
    # Check Image
    $image = docker images security-scanner:latest --format "{{.Repository}}" 2>&1
    $imageIcon = if ($image -eq "security-scanner") { "✓" } else { "✗" }
    $imageColor = if ($image -eq "security-scanner") { "Green" } else { "Red" }
    
    # Check Dev Server
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
        $serverIcon = "✓"
        $serverColor = "Green"
    } catch {
        $serverIcon = "✗"
        $serverColor = "Red"
    }
    
    # Check API
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000/api/scan" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
        $apiIcon = "✓"
        $apiColor = "Green"
    } catch {
        $apiIcon = "✗"
        $apiColor = "Red"
    }
    
    # Display Status
    Clear-Host
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "TOOL MONITOR - $timestamp" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Docker:      $dockerIcon" -ForegroundColor $dockerColor
    Write-Host "Image:       $imageIcon" -ForegroundColor $imageColor
    Write-Host "Dev Server:  $serverIcon" -ForegroundColor $serverColor
    Write-Host "API:         $apiIcon" -ForegroundColor $apiColor
    Write-Host ""
    Write-Host "Next check in $IntervalSeconds seconds..." -ForegroundColor Gray
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
    
    Start-Sleep -Seconds $IntervalSeconds
}
