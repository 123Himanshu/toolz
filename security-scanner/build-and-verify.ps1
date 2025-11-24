################################################################################
# Build and Verify Security Scanner Docker Image (PowerShell)
################################################################################

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Building Security Scanner Image" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Build the image
docker build -t security-scanner:latest .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Verifying Tool Installation" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

$tools = @(
    @{Name="Nmap"; Command="nmap --version"},
    @{Name="Masscan"; Command="masscan --version"},
    @{Name="ZMap"; Command="zmap --version"},
    @{Name="Nuclei"; Command="nuclei -version"},
    @{Name="Trivy"; Command="trivy --version"},
    @{Name="Nikto"; Command="nikto -Version"},
    @{Name="Naabu"; Command="naabu -version"},
    @{Name="Subfinder"; Command="subfinder -version"},
    @{Name="Httpx"; Command="httpx -version"},
    @{Name="Jaeles"; Command="jaeles version"}
)

$failed = 0

foreach ($tool in $tools) {
    Write-Host "Testing $($tool.Name)..." -NoNewline
    $result = docker run --rm security-scanner $tool.Command 2>&1 | Select-Object -First 1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host " ✓" -ForegroundColor Green
        Write-Host "  $result" -ForegroundColor Gray
    } else {
        Write-Host " ✗" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Testing Python Wrappers" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

$wrappers = @(
    @{Name="Nmap"; Import="from nmap_wrapper import NmapWrapper"},
    @{Name="Masscan"; Import="from masscan_wrapper import MasscanWrapper"},
    @{Name="Nuclei"; Import="from nuclei_scanner import NucleiScanner"},
    @{Name="Trivy"; Import="from trivy_wrapper import TrivyScanner"},
    @{Name="Nikto"; Import="from nikto_scanner import NiktoScanner"},
    @{Name="Wapiti"; Import="from wapiti_scanner import WapitiScanner"}
)

foreach ($wrapper in $wrappers) {
    Write-Host "Testing $($wrapper.Name) wrapper..." -NoNewline
    $cmd = "$($wrapper.Import); print('OK')"
    $result = docker run --rm security-scanner python -c $cmd 2>&1
    
    if ($result -match "OK") {
        Write-Host " ✓" -ForegroundColor Green
    } else {
        Write-Host " ✗" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan

if ($failed -eq 0) {
    Write-Host "✅ BUILD AND VERIFICATION COMPLETE" -ForegroundColor Green
} else {
    Write-Host "⚠️  BUILD COMPLETE WITH $failed WARNINGS" -ForegroundColor Yellow
}

Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

$imageSize = docker images security-scanner:latest --format "{{.Size}}"
Write-Host "Image: security-scanner:latest" -ForegroundColor White
Write-Host "Size: $imageSize" -ForegroundColor White
Write-Host ""
Write-Host "Ready to scan!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Test real scanning: python security-scanner/test-real-scan.py" -ForegroundColor Gray
Write-Host "  2. Start Next.js dev: cd vulnerability-scanner && npm run dev" -ForegroundColor Gray
Write-Host "  3. Open browser: http://localhost:3000" -ForegroundColor Gray
