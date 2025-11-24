################################################################################
# Start OpenVAS Container
################################################################################

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "Starting OpenVAS Container" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# Check if docker-compose is available
if (!(Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Host "❌ docker-compose not found!" -ForegroundColor Red
    Write-Host "Please install docker-compose first" -ForegroundColor Yellow
    exit 1
}

# Start OpenVAS stack
Write-Host "Starting OpenVAS, PostgreSQL, and Redis..." -ForegroundColor Cyan
docker-compose -f docker-compose.openvas.yml up -d

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=================================" -ForegroundColor Green
    Write-Host "✓ OpenVAS Started Successfully!" -ForegroundColor Green
    Write-Host "=================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "OpenVAS is initializing..." -ForegroundColor Yellow
    Write-Host "This may take 5-10 minutes on first start" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Services:" -ForegroundColor Cyan
    Write-Host "  Web UI:  http://localhost:9390" -ForegroundColor White
    Write-Host "  API:     http://localhost:9392" -ForegroundColor White
    Write-Host ""
    Write-Host "Credentials:" -ForegroundColor Cyan
    Write-Host "  Username: admin" -ForegroundColor White
    Write-Host "  Password: admin" -ForegroundColor White
    Write-Host ""
    Write-Host "Check status:" -ForegroundColor Cyan
    Write-Host "  docker-compose -f docker-compose.openvas.yml ps" -ForegroundColor Gray
    Write-Host ""
    Write-Host "View logs:" -ForegroundColor Cyan
    Write-Host "  docker-compose -f docker-compose.openvas.yml logs -f openvas" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Stop OpenVAS:" -ForegroundColor Cyan
    Write-Host "  docker-compose -f docker-compose.openvas.yml down" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "❌ Failed to start OpenVAS" -ForegroundColor Red
    Write-Host "Check Docker is running and try again" -ForegroundColor Yellow
    exit 1
}
