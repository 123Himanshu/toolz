# ============================================================================
# PHASE 2 SETUP SCRIPT
# Sets up all infrastructure for the vulnerability scanner
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  VULNERABILITY SCANNER - PHASE 2 SETUP" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check Docker
Write-Host "[1/6] Checking Docker..." -ForegroundColor Yellow
try {
    $dockerVersion = docker --version
    Write-Host "  ✓ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Docker not found. Please install Docker Desktop." -ForegroundColor Red
    exit 1
}

# Start Redis and Elasticsearch
Write-Host ""
Write-Host "[2/6] Starting Redis and Elasticsearch..." -ForegroundColor Yellow
Set-Location security-scanner

try {
    docker-compose -f docker-compose.dev.yml up -d
    Write-Host "  ✓ Redis and Elasticsearch started" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ Failed to start containers. Continuing..." -ForegroundColor Yellow
}

# Wait for services
Write-Host ""
Write-Host "[3/6] Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check Redis
try {
    $redisCheck = docker exec vuln-scanner-redis redis-cli ping
    if ($redisCheck -eq "PONG") {
        Write-Host "  ✓ Redis is ready" -ForegroundColor Green
    }
} catch {
    Write-Host "  ⚠ Redis not responding yet" -ForegroundColor Yellow
}

# Check Elasticsearch
try {
    $esCheck = Invoke-RestMethod -Uri "http://localhost:9200" -Method Get -ErrorAction SilentlyContinue
    Write-Host "  ✓ Elasticsearch is ready" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ Elasticsearch not responding yet (may take a minute)" -ForegroundColor Yellow
}

# Install npm dependencies
Write-Host ""
Write-Host "[4/6] Installing npm dependencies..." -ForegroundColor Yellow
Set-Location ../vulnerability-scanner

try {
    pnpm install
    Write-Host "  ✓ Dependencies installed" -ForegroundColor Green
} catch {
    try {
        npm install
        Write-Host "  ✓ Dependencies installed (npm)" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Failed to install dependencies" -ForegroundColor Red
    }
}

# Check environment file
Write-Host ""
Write-Host "[5/6] Checking environment configuration..." -ForegroundColor Yellow

if (Test-Path ".env.local") {
    Write-Host "  ✓ .env.local found" -ForegroundColor Green
    
    $envContent = Get-Content ".env.local" -Raw
    
    if ($envContent -match "DATABASE_URL=") {
        Write-Host "  ✓ PostgreSQL configured" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ PostgreSQL not configured" -ForegroundColor Yellow
    }
    
    if ($envContent -match "MONGODB_URI=") {
        Write-Host "  ✓ MongoDB configured" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ MongoDB not configured" -ForegroundColor Yellow
    }
    
    if ($envContent -match "GROQ_API_KEY=") {
        Write-Host "  ✓ Groq AI configured" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Groq AI not configured" -ForegroundColor Yellow
    }
    
    if ($envContent -match "QDRANT_URL=") {
        Write-Host "  ✓ Qdrant configured" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Qdrant not configured" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ✗ .env.local not found!" -ForegroundColor Red
}

# Summary
Write-Host ""
Write-Host "[6/6] Setup Summary" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Infrastructure Status:" -ForegroundColor White
Write-Host "  • Redis:         http://localhost:6379" -ForegroundColor Gray
Write-Host "  • Elasticsearch: http://localhost:9200" -ForegroundColor Gray
Write-Host "  • PostgreSQL:    Cloud (Neon)" -ForegroundColor Gray
Write-Host "  • MongoDB:       Cloud (Atlas)" -ForegroundColor Gray
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor White
Write-Host "  1. Start the development server:" -ForegroundColor Gray
Write-Host "     pnpm dev" -ForegroundColor Cyan
Write-Host ""
Write-Host "  2. Initialize databases (in browser or curl):" -ForegroundColor Gray
Write-Host "     POST http://localhost:3000/api/db/init" -ForegroundColor Cyan
Write-Host ""
Write-Host "  3. Create an account:" -ForegroundColor Gray
Write-Host "     http://localhost:3000/login" -ForegroundColor Cyan
Write-Host ""
Write-Host "  4. (Optional) Start OpenVAS:" -ForegroundColor Gray
Write-Host "     cd security-scanner" -ForegroundColor Cyan
Write-Host "     docker-compose -f docker-compose.openvas-simple.yml up -d" -ForegroundColor Cyan
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Setup complete! Run 'pnpm dev' to start." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Set-Location ..
