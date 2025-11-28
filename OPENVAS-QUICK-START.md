# 🛡️ OpenVAS Quick Start Guide

## Current Status
OpenVAS shows "not_configured" because it requires a separate Docker container.

## Quick Setup (5 minutes)

### Step 1: Start OpenVAS Container
```bash
cd security-scanner
docker-compose -f docker-compose.openvas-simple.yml up -d
```

### Step 2: Wait for Initialization
OpenVAS needs ~5 minutes to initialize on first run.

Check status:
```bash
docker logs -f openvas-gvm
```

Wait until you see: "GVM is ready"

### Step 3: Access Web UI
- URL: https://localhost:9390
- Username: admin
- Password: admin

### Step 4: Run Scan
Now when you run a scan with OpenVAS/Nessus, it will connect to the container.

---

## Alternative: Use Nessus Instead
Since Nessus runs OpenVAS in the backend, you can:
1. Select "Nessus Professional" in the UI
2. It will run OpenVAS and show results as Nessus

---

## Troubleshooting

### Container not starting
```bash
docker-compose -f docker-compose.openvas-simple.yml logs
```

### Port already in use
```bash
# Check what's using port 9390
netstat -an | findstr 9390

# Or change port in docker-compose file
```

### Memory issues
OpenVAS needs at least 4GB RAM. Check Docker settings.

---

## Full Setup (Production)

For production, use the full setup:
```bash
docker-compose -f docker-compose.openvas.yml up -d
```

This includes:
- PostgreSQL database
- Redis cache
- Full GVM stack
