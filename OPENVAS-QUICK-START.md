# 🛡️ OpenVAS Quick Start Guide

## ✅ OpenVAS is Now Fully Integrated!

OpenVAS now runs in a separate container and communicates via GMP (Greenbone Management Protocol). The integration is complete and ready to use.

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

Look for: `"OpenVAS is ready"` or `"GSA is now running"`

### Step 3: Test Integration

```bash
# From project root
pwsh test-openvas-live.ps1

# Or manually
docker run --rm --network host security-scanner python3 test-openvas-integration.py
```

### Step 4: Access Web UI (Optional)

- URL: https://localhost:9390
- Username: `admin`
- Password: `admin`

### Step 5: Run Scans

**From Web UI:**
1. Open vulnerability-scanner frontend
2. Select "OpenVAS" as scanner
3. Enter target and click "Start Scan"
4. View results in real-time

**From Python:**
```python
from openvas_wrapper_simple import OpenVASScanner

scanner = OpenVASScanner(host="localhost", port=9390)

# Quick scan (async)
result = scanner.quick_scan("192.168.1.1", wait=False)
print(f"Task ID: {result['task_id']}")

# Check status
status = scanner.get_scan_status(result['task_id'])
print(f"Progress: {status['progress']}%")

# Get report when done
report = scanner.get_report(result['task_id'])
print(f"Vulnerabilities: {report['vulnerabilities_found']}")
```

**From Docker:**
```bash
docker run --rm --network host security-scanner python3 -c "
from openvas_wrapper_simple import OpenVASScanner
import json
scanner = OpenVASScanner(host='localhost', port=9390)
result = scanner.quick_scan('scanme.nmap.org', wait=False)
print(json.dumps(result, indent=2, default=str))
"
```

---

## Features

✅ **Full GMP Integration** - Uses Greenbone Management Protocol  
✅ **Async Scans** - Start scans and check status later  
✅ **50,000+ Tests** - Comprehensive vulnerability detection  
✅ **CVE Detection** - Latest CVE database  
✅ **Web UI Access** - View scans in OpenVAS web interface  
✅ **Report Export** - JSON, XML, PDF, HTML formats  
✅ **Status Polling** - Real-time progress updates  

---

## API Reference

See [OPENVAS-INTEGRATION.md](security-scanner/OPENVAS-INTEGRATION.md) for complete API documentation.

**Quick Reference:**
- `scanner.is_available()` - Check if OpenVAS is ready
- `scanner.quick_scan(target, wait=False)` - Fast discovery scan
- `scanner.full_scan(target, wait=False)` - Comprehensive scan
- `scanner.get_scan_status(task_id)` - Check scan progress
- `scanner.get_report(task_id)` - Get vulnerability report

---

## Troubleshooting

### Container not starting
```bash
docker-compose -f docker-compose.openvas-simple.yml logs
docker-compose -f docker-compose.openvas-simple.yml restart
```

### Connection refused
- Wait 5 minutes after first start
- Check container: `docker ps | grep openvas`
- Check logs: `docker logs openvas-gvm`

### Port already in use
```bash
# Find conflicting process
netstat -ano | findstr :9390

# Stop OpenVAS
docker-compose -f docker-compose.openvas-simple.yml down
```

### Memory issues
OpenVAS needs at least 4GB RAM. Check Docker settings:
```bash
docker stats openvas-gvm
```

### Scan not starting
1. Verify OpenVAS is initialized: `docker logs openvas-gvm`
2. Test connection: `pwsh test-openvas-live.ps1`
3. Check python-gvm is installed: `docker run --rm security-scanner pip3 list | grep gvm`

---

## Architecture

```
┌─────────────────────┐         GMP Protocol        ┌──────────────────┐
│ Security Scanner    │◄──────────────────────────►│ OpenVAS Container│
│ (Python Wrapper)    │      (Port 9390)            │ + PostgreSQL     │
│                     │                             │ + Redis          │
│ - Quick scan        │                             │ - 50k+ tests     │
│ - Full scan         │                             │ - CVE database   │
│ - Status check      │                             │ - Web UI         │
│ - Report export     │                             │ - Scan engine    │
└─────────────────────┘                             └──────────────────┘
```

---

## Alternative: Nessus

Since Nessus Professional is paid, we use OpenVAS as the backend. When you select "Nessus" in the UI, it actually runs OpenVAS scans.

---

## Production Setup

For production with separate PostgreSQL and Redis:
```bash
docker-compose -f docker-compose.openvas.yml up -d
```

---

## Resources

- **Integration Guide**: [OPENVAS-INTEGRATION.md](security-scanner/OPENVAS-INTEGRATION.md)
- **Test Script**: `test-openvas-live.ps1`
- **Python Test**: `security-scanner/test-openvas-integration.py`
- **OpenVAS Docs**: https://docs.greenbone.net/
- **GMP Protocol**: https://docs.greenbone.net/API/GMP/
