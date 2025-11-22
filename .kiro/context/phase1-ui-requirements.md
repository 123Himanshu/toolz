# Phase 1 UI Requirements

## Core Principle
**Phase 1 UI = Input → Scan Control → Results Viewer**

No reporting dashboards, no analytics, no AI. That comes in Phase 2 & 3.
Build only the core functional skeleton that can start scans, show progress, show results.

## Tool Categorization (MUST FOLLOW)

### 1. Network Enumeration (Active)
- Nmap - Network scanner
- Masscan - High-speed IP scanner
- RustScan - Fast port scanner
- Naabu - Port scanning tool
- Zmap - Internet-scale scanner

### 2. Web Application Scanning (DAST)
- ZAP - OWASP Zed Attack Proxy
- Nuclei - Template-based scanner
- Wapiti - Web application scanner
- Nikto - Web server scanner
- Jaeles - Signature-based scanner

### 3. Host & System Vulnerability Scanning
- Trivy - Container/IaC scanner
- OpenVAS - Vulnerability scanner
- Nessus - Enterprise vulnerability scanner (future)

## UI Screens (6 Required)

### 1. Dashboard
- Minimal landing page
- "New Scan" button
- Recent scans list (optional)

### 2. New Scan Page (MAIN PAGE)
**Components:**

A. **Target Input**
   - Single IP
   - IP Range (CIDR)
   - Domain
   - Subdomain List
   - File Upload (list of targets)

B. **Scan Type Selection**
   - Passive Scan (Recon only)
   - Active Scan (Tools)
   - Both

C. **Tool Selection (Categorized)**
   ```
   NETWORK ENUMERATION
   [x] Nmap
   [x] RustScan
   [x] Naabu
   [ ] Masscan
   [ ] Zmap
   
   WEB APPLICATION SCANNERS
   [x] ZAP
   [x] Nuclei
   [ ] Wapiti
   [ ] Nikto
   [ ] Jaeles
   
   HOST & SYSTEM SCANNERS
   [x] Trivy
   [ ] OpenVAS
   ```

D. **Scan Configuration**
   - Scan Intensity: Low / Medium / High
   - Scan Rate: Fast / Moderate / Slow
   - Max Depth: Shallow / Normal / Deep
   - Timeout per tool

E. **Start Scan Button**

### 3. Scan Queue Page
- Shows all running scans
- Scan ID
- Target
- Status
- Started time
- Actions (pause/stop)

### 4. Scan Progress Page
- Real-time tool-by-tool progress
- Example:
  ```
  Nmap: running (45%)
  Masscan: completed ✓
  Nuclei: queued
  ZAP: running (32%)
  ```

### 5. Scan Results Summary
**Visual + Text Display:**
- Open Ports
- Services Detected
- Technologies Identified
- Vulnerabilities Found
- Critical Findings
- Host List

### 6. Individual Tool Output Page
- Per-tool tabs (like Burp/ZAP)
- Parsed JSON output
- Raw output (for debugging)
- Export options

## Real-World References

This UI design matches:
- **Nessus** - "New Scan" page
- **Burp Enterprise** - "Scan Status"
- **ZAP** - "Sites + Alerts panel"
- **runZero** - "Asset Viewer"
- **Qualys** - Scan configuration

## Key Design Principles

1. **Categorize Tools** - Never dump all tools in one list
2. **User Control** - Let users select which tools to run
3. **Clear Progress** - Show what's running, what's done
4. **Aggregate Results** - Combine outputs intelligently
5. **Raw Access** - Always provide raw output for debugging

## What NOT to Include in Phase 1

❌ Reporting dashboards
❌ Analytics/graphs
❌ AI/ML features
❌ Attack path visualization
❌ CVE correlation
❌ Threat intelligence integration
❌ Chatbot interface

These come in Phase 2 & 3.
