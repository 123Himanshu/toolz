# Problem Statement - SIH 2025

**Problem ID:** 25234  
**Title:** Centralized Vulnerability Detection and Intelligent Query Interface  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software

## Background

Cybersecurity defenders today use too many separate tools for analysis. Build an integrated smart AI assistant that can explain threats in a consolidated format and help in making sense of security reports.

## Three Phases

### Phase 1: Vulnerability Scanning & Data Collection
Develop a responsive web GUI that initiates active/passive enumeration. Integrate tools like Nmap, OpenVAS, Nessus, Nikto, Nuclei and more for wider data collection.

### Phase 2: Report Aggregation & Attack Path Generation
Aggregate and normalize scan results into structured reports detailing CVE IDs, CVSS scores, vulnerability descriptions, and affected components. Develop Model that should be capable to generate possible attack path for simple and chain vulnerabilities given in report. Automate correlation with threat intelligence sources (NVD, ExploitDB, Rapid7) for enriched and accurate insights.

### Phase 3: RAG-Based Chatbot Integration
Integrate a context-aware RAG-based chatbot to allow natural language queries on attack path, vulnerabilities. The assistant must deliver exploit steps, remediation guidance, and reference CVE databases. Use a custom or pre-trained model, enabling real-time, multi-user interaction without ethical prompt restrictions.

## Expected Solution

The proposed solution must facilitate:
- Real-time vulnerability scanning of specified targets (web domains)
- Seamless and user-friendly GUI
- Automatically generating structured and concise scan reports
- Integrated RAG-powered chatbot referencing NVD, ExploitDB, and CVE databases
- Command interpretation based on vulnerability nature and severity
- Model evaluation based on Accuracy, F1 score, BLEU/ROUGE score

## Current Status

**Working on:** Phase 1 - Vulnerability Scanning & Data Collection

**Backend Status:** ✅ COMPLETE
- All scanning tools integrated in Docker
- 12+ tools ready: Nmap, Masscan, RustScan, Naabu, Zmap, Nuclei, Jaeles, Wapiti, Nikto, ZAP, Trivy, OpenVAS
- Unified scanner interface working
- Passive reconnaissance engines ready
- Docker image: security-scanner:latest

**Next:** Build Phase 1 UI
