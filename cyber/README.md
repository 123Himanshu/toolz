# Attack Path Intelligence Engine

A production-grade cybersecurity system that aggregates, normalizes, enriches, correlates, and analyzes vulnerabilities from multiple scanners to generate attack paths and identify zero-day exposure risk.

## Features

### 🔍 Multi-Scanner Support
Ingests and parses data from 10 vulnerability scanners:
- **Nmap** (XML)
- **RustScan** (JSON/stdout)
- **Masscan** (XML/JSON)
- **Naabu** (JSON)
- **Nuclei** (JSON)
- **Wapiti** (JSON)
- **Nikto** (TXT/JSON)
- **Trivy** (JSON)
- **OpenVAS** (XML)
- **Nessus** (XML)

### 🔄 Normalization Pipeline
- Unified vulnerability schema across all scanners
- Intelligent deduplication and merging
- Conflict resolution for overlapping findings
- CVE-based correlation

### 🌐 Threat Intelligence Enrichment
- **NVD API** integration for CVE details
- **ExploitDB** exploit availability checking
- **EPSS** (Exploit Prediction Scoring System) integration
- **MITRE ATT&CK** technique mapping
- CWE classification
- Patch availability detection

### 🕸️ Attack Graph Engine
- NetworkX-based graph construction
- Asset and privilege level modeling
- Vulnerability-based edge creation
- Network reachability analysis
- Lateral movement path identification
- Privilege escalation chains

### ⚔️ Attack Path Generation
- Simple and chained multi-stage attack paths
- Shortest path analysis
- Highest impact path identification
- Most probable path calculation (EPSS-based)
- Kill chain sequence generation
- Exploitability scoring

### 🚨 Zero-Day Detection
Three-layer zero-day capability:

#### 1. Zero-Day Exposure Score (ZDES)
Scores assets (0-100) based on:
- Unknown/unclassified services
- End-of-Life (EOL) software
- Unknown version fingerprints
- Weak configurations
- Abnormal port-service mappings
- Lack of patches
- External exposure
- Scanner disagreements

#### 2. Attack Surface Anomaly Detection
- New ports opened since baseline
- Service banner changes
- Scanner disagreements
- Suspicious patterns
- Baseline deviation analysis

#### 3. Exploit Behavior Detection
- Privilege escalation anomalies
- Unexpected lateral movement
- RCE-like patterns
- Suspicious pivot paths
- Toxic CVE combinations

### 📊 Correlation & Risk Modeling
Weighted risk scoring combining:
- CVSS scores (25%)
- EPSS scores (20%)
- Exploitability (20%)
- Chain potential (15%)
- ZDES scores (10%)
- Path impact (10%)

### 📈 Comprehensive Reporting
- **JSON** - Complete structured data export
- **PDF** - Executive and technical reports
- **HTML** - Interactive dashboard with charts
- **Graph Visualizations** - PNG and D3.js interactive graphs

## Installation

```bash
# Clone repository
git clone <repository-url>
cd attack-path-engine

# Install dependencies
pip install -r requirements.txt

# Optional: Configure Neo4j for graph database (advanced)
# Edit config.yaml with your Neo4j credentials
```

## Configuration

Edit `config.yaml` to customize:

```yaml
# API Keys
api_keys:
  nvd_api_key: "your-nvd-api-key"  # Get from https://nvd.nist.gov/developers/request-an-api-key

# Risk Scoring Weights
risk_weights:
  cvss: 0.25
  epss: 0.20
  exploitability: 0.20
  chain_potential: 0.15
  zdes: 0.10
  path_impact: 0.10

# Zero-Day Detection
zero_day:
  zdes_threshold: 70
  anomaly_sensitivity: 0.8

# Attack Graph
attack_graph:
  max_path_length: 5
  min_cvss_threshold: 4.0
```

## Usage

### Basic Usage

```bash
# Analyze Nmap scan
python main.py --nmap scan_results.xml

# Multiple scanners
python main.py --nmap nmap.xml --nuclei nuclei.json --nessus nessus.nessus

# Specify output formats
python main.py --nmap scan.xml --output json pdf html

# Use custom config
python main.py --nmap scan.xml --config custom_config.yaml
```

### Advanced Usage

```python
from main import AttackPathEngine

# Initialize engine
engine = AttackPathEngine()

# Run analysis
scan_files = {
    'nmap': 'scans/nmap_output.xml',
    'nuclei': 'scans/nuclei_output.json',
    'nessus': 'scans/nessus_scan.nessus'
}

results = engine.run(scan_files, output_formats=['json', 'html'])

# Access results
print(f"Network Risk Score: {results['network_risk_score']}")
print(f"High-Risk Assets: {len(results['high_risk_assets'])}")
print(f"Critical Paths: {len(results['critical_paths'])}")
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SCAN DATA INGESTION                      │
│  Nmap │ RustScan │ Masscan │ Naabu │ Nuclei │ Wapiti │ ... │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  NORMALIZATION PIPELINE                     │
│  • Unified Schema  • Deduplication  • Conflict Resolution   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              THREAT INTELLIGENCE ENRICHMENT                 │
│     NVD │ ExploitDB │ EPSS │ MITRE ATT&CK │ CWE            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   ATTACK GRAPH ENGINE                       │
│  • Graph Construction  • Path Generation  • Risk Analysis   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                 ZERO-DAY DETECTION LAYER                    │
│    ZDES Score │ Anomaly Detection │ Behavior Analysis       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              CORRELATION & RISK MODELING                    │
│  • Weighted Scoring  • Asset Ranking  • Path Prioritization │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   REPORT GENERATION                         │
│         JSON │ PDF │ HTML Dashboard │ Visualizations        │
└─────────────────────────────────────────────────────────────┘
```

## Output Examples

### JSON Output
```json
{
  "metadata": {
    "export_date": "2024-01-15T10:30:00",
    "report_type": "Attack Path Intelligence Engine - Complete Analysis"
  },
  "summary": {
    "total_vulnerabilities": 247,
    "total_attack_paths": 18,
    "total_zero_day_indicators": 12,
    "network_risk_score": 73.5
  },
  "high_risk_assets": [...],
  "critical_paths": [...],
  "zero_day_exposure_map": {...}
}
```

### HTML Dashboard
Interactive dashboard with:
- Real-time risk metrics
- Asset risk distribution charts
- Attack path visualization
- Zero-day exposure heatmap
- Sortable data tables

### PDF Report
Executive report containing:
- Executive summary
- High-risk asset analysis
- Critical attack paths
- Zero-day exposure analysis
- Remediation recommendations

## Project Structure

```
attack-path-engine/
├── ingestors/           # Scanner parsers
│   ├── nmap_parser.py
│   ├── nuclei_parser.py
│   └── ...
├── normalizer/          # Data normalization
│   └── normalize.py
├── enrichment/          # Threat intelligence
│   ├── nvd_enrich.py
│   ├── epss_enrich.py
│   └── attck_mapping.py
├── attack_graph/        # Graph engine
│   ├── graph_builder.py
│   ├── path_generator.py
│   └── edge_rules.py
├── zero_day/            # Zero-day detection
│   ├── zdes_score.py
│   ├── anomaly_detection.py
│   └── exploit_behavior.py
├── correlation/         # Risk correlation
│   └── correlate.py
├── reports/             # Report generation
│   ├── json_exporter.py
│   ├── pdf_report.py
│   ├── html_dashboard.py
│   └── graph_visualizer.py
├── models/              # Data schemas
│   └── schemas.py
├── utils/               # Utilities
│   ├── logger.py
│   └── config.py
├── main.py              # Main engine
├── config.yaml          # Configuration
├── requirements.txt     # Dependencies
└── README.md           # Documentation
```

## Advanced Features

### Bayesian Attack Path Likelihood
The engine uses EPSS scores and historical exploit data to predict attack path probability using Bayesian inference.

### Credential Graph Intelligence
Tracks potential credential reuse and trust relationships between assets for lateral movement analysis.

### Toxic CVE Combinations
Identifies dangerous combinations of vulnerabilities that enable advanced attack chains.

### Service Fingerprint Inference
Uses heuristics to infer service versions when scanners fail to identify them.

### Time-Based Vulnerability Aging
Factors in vulnerability age and patch availability timeline for risk scoring.

## API Integration (Future)

The engine is designed for API integration:

```python
# Future API endpoints
POST /api/v1/scan/ingest
GET  /api/v1/analysis/status
GET  /api/v1/assets/risk
GET  /api/v1/paths/critical
GET  /api/v1/zeroday/indicators
```

## Performance

- Handles 10,000+ vulnerabilities
- Generates attack graphs with 1,000+ nodes
- Processes multiple scanner outputs in parallel
- Efficient caching for API calls
- Optimized graph algorithms

## Security Considerations

- API keys stored in config (use environment variables in production)
- Rate limiting for external API calls
- Input validation for all scanner outputs
- Secure handling of sensitive vulnerability data

## Contributing

This is a production-grade security tool. Contributions should:
- Include comprehensive tests
- Follow security best practices
- Document all changes
- Maintain code quality standards

## License

[Specify your license]

## Disclaimer

This tool is for authorized security testing only. Users are responsible for compliance with applicable laws and regulations.

## Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Built with ❤️ for the cybersecurity community**
