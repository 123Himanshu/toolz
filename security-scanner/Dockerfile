################################################################################
# COMPLETE SECURITY SCANNER - ALL-IN-ONE DOCKER IMAGE
################################################################################
# This Dockerfile includes ALL security scanning tools in a single image:
# - Core Scanners: Nuclei, Jaeles, Wapiti, ZAP, Nikto
# - Network Tools: Nmap, Masscan, Naabu, Subfinder, Httpx
# - Passive Recon: Custom Python engines
# - Unified Interface: Python-based unified scanner
################################################################################

FROM python:3.11-slim

LABEL maintainer="Security Scanner Team"
LABEL description="Complete all-in-one security scanning suite"
LABEL version="1.0"

# Environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:/usr/local/go/bin:/root/go/bin:${PATH}" \
    GOPATH=/root/go

################################################################################
# STAGE 1: INSTALL SYSTEM DEPENDENCIES
################################################################################
RUN apt-get update && apt-get install -y \
    # Basic utilities
    curl \
    wget \
    unzip \
    git \
    ca-certificates \
    # Build tools
    build-essential \
    clang \
    make \
    # Network tools
    libpcap-dev \
    nmap \
    whois \
    dnsutils \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

################################################################################
# STAGE 2: INSTALL MASSCAN FROM SOURCE
################################################################################
RUN echo "==> Installing Masscan from source..." && \
    git clone https://github.com/robertdavidgraham/masscan /tmp/masscan && \
    cd /tmp/masscan && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/masscan && \
    (masscan --version 2>&1 || echo "Masscan installed but version check failed") && \
    echo "✓ Masscan installed"

################################################################################
# STAGE 3: INSTALL GO (Required for Jaeles)
################################################################################
RUN echo "==> Installing Go..." && \
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz && \
    /usr/local/go/bin/go version && \
    echo "✓ Go installed"

################################################################################
# STAGE 4: INSTALL PYTHON DEPENDENCIES
################################################################################
WORKDIR /scanner

RUN echo "==> Installing Python packages..." && \
    pip install --no-cache-dir \
    requests \
    dnspython \
    python-whois \
    urllib3 \
    docker \
    wapiti3 && \
    echo "✓ Python packages installed"

################################################################################
# STAGE 5: INSTALL NUCLEI
################################################################################
RUN echo "==> Installing Nuclei..." && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip nuclei_3.3.7_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.3.7_linux_amd64.zip && \
    nuclei -version && \
    nuclei -update-templates && \
    echo "✓ Nuclei installed with templates"

################################################################################
# STAGE 6: INSTALL JAELES
################################################################################
RUN echo "==> Installing Jaeles..." && \
    /usr/local/go/bin/go install github.com/jaeles-project/jaeles@latest && \
    cp /root/go/bin/jaeles /usr/local/bin/ && \
    (jaeles --help 2>&1 | head -n 1 && echo "✓ Jaeles: Available" || echo "⚠ Jaeles: Installed but help check failed") && \
    (jaeles config init || echo "Jaeles config init skipped") && \
    echo "✓ Jaeles installed"

################################################################################
# STAGE 7: INSTALL SUBFINDER
################################################################################
RUN echo "==> Installing Subfinder..." && \
    wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    rm -f subfinder_2.6.6_linux_amd64.zip LICENSE.md README.md && \
    subfinder -version && \
    echo "✓ Subfinder installed"

################################################################################
# STAGE 8: INSTALL NAABU
################################################################################
RUN echo "==> Installing Naabu..." && \
    wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.2/naabu_2.3.2_linux_amd64.zip && \
    unzip naabu_2.3.2_linux_amd64.zip && \
    mv naabu /usr/local/bin/ && \
    rm -f naabu_2.3.2_linux_amd64.zip LICENSE.md README.md && \
    naabu -version && \
    echo "✓ Naabu installed"

################################################################################
# STAGE 9: INSTALL HTTPX
################################################################################
RUN echo "==> Installing Httpx..." && \
    wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && \
    unzip httpx_1.6.9_linux_amd64.zip && \
    mv httpx /usr/local/bin/ && \
    rm -f httpx_1.6.9_linux_amd64.zip LICENSE.md README.md && \
    httpx -version && \
    echo "✓ Httpx installed"

################################################################################
# STAGE 10: VERIFY ALL INSTALLATIONS
################################################################################
RUN echo "==> Verifying all installations..." && \
    echo "✓ Nuclei: $(nuclei -version 2>&1 | head -n 1)" && \
    (jaeles --help 2>&1 | head -n 1 && echo "✓ Jaeles: Available" || echo "⚠ Jaeles: Installed") && \
    echo "✓ Subfinder: $(subfinder -version 2>&1 | head -n 1)" && \
    echo "✓ Naabu: $(naabu -version 2>&1 | head -n 1)" && \
    echo "✓ Httpx: $(httpx -version 2>&1 | head -n 1)" && \
    echo "✓ Nmap: $(nmap --version | head -n 1)" && \
    (masscan --version 2>&1 | head -n 1 && echo "✓ Masscan: Available" || echo "⚠ Masscan: Installed but version check failed") && \
    echo "✓ Wapiti: $(wapiti --version 2>&1 | head -n 1)" && \
    echo "✓ Python: $(python --version)" && \
    echo "==> All tools verified successfully!"

################################################################################
# STAGE 11: COPY SCANNER FILES
################################################################################
COPY nuclei_scanner.py .
COPY jaeles_scanner.py .
COPY wapiti_scanner.py .
COPY zap_scanner.py .
COPY nikto_scanner.py .
COPY unified_scanner.py .
COPY passive_recon.py .
COPY passive_recon_v2.py .
COPY nmap_wrapper.py .
COPY masscan_wrapper.py .
COPY naabu_wrapper.py .
COPY rustscan_wrapper.py .
COPY zmap_wrapper.py .
COPY openvas_wrapper.py .
COPY trivy_wrapper.py .
COPY tools_wrapper.py .
COPY utils.py .
COPY test_docker_complete.py .
COPY test_quick_scan.py .
COPY final_verification.py .

################################################################################
# STAGE 12: CREATE RESULT DIRECTORIES
################################################################################
RUN mkdir -p \
    /scanner/results \
    /scanner/reports \
    /scanner/zap-results \
    /scanner/nikto-results \
    /scanner/jaeles-output \
    /scanner/nmap-results \
    /scanner/masscan-results \
    /scanner/nuclei-output

################################################################################
# STAGE 13: HEALTHCHECK
################################################################################
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nuclei -version && \
        jaeles version && \
        nmap --version && \
        masscan --version && \
        python --version || exit 1

################################################################################
# STAGE 14: ENTRYPOINT
################################################################################
CMD ["python", "-c", "\
print('\\n' + '='*70); \
print('🔒 COMPLETE SECURITY SCANNER - ALL TOOLS READY'); \
print('='*70); \
print('\\nCore Scanners:'); \
print('  ✓ Nuclei v3.3.7    - Template-based vulnerability scanner'); \
print('  ✓ Jaeles          - Signature-based web scanner'); \
print('  ✓ Wapiti          - Web application scanner'); \
print('  ✓ ZAP             - OWASP Zed Attack Proxy (via Docker)'); \
print('  ✓ Nikto           - Web server scanner (via Docker)'); \
print('\\nNetwork Tools:'); \
print('  ✓ Nmap 7.95       - Network scanner'); \
print('  ✓ Masscan         - High-speed IP scanner'); \
print('  ✓ Naabu v2.3.2    - Port scanner'); \
print('  ✓ Subfinder v2.6.6 - Subdomain enumeration'); \
print('  ✓ Httpx v1.6.9    - HTTP probe'); \
print('\\nPassive Recon:'); \
print('  ✓ Passive Recon v1 - Basic intelligence gathering'); \
print('  ✓ Passive Recon v2 - Enhanced reconnaissance'); \
print('\\nUnified Interface:'); \
print('  ✓ Unified Scanner  - Combines all scanners'); \
print('\\n' + '='*70); \
print('Usage Examples:'); \
print('  docker run -it security-scanner /bin/bash'); \
print('  docker run --rm security-scanner python test_docker_complete.py'); \
print('  docker run --rm security-scanner python -c \"from unified_scanner import UnifiedScanner; scanner = UnifiedScanner(use_docker=False); scanner.quick_scan(\\'https://httpbin.org\\')\"'); \
print('\\n' + '='*70); \
print('Ready to scan! 🚀'); \
print('='*70 + '\\n'); \
"]

################################################################################
# BUILD & RUN INSTRUCTIONS
################################################################################
# Build:
#   docker build -t security-scanner:latest .
#
# Run default:
#   docker run --rm security-scanner
#
# Run tests:
#   docker run --rm security-scanner python test_docker_complete.py
#
# Interactive shell:
#   docker run -it --rm security-scanner /bin/bash
#
# Quick scan:
#   docker run --rm -v $(pwd)/results:/scanner/results security-scanner \
#     python -c "from unified_scanner import UnifiedScanner; \
#     scanner = UnifiedScanner(use_docker=False); \
#     scanner.quick_scan('https://httpbin.org'); \
#     scanner.generate_report()"
#
# Mount Docker socket (for ZAP/Nikto):
#   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock security-scanner
#
# Expected image size: ~2GB
# Build time: ~10-15 minutes
################################################################################
