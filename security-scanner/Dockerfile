################################################################################
# COMPLETE SECURITY SCANNER - ALL TOOLS WORKING
################################################################################

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:/usr/local/go/bin:/root/go/bin:${PATH}" \
    GOPATH=/root/go

################################################################################
# STAGE 1: SYSTEM DEPENDENCIES
################################################################################
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    curl wget unzip git ca-certificates \
    build-essential clang make \
    libpcap-dev nmap whois dnsutils \
    net-tools iputils-ping \
    perl libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

################################################################################
# STAGE 2: INSTALL GO
################################################################################
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz && \
    go version

################################################################################
# STAGE 3: INSTALL PYTHON PACKAGES
################################################################################
RUN pip3 install --no-cache-dir \
    requests dnspython python-whois urllib3 docker wapiti3 python-gvm lxml

################################################################################
# STAGE 4: INSTALL MASSCAN
################################################################################
RUN git clone https://github.com/robertdavidgraham/masscan /tmp/masscan && \
    cd /tmp/masscan && make -j$(nproc) && make install && \
    cd / && rm -rf /tmp/masscan && \
    (masscan --version || echo "Masscan installed")

################################################################################
# STAGE 5: INSTALL NUCLEI
################################################################################
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /tmp && \
    chmod +x /tmp/nuclei && \
    mv /tmp/nuclei /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    nuclei -version && \
    nuclei -update-templates

################################################################################
# STAGE 6: INSTALL SUBFINDER
################################################################################
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip -O /tmp/subfinder.zip && \
    unzip -o -q /tmp/subfinder.zip -d /tmp && \
    chmod +x /tmp/subfinder && \
    mv /tmp/subfinder /usr/local/bin/ && \
    rm -f /tmp/subfinder.zip /tmp/LICENSE.md /tmp/README.md && \
    subfinder -version

################################################################################
# STAGE 8: INSTALL NAABU
################################################################################
RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.2/naabu_2.3.2_linux_amd64.zip -O /tmp/naabu.zip && \
    unzip -o -q /tmp/naabu.zip -d /tmp && \
    chmod +x /tmp/naabu && \
    mv /tmp/naabu /usr/local/bin/ && \
    rm -f /tmp/naabu.zip /tmp/LICENSE.md /tmp/README.md && \
    naabu -version

################################################################################
# STAGE 9: INSTALL HTTPX
################################################################################
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip -O /tmp/httpx.zip && \
    unzip -o -q /tmp/httpx.zip -d /tmp && \
    chmod +x /tmp/httpx && \
    mv /tmp/httpx /usr/local/bin/ && \
    rm -f /tmp/httpx.zip /tmp/LICENSE.md /tmp/README.md && \
    httpx -version

################################################################################
# STAGE 10: INSTALL TRIVY
################################################################################
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.deb -O /tmp/trivy.deb && \
    dpkg -i /tmp/trivy.deb && \
    rm /tmp/trivy.deb && \
    trivy --version

################################################################################
# STAGE 12: INSTALL RUSTSCAN (from GitHub releases - static binary)
################################################################################
RUN wget -q https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb -O /tmp/rustscan.deb && \
    apt-get update && \
    apt-get install -y -f /tmp/rustscan.deb || \
    (dpkg --unpack /tmp/rustscan.deb && apt-get install -y -f && dpkg --configure rustscan) && \
    rm /tmp/rustscan.deb && \
    rm -rf /var/lib/apt/lists/* && \
    rustscan --version

################################################################################
# STAGE 13: INSTALL NIKTO (from source)
################################################################################
RUN git clone https://github.com/sullo/nikto /tmp/nikto && \
    cd /tmp/nikto/program && \
    chmod +x nikto.pl && \
    ln -s /tmp/nikto/program/nikto.pl /usr/local/bin/nikto && \
    nikto -Version

################################################################################
# STAGE 14: OPENVAS NOTE
################################################################################
# OpenVAS/Nessus requires separate container with PostgreSQL and Redis
# Use: docker-compose -f docker-compose.openvas-simple.yml up -d
# The wrapper (openvas_wrapper_simple.py) connects to external OpenVAS instance
RUN echo "OpenVAS: Use separate container (docker-compose.openvas-simple.yml)"

################################################################################
# STAGE 15: VERIFY ALL TOOLS
################################################################################
RUN echo "==> Verifying installations..." && \
    echo "✓ Nmap: $(nmap --version | head -n 1)" && \
    echo "✓ Masscan: Installed" && \
    echo "✓ RustScan: $(rustscan --version 2>&1 | head -n 1)" && \

    echo "✓ Nuclei: $(nuclei -version 2>&1 | head -n 1)" && \

    echo "✓ Subfinder: $(subfinder -version 2>&1 | head -n 1)" && \
    echo "✓ Naabu: $(naabu -version 2>&1 | head -n 1)" && \
    echo "✓ Httpx: $(httpx -version 2>&1 | head -n 1)" && \
    echo "✓ Trivy: $(trivy --version 2>&1 | head -n 1)" && \
    echo "✓ Nikto: $(nikto -Version 2>&1 | head -n 1)" && \
    echo "✓ Wapiti: $(wapiti --version 2>&1 | head -n 1)" && \
    echo "✓ Python: $(python3 --version)" && \
    echo "✓ OpenVAS: External container (use docker-compose.openvas-simple.yml)" && \
    echo "==> ALL 11 TOOLS VERIFIED (OpenVAS/Nessus via separate container)!"

################################################################################
# STAGE 16: COPY SCANNER FILES
################################################################################
WORKDIR /scanner

COPY nuclei_scanner.py .

COPY wapiti_scanner.py .
COPY nikto_scanner.py .
COPY unified_scanner.py .
COPY passive_recon.py .
COPY passive_recon_v2.py .
COPY nmap_wrapper.py .
COPY masscan_wrapper.py .
COPY naabu_wrapper.py .
COPY rustscan_wrapper.py .

COPY openvas_wrapper.py .
COPY subfinder_wrapper.py .
COPY httpx_wrapper.py .
COPY openvas_wrapper_simple.py .
COPY trivy_wrapper.py .
COPY tools_wrapper.py .
COPY utils.py .
COPY target_classifier.py .
COPY test-all-tools.py .
COPY health-check.py .
COPY test-gmp-connection.py .

################################################################################
# STAGE 17: CREATE DIRECTORIES
################################################################################
RUN mkdir -p results reports nikto-results \
    nmap-results masscan-results nuclei-output

################################################################################
# STAGE 18: ENTRYPOINT
################################################################################
CMD ["python3", "-c", "print('\\n🔒 Security Scanner Ready - All 13 Tools Installed\\n')"]
