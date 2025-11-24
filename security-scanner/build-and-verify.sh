#!/bin/bash
################################################################################
# Build and Verify Security Scanner Docker Image
################################################################################

set -e

echo "=================================="
echo "Building Security Scanner Image"
echo "=================================="

# Build the image
docker build -t security-scanner:latest .

echo ""
echo "=================================="
echo "Verifying Tool Installation"
echo "=================================="

# Test each tool
echo "Testing Nmap..."
docker run --rm security-scanner nmap --version | head -n 1

echo "Testing RustScan..."
docker run --rm security-scanner rustscan --version

echo "Testing Masscan..."
docker run --rm security-scanner masscan --version | head -n 1

echo "Testing ZMap..."
docker run --rm security-scanner zmap --version | head -n 1

echo "Testing Nuclei..."
docker run --rm security-scanner nuclei -version | head -n 1

echo "Testing Trivy..."
docker run --rm security-scanner trivy --version | head -n 1

echo "Testing Nikto..."
docker run --rm security-scanner nikto -Version | head -n 1

echo "Testing Naabu..."
docker run --rm security-scanner naabu -version | head -n 1

echo "Testing Wapiti..."
docker run --rm security-scanner wapiti --version | head -n 1

echo ""
echo "=================================="
echo "Testing Python Wrappers"
echo "=================================="

echo "Testing RustScan wrapper..."
docker run --rm security-scanner python -c "from rustscan_wrapper import RustScanWrapper; print('✓ RustScan wrapper OK')"

echo "Testing Nmap wrapper..."
docker run --rm security-scanner python -c "from nmap_wrapper import NmapWrapper; print('✓ Nmap wrapper OK')"

echo "Testing Masscan wrapper..."
docker run --rm security-scanner python -c "from masscan_wrapper import MasscanWrapper; print('✓ Masscan wrapper OK')"

echo "Testing Nuclei wrapper..."
docker run --rm security-scanner python -c "from nuclei_scanner import NucleiScanner; print('✓ Nuclei wrapper OK')"

echo ""
echo "=================================="
echo "✅ BUILD AND VERIFICATION COMPLETE"
echo "=================================="
echo ""
echo "Image: security-scanner:latest"
echo "Size: $(docker images security-scanner:latest --format '{{.Size}}')"
echo ""
echo "Ready to scan!"
