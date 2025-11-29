#!/bin/bash
# Attack Path Intelligence Engine - Installation Script

echo "=========================================="
echo "Attack Path Intelligence Engine"
echo "Installation Script"
echo "=========================================="
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

# Create virtual environment
echo ""
echo "[2/5] Creating virtual environment..."
python3 -m venv venv
echo "✓ Virtual environment created"

# Activate virtual environment
echo ""
echo "[3/5] Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"

# Install dependencies
echo ""
echo "[4/5] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "✓ Dependencies installed"

# Create necessary directories
echo ""
echo "[5/5] Creating directories..."
mkdir -p logs
mkdir -p data
mkdir -p output/json
mkdir -p output/pdf
mkdir -p output/html
mkdir -p output/graphs
mkdir -p test_data
echo "✓ Directories created"

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Configure API keys in config.yaml (optional)"
echo "3. Run test: python test_engine.py"
echo "4. Run analysis: python main.py --nmap scan.xml"
echo ""
echo "For more information, see:"
echo "  - README.md (complete documentation)"
echo "  - QUICKSTART.md (getting started guide)"
echo "  - API_REFERENCE.md (API documentation)"
echo ""
