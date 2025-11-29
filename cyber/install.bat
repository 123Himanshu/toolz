@echo off
REM Attack Path Intelligence Engine - Installation Script (Windows)

echo ==========================================
echo Attack Path Intelligence Engine
echo Installation Script (Windows)
echo ==========================================
echo.

REM Check Python version
echo [1/5] Checking Python version...
python --version
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.8 or higher.
    pause
    exit /b 1
)
echo.

REM Create virtual environment
echo [2/5] Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)
echo Virtual environment created
echo.

REM Activate virtual environment
echo [3/5] Activating virtual environment...
call venv\Scripts\activate.bat
echo Virtual environment activated
echo.

REM Install dependencies
echo [4/5] Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo Dependencies installed
echo.

REM Create necessary directories
echo [5/5] Creating directories...
if not exist logs mkdir logs
if not exist data mkdir data
if not exist output\json mkdir output\json
if not exist output\pdf mkdir output\pdf
if not exist output\html mkdir output\html
if not exist output\graphs mkdir output\graphs
if not exist test_data mkdir test_data
echo Directories created
echo.

echo ==========================================
echo Installation Complete!
echo ==========================================
echo.
echo Next steps:
echo 1. Activate virtual environment: venv\Scripts\activate.bat
echo 2. Configure API keys in config.yaml (optional)
echo 3. Run test: python test_engine.py
echo 4. Run analysis: python main.py --nmap scan.xml
echo.
echo For more information, see:
echo   - README.md (complete documentation)
echo   - QUICKSTART.md (getting started guide)
echo   - API_REFERENCE.md (API documentation)
echo.
pause
