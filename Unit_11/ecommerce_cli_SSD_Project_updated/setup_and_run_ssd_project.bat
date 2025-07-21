@echo off
REM Secure E-Commerce CLI Setup Script for Windows

echo.
echo ========================================
echo     MSc SSD Project Setup Script
echo ========================================
echo.

REM Create virtual environment
echo [1/5] Creating virtual environment...
python -m venv venv

REM Activate environment
echo [2/5] Activating environment...
call venv\Scripts\activate.bat

REM Install requirements
echo [3/5] Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt

REM Generate encryption key
echo [4/5] Generating encryption key...
python -c "from app.core import storage; storage.generate_key()"

REM Start application
echo [5/5] Launching CLI...
python run.py

pause
