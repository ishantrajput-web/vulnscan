@echo off
REM Double-click to start the VulnScan dashboard (opens your browser)
set PY=py
%PY% --version >nul 2>nul || set PY=python
%PY% --version >nul 2>nul || (echo Python 3.9+ not found. Install from python.org and tick "Add Python to PATH". & pause & exit /b 1)
cd /d "%~dp0"
%PY% main.py --ui
pause
