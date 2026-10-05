@echo off
REM One-click setup for Windows (uses the 'py' launcher, avoids the Microsoft Store 'python' alias)
set PY=py
%PY% --version >nul 2>nul || set PY=python
%PY% --version >nul 2>nul || (echo Python 3.9+ not found. Install from python.org and tick "Add Python to PATH". & exit /b 1)
%PY% -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py --doctor
echo.
echo Setup done. Next time run:  .venv\Scripts\activate   then   python main.py 192.168.1.0/24
