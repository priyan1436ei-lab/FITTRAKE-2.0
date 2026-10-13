@echo off
setlocal
cd /d "%~dp0\.."
where py >nul 2>&1
if errorlevel 1 (
  echo Python launcher not found. Install Python 3.11+ from python.org.
  exit /b 1
)
py -3 -m venv .venv
if errorlevel 1 exit /b 1
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
if errorlevel 1 exit /b 1
python -m pip install -e ".[dev]"
if errorlevel 1 exit /b 1
python -m pytest -q
if errorlevel 1 exit /b 1
python -m PyInstaller --noconfirm --clean --onedir --windowed --name "TRACEBACK-WiFi" --paths src src\traceback_wifi\__main__.py
if errorlevel 1 exit /b 1
echo.
echo SUCCESS: dist\TRACEBACK-WiFi\TRACEBACK-WiFi.exe
echo Copy the WHOLE dist\TRACEBACK-WiFi directory to another Windows computer.
endlocal
