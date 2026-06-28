@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo [1/5] Checking Python...
py -3 --version >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python 3 was not found. Please install Python 3.9+ and enable "Add Python to PATH".
    exit /b 1
)

echo [2/5] Creating build virtual environment...
if not exist ".venv-build" (
    py -3 -m venv .venv-build
    if errorlevel 1 exit /b 1
)

call ".venv-build\Scripts\activate.bat"
if errorlevel 1 exit /b 1

echo [3/5] Installing dependencies...
python -m pip install --upgrade pip
if errorlevel 1 exit /b 1
python -m pip install -r requirements.txt -r requirements-build.txt
if errorlevel 1 exit /b 1

echo [4/5] Running regression tests...
python test_signing_service.py
if errorlevel 1 exit /b 1

echo [5/5] Building Windows executable...
pyinstaller --clean --noconfirm p7s_signer.spec
if errorlevel 1 exit /b 1

echo.
echo Build finished.
echo EXE path: %cd%\dist\P7S离线文件数字签名工具.exe
echo.
pause
