@echo off
echo ============================================================
echo FME-ABT Backend Startup Script
echo ============================================================
echo.

REM Try different Python commands
echo Checking for Python installation...

python --version >nul 2>&1
if %errorlevel% == 0 (
    echo Found Python: python
    set PYTHON_CMD=python
    goto :start_backend
)

python3 --version >nul 2>&1
if %errorlevel% == 0 (
    echo Found Python: python3
    set PYTHON_CMD=python3
    goto :start_backend
)

py --version >nul 2>&1
if %errorlevel% == 0 (
    echo Found Python: py
    set PYTHON_CMD=py
    goto :start_backend
)

echo.
echo ERROR: Python not found!
echo Please install Python from https://python.org
echo Make sure to check "Add Python to PATH" during installation
echo.
pause
exit /b 1

:start_backend
echo.
echo Installing dependencies...
%PYTHON_CMD% -m pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies
    echo Please check your internet connection and try again
    pause
    exit /b 1
)

echo.
echo Starting FME-ABT Backend...
echo Backend will be available at: http://127.0.0.1:5000
echo Dashboard will be available at: http://127.0.0.1:5000
echo.
echo To start FME Sentinel Watch frontend:
echo 1. Open a new command prompt
echo 2. cd fme-sentinel-watch
echo 3. npm install
echo 4. npm run dev
echo 5. Open http://localhost:5173 in your browser
echo.
echo Press Ctrl+C to stop the backend
echo ============================================================
echo.

%PYTHON_CMD% app.py

echo.
echo Backend stopped.
pause
