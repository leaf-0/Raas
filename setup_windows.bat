@echo off
echo ============================================================
echo FME-ABT Windows Setup Script
echo ============================================================
echo.

echo Checking Python installation...
echo.

REM Check for different Python commands
python --version >nul 2>&1
if %errorlevel% == 0 (
    echo Found Python: python
    set PYTHON_CMD=python
    set PIP_CMD=pip
    goto :check_pip
)

python3 --version >nul 2>&1
if %errorlevel% == 0 (
    echo Found Python: python3
    set PYTHON_CMD=python3
    set PIP_CMD=pip3
    goto :check_pip
)

py --version >nul 2>&1
if %errorlevel% == 0 (
    echo Found Python: py
    set PYTHON_CMD=py
    set PIP_CMD=py -m pip
    goto :check_pip
)

echo.
echo ERROR: Python not found!
echo.
echo Please install Python from https://python.org
echo Make sure to:
echo 1. Download Python 3.9 or later
echo 2. Check "Add Python to PATH" during installation
echo 3. Restart your command prompt after installation
echo.
echo Alternative: Try using the Python Launcher:
echo   py --version
echo   py -m pip --version
echo.
pause
exit /b 1

:check_pip
echo.
echo Checking pip installation...
%PIP_CMD% --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ERROR: pip not found!
    echo Trying alternative pip commands...
    
    %PYTHON_CMD% -m pip --version >nul 2>&1
    if %errorlevel% == 0 (
        echo Found pip via: %PYTHON_CMD% -m pip
        set PIP_CMD=%PYTHON_CMD% -m pip
        goto :install_deps
    )
    
    echo.
    echo pip is not available. Installing pip...
    %PYTHON_CMD% -m ensurepip --upgrade
    if %errorlevel% neq 0 (
        echo Failed to install pip automatically.
        echo Please install pip manually or reinstall Python.
        pause
        exit /b 1
    )
    set PIP_CMD=%PYTHON_CMD% -m pip
)

:install_deps
echo.
echo Python command: %PYTHON_CMD%
echo Pip command: %PIP_CMD%
echo.
echo Installing dependencies...
echo.

%PIP_CMD% install --upgrade pip
if %errorlevel% neq 0 (
    echo Warning: Could not upgrade pip, continuing...
)

echo.
echo Installing required packages...
%PIP_CMD% install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install some dependencies.
    echo.
    echo Trying to install packages individually...
    echo.
    
    %PIP_CMD% install watchdog==6.0.0
    %PIP_CMD% install psutil==7.0.0
    %PIP_CMD% install scipy==1.15.2
    %PIP_CMD% install flask==3.1.0
    %PIP_CMD% install flask-socketio==5.3.6
    %PIP_CMD% install flask-cors==4.0.0
    %PIP_CMD% install plotly==5.17.0
    %PIP_CMD% install requests==2.31.0
    
    echo.
    echo Individual package installation complete.
)

echo.
echo ============================================================
echo Testing installation...
echo ============================================================

%PYTHON_CMD% -c "import flask; print('✓ Flask installed')" 2>nul || echo "✗ Flask not installed"
%PYTHON_CMD% -c "import psutil; print('✓ psutil installed')" 2>nul || echo "✗ psutil not installed"
%PYTHON_CMD% -c "import watchdog; print('✓ watchdog installed')" 2>nul || echo "✗ watchdog not installed"
%PYTHON_CMD% -c "import scipy; print('✓ scipy installed')" 2>nul || echo "✗ scipy not installed"
%PYTHON_CMD% -c "import requests; print('✓ requests installed')" 2>nul || echo "✗ requests not installed"

echo.
echo ============================================================
echo Starting FME-ABT Backend...
echo ============================================================
echo.
echo Backend will be available at: http://127.0.0.1:5000
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
