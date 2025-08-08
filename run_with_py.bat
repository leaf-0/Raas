@echo off
echo ============================================================
echo FME-ABT Quick Start (Using Python Launcher)
echo ============================================================
echo.

echo Trying Python Launcher (py command)...
py --version
if %errorlevel% neq 0 (
    echo.
    echo Python Launcher not found.
    echo Please install Python from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo.
echo Installing dependencies using Python Launcher...
py -m pip install --upgrade pip
py -m pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo Some packages failed to install. Trying individually...
    py -m pip install watchdog psutil scipy flask flask-socketio flask-cors plotly requests
)

echo.
echo Testing connection...
py test_connection.py

echo.
echo Starting backend...
echo Backend will be available at: http://127.0.0.1:5000
echo.
py app.py

pause
