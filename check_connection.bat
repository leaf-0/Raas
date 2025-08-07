@echo off
echo ============================================================
echo FME-ABT Backend Connection Test
echo ============================================================
echo.

echo Testing backend connection...
echo.

REM Test if backend is running
curl -s http://127.0.0.1:5000/api/status >nul 2>&1
if %errorlevel% == 0 (
    echo ✓ Backend is running on http://127.0.0.1:5000
    echo.
    echo Testing API endpoints:
    echo.
    
    echo Testing /api/status...
    curl -s http://127.0.0.1:5000/api/status
    echo.
    echo.
    
    echo Testing /api/alerts...
    curl -s http://127.0.0.1:5000/api/alerts
    echo.
    echo.
    
    echo Testing /api/memory...
    curl -s http://127.0.0.1:5000/api/memory
    echo.
    echo.
    
    echo ✓ Backend is ready for FME Sentinel Watch!
    echo.
    echo Next steps:
    echo 1. Open a new command prompt
    echo 2. cd fme-sentinel-watch
    echo 3. npm install (first time only)
    echo 4. npm run dev
    echo 5. Open http://localhost:5173 in your browser
    
) else (
    echo ✗ Backend is not running
    echo.
    echo To start the backend:
    echo 1. Run: start_backend.bat
    echo 2. Wait for "Running on http://127.0.0.1:5000" message
    echo 3. Run this script again to test
)

echo.
echo ============================================================
pause
