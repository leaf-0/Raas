#!/usr/bin/env python3
"""
FME Sentinel Watch Startup Script
Starts both the backend and provides instructions for the frontend
"""

import os
import sys
import subprocess
import time
import threading
import signal
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    print("Checking dependencies...")
    
    required_packages = [
        'flask', 'flask_cors', 'flask_socketio', 'psutil', 
        'watchdog', 'scipy', 'plotly'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✓ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"✗ {package}")
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Installing missing packages...")
        
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ])
            print("✓ Dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("✗ Failed to install dependencies")
            print("Please run: pip install -r requirements.txt")
            return False
    
    return True

def start_backend():
    """Start the Flask backend"""
    print("\n" + "="*50)
    print("Starting FME-ABT Backend...")
    print("="*50)
    
    try:
        # Import and start the dashboard app
        from app import dashboard_app
        
        # Start in a separate thread so we can handle shutdown
        def run_app():
            dashboard_app.run(host='127.0.0.1', port=5000, debug=False)
        
        backend_thread = threading.Thread(target=run_app, daemon=True)
        backend_thread.start()
        
        # Give the backend time to start
        time.sleep(3)
        
        print("✓ Backend started on http://127.0.0.1:5000")
        return True
        
    except Exception as e:
        print(f"✗ Failed to start backend: {e}")
        return False

def test_backend_connection():
    """Test if backend is responding"""
    import requests
    
    try:
        response = requests.get("http://127.0.0.1:5000/api/status", timeout=5)
        if response.status_code == 200:
            print("✓ Backend is responding")
            return True
        else:
            print(f"✗ Backend returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Backend connection failed: {e}")
        return False

def print_frontend_instructions():
    """Print instructions for starting the frontend"""
    print("\n" + "="*50)
    print("FME Sentinel Watch Frontend Instructions")
    print("="*50)
    
    frontend_path = Path("fme-sentinel-watch")
    
    if frontend_path.exists():
        print("Frontend directory found!")
        print("\nTo start the FME Sentinel Watch frontend:")
        print("1. Open a new terminal/command prompt")
        print("2. Navigate to the frontend directory:")
        print(f"   cd {frontend_path.absolute()}")
        print("3. Install dependencies (first time only):")
        print("   npm install")
        print("4. Start the development server:")
        print("   npm run dev")
        print("\n5. Open your browser to: http://localhost:5173")
    else:
        print("Frontend directory not found!")
        print("Make sure the 'fme-sentinel-watch' directory exists")
    
    print("\n" + "="*50)

def main():
    """Main startup function"""
    print("🛡️  FME Sentinel Watch Startup")
    print("="*50)
    
    # Check if we're in the right directory
    if not os.path.exists("app.py"):
        print("✗ app.py not found. Please run this script from the project root directory.")
        return
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Start backend
    if not start_backend():
        return
    
    # Test connection
    if not test_backend_connection():
        return
    
    # Print frontend instructions
    print_frontend_instructions()
    
    print("\n🎉 Backend is running!")
    print("📊 Dashboard available at: http://127.0.0.1:5000")
    print("🛡️  FME Sentinel Watch will connect automatically when started")
    
    print("\nPress Ctrl+C to stop the backend...")
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down...")
        print("Backend stopped.")

if __name__ == "__main__":
    main()
