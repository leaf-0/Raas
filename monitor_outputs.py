#!/usr/bin/env python3
"""
Real-time Output Monitor for FME-ABT Detector
Shows all system outputs in real-time including database contents, API responses, and logs
"""

import os
import time
import sqlite3
import requests
import json
from datetime import datetime
from pathlib import Path

def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def check_backend_status():
    """Check if backend is running"""
    try:
        response = requests.get("http://127.0.0.1:5000/api/status", timeout=5)
        return response.status_code == 200
    except:
        return False

def show_database_contents():
    """Show contents of both databases"""
    print_header("📊 DATABASE CONTENTS")
    
    # File Events Database
    if os.path.exists("file_events.db"):
        print("\n📁 Recent File Events:")
        try:
            conn = sqlite3.connect("file_events.db")
            cursor = conn.execute("""
                SELECT path, event_type, timestamp, process_name, size 
                FROM file_events 
                ORDER BY timestamp DESC 
                LIMIT 10
            """)
            
            events = cursor.fetchall()
            if events:
                print(f"{'Path':<30} {'Type':<10} {'Time':<20} {'Process':<15} {'Size':<10}")
                print("-" * 95)
                for event in events:
                    path = os.path.basename(event[0]) if event[0] else "N/A"
                    event_type = event[1] or "N/A"
                    timestamp = datetime.fromtimestamp(event[2]).strftime('%H:%M:%S') if event[2] else "N/A"
                    process = event[3] or "N/A"
                    size = f"{event[4]}B" if event[4] else "N/A"
                    print(f"{path:<30} {event_type:<10} {timestamp:<20} {process:<15} {size:<10}")
            else:
                print("  No events found")
            
            conn.close()
        except Exception as e:
            print(f"  Error reading file_events.db: {e}")
    else:
        print("  📁 file_events.db not found")
    
    # Alerts Database
    if os.path.exists("alerts.db"):
        print("\n🚨 Recent Alerts:")
        try:
            conn = sqlite3.connect("alerts.db")
            cursor = conn.execute("""
                SELECT alert_type, severity, message, timestamp, file_path 
                FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT 10
            """)
            
            alerts = cursor.fetchall()
            if alerts:
                print(f"{'Type':<12} {'Severity':<10} {'Message':<40} {'Time':<10}")
                print("-" * 80)
                for alert in alerts:
                    alert_type = alert[0] or "N/A"
                    severity = alert[1] or "N/A"
                    message = (alert[2][:37] + "...") if alert[2] and len(alert[2]) > 40 else (alert[2] or "N/A")
                    timestamp = datetime.fromtimestamp(alert[3]).strftime('%H:%M:%S') if alert[3] else "N/A"
                    print(f"{alert_type:<12} {severity:<10} {message:<40} {timestamp:<10}")
            else:
                print("  No alerts found")
            
            conn.close()
        except Exception as e:
            print(f"  Error reading alerts.db: {e}")
    else:
        print("  🚨 alerts.db not found")

def show_api_responses():
    """Show current API responses"""
    print_header("🌐 API RESPONSES")
    
    if not check_backend_status():
        print("❌ Backend not running - start with: python app.py")
        return
    
    endpoints = [
        ("/api/status", "System Status"),
        ("/api/alerts", "Recent Alerts"),
        ("/api/memory", "Memory Usage"),
        ("/api/events", "Recent Events"),
        ("/api/metrics", "System Metrics")
    ]
    
    for endpoint, description in endpoints:
        try:
            response = requests.get(f"http://127.0.0.1:5000{endpoint}", timeout=5)
            print(f"\n🔗 {description} ({endpoint}):")
            
            if response.status_code == 200:
                data = response.json()
                # Pretty print JSON with truncation
                json_str = json.dumps(data, indent=2)
                if len(json_str) > 500:
                    json_str = json_str[:500] + "\n  ... (truncated)"
                print(json_str)
            else:
                print(f"  ❌ Error: {response.status_code}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")

def show_log_files():
    """Show recent log entries"""
    print_header("📝 LOG FILES")
    
    log_files = ["errors.log"]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            print(f"\n📄 {log_file} (last 10 lines):")
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    recent_lines = lines[-10:] if len(lines) > 10 else lines
                    
                    if recent_lines:
                        for line in recent_lines:
                            print(f"  {line.strip()}")
                    else:
                        print("  (empty)")
            except Exception as e:
                print(f"  Error reading {log_file}: {e}")
        else:
            print(f"\n📄 {log_file}: Not found")

def show_monitored_directory():
    """Show contents of monitored directory"""
    print_header("📂 MONITORED DIRECTORY")
    
    monitor_dir = Path("./monitored")
    
    if monitor_dir.exists():
        files = list(monitor_dir.iterdir())
        if files:
            print(f"\n📁 Files in {monitor_dir.absolute()}:")
            print(f"{'Name':<30} {'Size':<10} {'Modified':<20}")
            print("-" * 65)
            
            for file_path in sorted(files):
                if file_path.is_file():
                    try:
                        stat = file_path.stat()
                        size = f"{stat.st_size}B"
                        modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        print(f"{file_path.name:<30} {size:<10} {modified:<20}")
                    except Exception as e:
                        print(f"{file_path.name:<30} {'Error':<10} {str(e):<20}")
        else:
            print("  📁 Directory is empty")
    else:
        print("  📁 Monitored directory does not exist")
        print("  💡 Create it with: mkdir monitored")

def show_system_status():
    """Show overall system status"""
    print_header("⚡ SYSTEM STATUS")
    
    # Backend status
    backend_running = check_backend_status()
    print(f"🖥️  Backend (Flask): {'✅ Running' if backend_running else '❌ Not Running'}")
    
    # Frontend status (check if port 5173 is in use)
    try:
        response = requests.get("http://localhost:5173", timeout=2)
        frontend_running = True
    except:
        frontend_running = False
    
    print(f"🌐 Frontend (Vite): {'✅ Running' if frontend_running else '❌ Not Running'}")
    
    # Database files
    db_files = ["file_events.db", "alerts.db"]
    for db_file in db_files:
        exists = os.path.exists(db_file)
        print(f"🗄️  {db_file}: {'✅ Exists' if exists else '❌ Missing'}")
    
    # Monitored directory
    monitor_exists = os.path.exists("./monitored")
    print(f"📂 Monitored directory: {'✅ Exists' if monitor_exists else '❌ Missing'}")
    
    print(f"\n🌐 Access URLs:")
    print(f"  • FME Sentinel Watch: http://localhost:5173")
    print(f"  • Traditional Dashboard: http://127.0.0.1:5000")

def monitor_continuously():
    """Monitor outputs continuously"""
    print("🔄 Starting continuous monitoring...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen
            
            print("🛡️  FME-ABT REAL-TIME OUTPUT MONITOR")
            print(f"⏰ Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            show_system_status()
            show_database_contents()
            show_monitored_directory()
            
            if check_backend_status():
                show_api_responses()
            
            show_log_files()
            
            print("\n" + "=" * 60)
            print("🔄 Refreshing in 10 seconds... (Ctrl+C to stop)")
            
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Monitoring stopped.")

def main():
    """Main function"""
    print("🛡️  FME-ABT Output Monitor")
    print("=" * 60)
    print("This tool shows all outputs from the FME-ABT detection system")
    print()
    
    choice = input("Choose monitoring mode:\n1. One-time snapshot\n2. Continuous monitoring\nEnter choice (1 or 2): ")
    
    if choice == "2":
        monitor_continuously()
    else:
        show_system_status()
        show_database_contents()
        show_monitored_directory()
        
        if check_backend_status():
            show_api_responses()
        
        show_log_files()
        
        print("\n" + "=" * 60)
        print("📊 Snapshot complete!")
        print("💡 Run 'python generate_test_data.py' to create test data")
        print("🔄 Run this script again to see updated outputs")

if __name__ == "__main__":
    main()
