"""
Test script for Flask UI Dashboard
Tests the web interface functionality and responsiveness
"""

import os
import sys
import time
import threading
import requests
import sqlite3
import tempfile
from datetime import datetime

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import DashboardApp


class UITester:
    """
    Test class for UI functionality
    """
    
    def __init__(self):
        self.base_url = "http://127.0.0.1:5000"
        self.app_thread = None
        self.dashboard_app = None
        
    def setup_test_data(self):
        """Create test data for UI testing"""
        print("Setting up test data...")
        
        # Create test events database
        events_db = "file_events.db"
        conn = sqlite3.connect(events_db)
        try:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    size INTEGER,
                    pid INTEGER,
                    process_name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insert test events
            current_time = time.time()
            test_events = [
                ("C:\\Users\\Test\\Documents\\test1.txt", "created", current_time - 3600, 1024, 1234, "notepad.exe"),
                ("C:\\Users\\Test\\Documents\\test2.txt", "modified", current_time - 1800, 2048, 1234, "notepad.exe"),
                ("C:\\Users\\Test\\Downloads\\suspicious.bin", "created", current_time - 900, 4096, 5678, "unknown.exe"),
                ("C:\\Users\\Test\\Desktop\\document.docx", "modified", current_time - 600, 8192, 2345, "winword.exe"),
                ("C:\\Users\\Test\\Temp\\temp_file.tmp", "deleted", current_time - 300, None, 3456, "system.exe"),
            ]
            
            for event in test_events:
                conn.execute('''
                    INSERT INTO file_events (path, event_type, timestamp, size, pid, process_name)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', event)
            
            conn.commit()
            print(f"  Created {len(test_events)} test events")
        finally:
            conn.close()
        
        # Create test alerts database
        alerts_db = "alerts.db"
        conn = sqlite3.connect(alerts_db)
        try:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    file_path TEXT,
                    process_id INTEGER,
                    process_name TEXT,
                    severity TEXT DEFAULT 'medium',
                    timestamp REAL NOT NULL,
                    action_taken TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insert test alerts
            test_alerts = [
                ("entropy", "High entropy detected in suspicious.bin", "C:\\Users\\Test\\Downloads\\suspicious.bin", 5678, "unknown.exe", "high", current_time - 900, None),
                ("burst", "Burst activity detected", "C:\\Users\\Test\\Documents\\", None, None, "medium", current_time - 600, None),
                ("vss_deletion", "Volume Shadow Copy deletion attempt", None, 7890, "vssadmin.exe", "critical", current_time - 300, "blocked"),
            ]
            
            for alert in test_alerts:
                conn.execute('''
                    INSERT INTO alerts (alert_type, message, file_path, process_id, process_name, severity, timestamp, action_taken)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', alert)
            
            conn.commit()
            print(f"  Created {len(test_alerts)} test alerts")
        finally:
            conn.close()
    
    def start_app(self):
        """Start the Flask application in a separate thread"""
        print("Starting Flask application...")
        
        self.dashboard_app = DashboardApp()
        
        def run_app():
            self.dashboard_app.run(host='127.0.0.1', port=5000, debug=False)
        
        self.app_thread = threading.Thread(target=run_app, daemon=True)
        self.app_thread.start()
        
        # Wait for app to start
        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                response = requests.get(f"{self.base_url}/api/config", timeout=1)
                if response.status_code == 200:
                    print("  Flask application started successfully")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(1)
        
        print("  Failed to start Flask application")
        return False
    
    def test_dashboard_page(self):
        """Test main dashboard page loads"""
        print("Testing dashboard page...")
        
        try:
            response = requests.get(self.base_url, timeout=10)
            
            if response.status_code == 200:
                print("  ✓ Dashboard page loads successfully")
                
                # Check for key elements in HTML
                content = response.text
                required_elements = [
                    "FME-ABT Detector",
                    "Total Events",
                    "Total Alerts",
                    "File Activity Trend",
                    "Burst Activity Heatmap",
                    "Recent File Events",
                    "Recent Alerts"
                ]
                
                missing_elements = []
                for element in required_elements:
                    if element not in content:
                        missing_elements.append(element)
                
                if missing_elements:
                    print(f"  ✗ Missing elements: {', '.join(missing_elements)}")
                    return False
                else:
                    print("  ✓ All required elements present")
                    return True
            else:
                print(f"  ✗ Dashboard page returned status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Error loading dashboard: {e}")
            return False
    
    def test_api_endpoints(self):
        """Test API endpoints"""
        print("Testing API endpoints...")
        
        endpoints = [
            ("/api/events", "events data"),
            ("/api/alerts", "alerts data"),
            ("/api/metrics", "metrics data"),
            ("/api/config", "configuration"),
            ("/api/charts/entropy-trend", "entropy trend chart"),
            ("/api/charts/burst-heatmap", "burst heatmap chart")
        ]
        
        results = []
        
        for endpoint, description in endpoints:
            try:
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success', False):
                        print(f"  ✓ {description} endpoint working")
                        results.append(True)
                    else:
                        print(f"  ✗ {description} endpoint returned error: {data.get('error', 'Unknown')}")
                        results.append(False)
                else:
                    print(f"  ✗ {description} endpoint returned status {response.status_code}")
                    results.append(False)
                    
            except Exception as e:
                print(f"  ✗ Error testing {description} endpoint: {e}")
                results.append(False)
        
        success_rate = (sum(results) / len(results)) * 100
        print(f"  API endpoints success rate: {success_rate:.1f}%")
        
        return success_rate >= 80  # 80% success rate required
    
    def test_threshold_tuning(self):
        """Test threshold tuning functionality"""
        print("Testing threshold tuning...")
        
        try:
            # Test updating thresholds
            new_thresholds = {
                "entropy_threshold": 6.5,
                "variance_threshold": 0.3,
                "chi_square_threshold": 800,
                "burst_multiplier": 2.5,
                "baseline_days": 14
            }
            
            response = requests.post(
                f"{self.base_url}/api/tune",
                json=new_thresholds,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success', False):
                    print("  ✓ Threshold tuning successful")
                    
                    # Verify the changes were applied
                    config_response = requests.get(f"{self.base_url}/api/config", timeout=10)
                    if config_response.status_code == 200:
                        config_data = config_response.json()
                        config = config_data.get('config', {})
                        
                        # Check if values were updated
                        if config.get('entropy_threshold') == 6.5:
                            print("  ✓ Threshold values updated correctly")
                            return True
                        else:
                            print("  ✗ Threshold values not updated correctly")
                            return False
                    else:
                        print("  ✗ Could not verify threshold updates")
                        return False
                else:
                    print(f"  ✗ Threshold tuning failed: {data.get('error', 'Unknown')}")
                    return False
            else:
                print(f"  ✗ Threshold tuning returned status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Error testing threshold tuning: {e}")
            return False
    
    def test_whitelist_management(self):
        """Test whitelist management functionality"""
        print("Testing whitelist management...")
        
        try:
            # Test adding to process whitelist
            whitelist_data = {
                "action": "add",
                "type": "process",
                "value": "test_process.exe"
            }
            
            response = requests.post(
                f"{self.base_url}/api/whitelist",
                json=whitelist_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success', False):
                    print("  ✓ Process whitelist management working")
                    
                    # Test directory whitelist
                    dir_whitelist_data = {
                        "action": "add",
                        "type": "directory",
                        "value": "C:\\Test\\Directory"
                    }
                    
                    dir_response = requests.post(
                        f"{self.base_url}/api/whitelist",
                        json=dir_whitelist_data,
                        timeout=10
                    )
                    
                    if dir_response.status_code == 200:
                        dir_data = dir_response.json()
                        if dir_data.get('success', False):
                            print("  ✓ Directory whitelist management working")
                            return True
                        else:
                            print(f"  ✗ Directory whitelist failed: {dir_data.get('error', 'Unknown')}")
                            return False
                    else:
                        print(f"  ✗ Directory whitelist returned status {dir_response.status_code}")
                        return False
                else:
                    print(f"  ✗ Process whitelist failed: {data.get('error', 'Unknown')}")
                    return False
            else:
                print(f"  ✗ Process whitelist returned status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Error testing whitelist management: {e}")
            return False
    
    def test_export_functionality(self):
        """Test dataset export functionality"""
        print("Testing export functionality...")
        
        try:
            response = requests.get(f"{self.base_url}/api/export", timeout=30)
            
            if response.status_code == 200:
                # Check if response is CSV
                content_type = response.headers.get('content-type', '')
                if 'csv' in content_type.lower() or len(response.content) > 0:
                    print("  ✓ Dataset export working")
                    print(f"  ✓ Export size: {len(response.content)} bytes")
                    return True
                else:
                    print("  ✗ Export did not return CSV data")
                    return False
            else:
                print(f"  ✗ Export returned status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Error testing export: {e}")
            return False
    
    def run_all_tests(self):
        """Run all UI tests"""
        print("=" * 50)
        print("FME-ABT Detector UI Test Suite")
        print("=" * 50)
        
        # Setup
        self.setup_test_data()
        
        if not self.start_app():
            print("Failed to start application. Aborting tests.")
            return False
        
        # Wait a bit for app to fully initialize
        time.sleep(3)
        
        # Run tests
        test_results = []
        
        test_results.append(("Dashboard Page", self.test_dashboard_page()))
        test_results.append(("API Endpoints", self.test_api_endpoints()))
        test_results.append(("Threshold Tuning", self.test_threshold_tuning()))
        test_results.append(("Whitelist Management", self.test_whitelist_management()))
        test_results.append(("Export Functionality", self.test_export_functionality()))
        
        # Summary
        print("\n" + "=" * 50)
        print("Test Results Summary:")
        print("=" * 50)
        
        passed = 0
        total = len(test_results)
        
        for test_name, result in test_results:
            status = "PASS" if result else "FAIL"
            print(f"{test_name:.<30} {status}")
            if result:
                passed += 1
        
        success_rate = (passed / total) * 100
        print(f"\nOverall Success Rate: {success_rate:.1f}% ({passed}/{total})")
        
        if success_rate >= 80:
            print("✓ UI tests PASSED")
            return True
        else:
            print("✗ UI tests FAILED")
            return False


def main():
    """Main test function"""
    tester = UITester()
    success = tester.run_all_tests()
    
    if success:
        print("\nAll UI tests completed successfully!")
        return 0
    else:
        print("\nSome UI tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    exit(main())
