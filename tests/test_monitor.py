"""
Test script for file monitoring functionality
"""

import os
import sys
import time
import sqlite3
import tempfile
from pathlib import Path

# Add parent directory to path to import monitor
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor import FileMonitor


def test_file_monitoring():
    """
    Test basic file monitoring functionality
    """
    print("Testing file monitoring...")
    
    # Create temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        test_monitor_dir = os.path.join(temp_dir, "test_monitored")
        test_db_path = os.path.join(temp_dir, "test_events.db")
        
        # Initialize monitor
        monitor = FileMonitor(test_monitor_dir, test_db_path)
        
        try:
            # Start monitoring
            monitor.start()
            time.sleep(1)  # Give monitor time to start
            
            # Create test file
            test_file = os.path.join(test_monitor_dir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("Hello, World!")
            
            # Modify test file
            time.sleep(0.5)
            with open(test_file, 'a') as f:
                f.write("\nModified content")
            
            # Delete test file
            time.sleep(0.5)
            os.remove(test_file)
            
            # Give time for events to be processed
            time.sleep(2)
            
            # Check database for events
            conn = sqlite3.connect(test_db_path)
            try:
                cursor = conn.execute("SELECT * FROM file_events ORDER BY timestamp")
                events = cursor.fetchall()

                print(f"Captured {len(events)} events:")
                for event in events:
                    print(f"  {event[2]}: {event[1]} - {os.path.basename(event[1])}")

                # Verify we captured the expected events
                event_types = [event[2] for event in events]
                expected_events = ['created', 'modified', 'deleted']

                for expected in expected_events:
                    if expected in event_types:
                        print(f"✓ {expected} event captured")
                    else:
                        print(f"✗ {expected} event missing")
            finally:
                conn.close()
            
        finally:
            monitor.stop()
    
    print("File monitoring test completed.\n")


def test_database_structure():
    """
    Test database structure and functionality
    """
    print("Testing database structure...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_db_path = os.path.join(temp_dir, "test_structure.db")

        # Create monitor to initialize database
        monitor = FileMonitor(temp_dir, test_db_path)
        # Initialize the event handler to create the database
        from monitor import FileEventHandler
        handler = FileEventHandler(test_db_path)
        
        # Check database structure
        conn = sqlite3.connect(test_db_path)
        try:
            cursor = conn.execute("PRAGMA table_info(file_events)")
            columns = cursor.fetchall()

            expected_columns = ['id', 'path', 'event_type', 'timestamp', 'size', 'pid', 'process_name', 'created_at']
            actual_columns = [col[1] for col in columns]

            print(f"Database columns: {actual_columns}")

            for expected in expected_columns:
                if expected in actual_columns:
                    print(f"✓ Column '{expected}' exists")
                else:
                    print(f"✗ Column '{expected}' missing")

            # Check indexes
            cursor = conn.execute("PRAGMA index_list(file_events)")
            indexes = cursor.fetchall()
            print(f"Database indexes: {[idx[1] for idx in indexes]}")
        finally:
            conn.close()
    
    print("Database structure test completed.\n")


if __name__ == "__main__":
    test_database_structure()
    test_file_monitoring()
