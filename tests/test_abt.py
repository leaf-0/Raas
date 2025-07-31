"""
Test script for ABT (Adaptive Burst Threshold) module
"""

import os
import sys
import time
import sqlite3
import tempfile
from datetime import datetime, timedelta

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from abt import BurstDetector


def create_test_database_with_events(db_path: str, events: list) -> None:
    """
    Create test database with predefined events
    
    Args:
        db_path: Path to database file
        events: List of event dictionaries
    """
    conn = sqlite3.connect(db_path)
    try:
        # Create table
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
        
        # Insert events
        for event in events:
            conn.execute('''
                INSERT INTO file_events (path, event_type, timestamp, size, pid, process_name)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                event['path'],
                event['event_type'],
                event['timestamp'],
                event.get('size'),
                event.get('pid'),
                event.get('process_name')
            ))
        
        conn.commit()
    finally:
        conn.close()


def test_directory_categorization():
    """Test directory categorization"""
    print("Testing directory categorization...")
    
    detector = BurstDetector()
    
    test_paths = [
        ("C:\\Users\\John\\Documents\\test.txt", "documents"),
        ("C:\\Users\\John\\Desktop\\file.doc", "desktop"),
        ("C:\\Users\\John\\Downloads\\archive.zip", "downloads"),
        ("C:\\Windows\\Temp\\temp.dat", "temp"),
        ("C:\\ProgramData\\app\\config.ini", "system"),
        ("C:\\SomeOther\\Path\\file.txt", "other"),
    ]
    
    for path, expected in test_paths:
        result = detector._get_directory_category(path)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {path} -> {result} (expected: {expected})")
    
    print("Directory categorization test completed.\n")


def test_file_type_categorization():
    """Test file type categorization"""
    print("Testing file type categorization...")
    
    detector = BurstDetector()
    
    test_files = [
        ("document.txt", "documents"),
        ("image.jpg", "images"),
        ("archive.zip", "archives"),
        ("program.exe", "executables"),
        ("data.dat", "data"),
        ("unknown.xyz", "other"),
    ]
    
    for filename, expected in test_files:
        result = detector._get_file_type_category(filename)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {filename} -> {result} (expected: {expected})")
    
    print("File type categorization test completed.\n")


def test_time_adjustments():
    """Test time-based adjustments"""
    print("Testing time adjustments...")
    
    detector = BurstDetector()
    
    # Test different times
    test_times = [
        (datetime(2024, 1, 15, 2, 0), "Night (2 AM Monday)"),    # Low activity
        (datetime(2024, 1, 15, 14, 0), "Business (2 PM Monday)"), # High activity
        (datetime(2024, 1, 20, 14, 0), "Weekend (2 PM Saturday)"), # Weekend
    ]
    
    for dt, description in test_times:
        timestamp = dt.timestamp()
        adjustment = detector._get_time_adjustment(timestamp)
        print(f"  {description}: {adjustment:.2f}x")
    
    print("Time adjustment test completed.\n")


def test_baseline_calculation():
    """Test baseline calculation"""
    print("Testing baseline calculation...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "test_abt.db")
        
        # Create events over several days
        current_time = time.time()
        events = []
        
        # Generate normal activity pattern
        for day in range(7):  # 7 days of history
            day_start = current_time - ((7 - day) * 24 * 3600)
            
            # Add events throughout the day
            for hour in range(24):
                hour_time = day_start + (hour * 3600)
                
                # More events during business hours
                event_count = 5 if 9 <= hour <= 17 else 2
                
                for i in range(event_count):
                    events.append({
                        'path': f'C:\\Users\\Test\\Documents\\file_{day}_{hour}_{i}.txt',
                        'event_type': 'modified',
                        'timestamp': hour_time + (i * 300),  # Spread within hour
                        'size': 1000,
                        'pid': 1234,
                        'process_name': 'test.exe'
                    })
        
        # Create database with events
        create_test_database_with_events(db_path, events)
        
        # Test baseline calculation
        detector = BurstDetector(db_path)
        detector._update_baselines()
        
        print(f"  Generated {len(events)} events over 7 days")
        print(f"  Calculated {len(detector._baseline_cache)} baselines:")
        
        for category, baseline in detector._baseline_cache.items():
            print(f"    {category}: {baseline:.2f} events/hour")
    
    print("Baseline calculation test completed.\n")


def test_burst_detection():
    """Test burst detection"""
    print("Testing burst detection...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "test_burst.db")
        
        current_time = time.time()
        events = []
        
        # Create normal baseline activity (low rate)
        for i in range(50):
            events.append({
                'path': 'C:\\Users\\Test\\Documents\\normal.txt',
                'event_type': 'modified',
                'timestamp': current_time - (7 * 24 * 3600) + (i * 3600),  # Spread over week
                'size': 1000,
                'pid': 1234,
                'process_name': 'normal.exe'
            })
        
        # Create burst activity (high rate in recent window)
        burst_start = current_time - 1800  # 30 minutes ago
        for i in range(20):  # Many events in short time
            events.append({
                'path': 'C:\\Users\\Test\\Documents\\burst.txt',
                'event_type': 'modified',
                'timestamp': burst_start + (i * 60),  # One per minute
                'size': 1000,
                'pid': 5678,
                'process_name': 'suspicious.exe'
            })
        
        # Create database with events
        create_test_database_with_events(db_path, events)
        
        # Test burst detection
        detector = BurstDetector(db_path)
        
        # Check normal file (should not be burst)
        normal_result = detector.check_burst('C:\\Users\\Test\\Documents\\normal.txt')
        print(f"  Normal file burst check:")
        print(f"    Rate: {normal_result['current_rate']:.2f} events/hour")
        print(f"    Threshold: {normal_result['threshold']:.2f}")
        print(f"    Is burst: {normal_result['is_burst']}")
        
        # Check burst file (should be burst)
        burst_result = detector.check_burst('C:\\Users\\Test\\Documents\\burst.txt')
        print(f"  Burst file check:")
        print(f"    Rate: {burst_result['current_rate']:.2f} events/hour")
        print(f"    Threshold: {burst_result['threshold']:.2f}")
        print(f"    Is burst: {burst_result['is_burst']}")
        print(f"    Burst factor: {burst_result['burst_factor']:.2f}x")
    
    print("Burst detection test completed.\n")


def test_threshold_adjustment():
    """Test threshold adjustment"""
    print("Testing threshold adjustment...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "test_thresholds.db")
        detector = BurstDetector(db_path)
        
        # Test default values
        print(f"  Default multiplier: {detector.threshold_multiplier}")
        print(f"  Default baseline days: {detector.baseline_days}")
        
        # Adjust thresholds
        detector.set_thresholds(multiplier=2.5, baseline_days=14)
        
        print(f"  Updated multiplier: {detector.threshold_multiplier}")
        print(f"  Updated baseline days: {detector.baseline_days}")
    
    print("Threshold adjustment test completed.\n")


if __name__ == "__main__":
    test_directory_categorization()
    test_file_type_categorization()
    test_time_adjustments()
    test_baseline_calculation()
    test_burst_detection()
    test_threshold_adjustment()
