"""
Full integration test for Monitor + FME + ABT modules
"""

import os
import sys
import time
import tempfile
import random
import sqlite3

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor import FileMonitor
from fme import EntropyAnalyzer
from abt import BurstDetector


def create_baseline_activity(monitor_dir: str, duration_hours: int = 24) -> None:
    """
    Create baseline file activity to establish normal patterns
    
    Args:
        monitor_dir: Directory to create files in
        duration_hours: Hours of activity to simulate
    """
    print(f"  Creating {duration_hours} hours of baseline activity...")
    
    # Create some normal files with regular patterns
    for hour in range(duration_hours):
        # Simulate normal document editing
        if 9 <= (hour % 24) <= 17:  # Business hours
            for i in range(3):  # More activity during business hours
                file_path = os.path.join(monitor_dir, f"document_{hour}_{i}.txt")
                with open(file_path, 'w') as f:
                    f.write(f"Normal document content for hour {hour}, file {i}. " * 10)
                time.sleep(0.1)  # Small delay
        else:
            # Less activity outside business hours
            file_path = os.path.join(monitor_dir, f"evening_{hour}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Evening activity for hour {hour}. " * 5)
            time.sleep(0.1)


def simulate_ransomware_activity(monitor_dir: str) -> list:
    """
    Simulate ransomware-like activity patterns
    
    Args:
        monitor_dir: Directory to create files in
        
    Returns:
        List of created suspicious files
    """
    print("  Simulating ransomware-like activity...")
    
    suspicious_files = []
    
    # 1. High entropy files (simulating encryption)
    for i in range(5):
        file_path = os.path.join(monitor_dir, f"encrypted_{i}.dat")
        with open(file_path, 'wb') as f:
            # Generate high-entropy data
            random_data = bytes([random.randint(0, 255) for _ in range(2000)])
            f.write(random_data)
        suspicious_files.append(file_path)
        time.sleep(0.2)
    
    # 2. Entropy sharing pattern (mixed entropy)
    for i in range(3):
        file_path = os.path.join(monitor_dir, f"mixed_entropy_{i}.bin")
        with open(file_path, 'wb') as f:
            # Low entropy start
            f.write(b'A' * 600)
            # High entropy middle
            random_middle = bytes([random.randint(0, 255) for _ in range(800)])
            f.write(random_middle)
            # Low entropy end
            f.write(b'B' * 600)
        suspicious_files.append(file_path)
        time.sleep(0.2)
    
    # 3. Burst activity (many files quickly)
    print("  Creating burst activity...")
    for i in range(15):  # Many files in short time
        file_path = os.path.join(monitor_dir, f"burst_{i}.txt")
        with open(file_path, 'w') as f:
            f.write(f"Burst file {i} content. " * 20)
        suspicious_files.append(file_path)
        time.sleep(0.1)  # Very short delay = burst
    
    return suspicious_files


def test_full_integration():
    """
    Test complete integration of all modules
    """
    print("Testing full integration (Monitor + FME + ABT)...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_monitor_dir = os.path.join(temp_dir, "monitored")
        test_db_path = os.path.join(temp_dir, "events.db")
        
        # Initialize components
        monitor = FileMonitor(test_monitor_dir, test_db_path)
        entropy_analyzer = EntropyAnalyzer()
        burst_detector = BurstDetector(test_db_path)
        
        try:
            # Start monitoring
            monitor.start()
            time.sleep(1)
            
            # Phase 1: Create baseline activity
            create_baseline_activity(test_monitor_dir, 2)  # 2 hours of baseline
            time.sleep(2)  # Let monitoring catch up
            
            # Phase 2: Simulate ransomware activity
            suspicious_files = simulate_ransomware_activity(test_monitor_dir)
            time.sleep(3)  # Let analysis complete
            
            # Phase 3: Analyze results
            print("\n  Analysis Results:")
            
            # Check database for events
            recent_events = monitor.get_recent_events(1)
            print(f"    Total events captured: {len(recent_events)}")
            
            # Analyze suspicious files directly
            entropy_detections = 0
            burst_detections = 0
            
            print("\n    Entropy Analysis Results:")
            for file_path in suspicious_files[:8]:  # Check first 8 files
                if os.path.exists(file_path):
                    result = entropy_analyzer.analyze_file(file_path)
                    if result['is_suspicious']:
                        entropy_detections += 1
                        print(f"      ✓ SUSPICIOUS: {os.path.basename(file_path)}")
                        print(f"        Entropy: {result['mean_entropy']:.2f}, "
                              f"Variance: {result['entropy_variance']:.2f}")
                        print(f"        Reasons: {', '.join(result['suspicion_reasons'])}")
                    else:
                        print(f"      - Normal: {os.path.basename(file_path)}")
            
            print("\n    Burst Analysis Results:")
            for file_path in suspicious_files[-5:]:  # Check last 5 files (burst)
                if os.path.exists(file_path):
                    result = burst_detector.check_burst(file_path)
                    if result['is_burst']:
                        burst_detections += 1
                        print(f"      ✓ BURST: {os.path.basename(file_path)}")
                        print(f"        Rate: {result['current_rate']:.2f} events/hour, "
                              f"Threshold: {result['threshold']:.2f}")
                        print(f"        Burst factor: {result['burst_factor']:.2f}x")
                    else:
                        print(f"      - Normal: {os.path.basename(file_path)}")
            
            # Summary
            print(f"\n    Detection Summary:")
            print(f"      Entropy detections: {entropy_detections}")
            print(f"      Burst detections: {burst_detections}")
            print(f"      Total suspicious files: {len(suspicious_files)}")
            
            # Calculate detection rates
            entropy_rate = (entropy_detections / min(8, len(suspicious_files))) * 100
            burst_rate = (burst_detections / min(5, len(suspicious_files))) * 100
            
            print(f"      Entropy detection rate: {entropy_rate:.1f}%")
            print(f"      Burst detection rate: {burst_rate:.1f}%")
            
            # Check for false positives by analyzing some normal files
            print(f"\n    False Positive Check:")
            normal_files = [f for f in os.listdir(test_monitor_dir) 
                          if f.startswith('document_') and f.endswith('.txt')][:5]
            
            false_positives = 0
            for filename in normal_files:
                file_path = os.path.join(test_monitor_dir, filename)
                entropy_result = entropy_analyzer.analyze_file(file_path)
                burst_result = burst_detector.check_burst(file_path)
                
                if entropy_result['is_suspicious'] or burst_result['is_burst']:
                    false_positives += 1
                    print(f"      ✗ False positive: {filename}")
                else:
                    print(f"      ✓ Correctly normal: {filename}")
            
            fp_rate = (false_positives / len(normal_files)) * 100 if normal_files else 0
            print(f"      False positive rate: {fp_rate:.1f}%")
            
        finally:
            monitor.stop()
    
    print("Full integration test completed.\n")


def test_performance():
    """
    Test performance with larger datasets
    """
    print("Testing performance...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_monitor_dir = os.path.join(temp_dir, "perf_test")
        test_db_path = os.path.join(temp_dir, "perf_events.db")
        
        # Create many files quickly
        start_time = time.time()
        
        os.makedirs(test_monitor_dir, exist_ok=True)
        for i in range(100):
            file_path = os.path.join(test_monitor_dir, f"perf_test_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Performance test file {i}. " * 50)
        
        creation_time = time.time() - start_time
        
        # Test analysis performance
        analyzer = EntropyAnalyzer()
        detector = BurstDetector(test_db_path)
        
        analysis_start = time.time()
        
        for i in range(50):  # Analyze subset
            file_path = os.path.join(test_monitor_dir, f"perf_test_{i}.txt")
            if os.path.exists(file_path):
                analyzer.analyze_file(file_path)
                detector.check_burst(file_path)
        
        analysis_time = time.time() - analysis_start
        
        print(f"  Created 100 files in {creation_time:.2f} seconds")
        print(f"  Analyzed 50 files in {analysis_time:.2f} seconds")
        print(f"  Average analysis time: {(analysis_time/50)*1000:.1f} ms per file")
    
    print("Performance test completed.\n")


if __name__ == "__main__":
    test_full_integration()
    test_performance()
