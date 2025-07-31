"""
Integration test for monitor and FME modules
"""

import os
import sys
import time
import tempfile
import random

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor import FileMonitor
from fme import EntropyAnalyzer


def test_monitor_fme_integration():
    """
    Test integration between file monitor and entropy analysis
    """
    print("Testing monitor-FME integration...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_monitor_dir = os.path.join(temp_dir, "test_monitored")
        test_db_path = os.path.join(temp_dir, "test_events.db")
        
        # Initialize monitor
        monitor = FileMonitor(test_monitor_dir, test_db_path)
        
        try:
            # Start monitoring
            monitor.start()
            time.sleep(1)  # Give monitor time to start
            
            print("  Creating test files...")
            
            # Create normal text file
            normal_file = os.path.join(test_monitor_dir, "normal.txt")
            with open(normal_file, 'w') as f:
                f.write("This is a normal text file with regular content. " * 20)
            
            time.sleep(0.5)
            
            # Create high-entropy file (simulating encrypted file)
            encrypted_file = os.path.join(test_monitor_dir, "encrypted.bin")
            with open(encrypted_file, 'wb') as f:
                # Generate random data to simulate encryption
                random_data = bytes([random.randint(0, 255) for _ in range(2000)])
                f.write(random_data)
            
            time.sleep(0.5)
            
            # Create entropy-sharing file (mixed entropy pattern)
            mixed_file = os.path.join(test_monitor_dir, "mixed.dat")
            with open(mixed_file, 'wb') as f:
                # Low entropy start
                f.write(b'A' * 600)
                # High entropy middle  
                random_middle = bytes([random.randint(0, 255) for _ in range(800)])
                f.write(random_middle)
                # Low entropy end
                f.write(b'B' * 600)
            
            # Give time for analysis to complete
            time.sleep(3)
            
            print("  Files created and analyzed.")
            
            # Test direct entropy analysis
            print("\n  Direct entropy analysis results:")
            analyzer = EntropyAnalyzer()
            
            for file_path in [normal_file, encrypted_file, mixed_file]:
                if os.path.exists(file_path):
                    result = analyzer.analyze_file(file_path)
                    print(f"    {os.path.basename(file_path)}:")
                    print(f"      Mean entropy: {result['mean_entropy']:.2f}")
                    print(f"      Variance: {result['entropy_variance']:.2f}")
                    print(f"      Chi-square: {result['chi_square']:.2f}")
                    print(f"      Suspicious: {result['is_suspicious']}")
                    if result['suspicion_reasons']:
                        print(f"      Reasons: {', '.join(result['suspicion_reasons'])}")
            
            # Check recent events
            recent_events = monitor.get_recent_events(1)  # Last hour
            print(f"\n  Captured {len(recent_events)} file events")
            
            for event in recent_events:
                print(f"    {event['event_type']}: {os.path.basename(event['path'])}")
            
        finally:
            monitor.stop()
    
    print("Monitor-FME integration test completed.\n")


def test_entropy_thresholds():
    """
    Test different entropy threshold configurations
    """
    print("Testing entropy threshold configurations...")
    
    analyzer = EntropyAnalyzer()
    
    # Create test file with known characteristics
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        # Create file with medium-high entropy
        mixed_data = b'Hello World! ' * 50  # Some structure
        random_data = bytes([random.randint(0, 255) for _ in range(500)])  # Random data
        temp_file.write(mixed_data + random_data)
        temp_file_path = temp_file.name
    
    try:
        # Test with default thresholds
        print("  Default thresholds:")
        result1 = analyzer.analyze_file(temp_file_path)
        print(f"    Suspicious: {result1['is_suspicious']}")
        print(f"    Mean entropy: {result1['mean_entropy']:.2f}")
        print(f"    Variance: {result1['entropy_variance']:.2f}")
        
        # Test with stricter thresholds
        print("  Stricter thresholds:")
        analyzer.set_thresholds(entropy=6.0, variance=0.3, chi_square=500)
        result2 = analyzer.analyze_file(temp_file_path)
        print(f"    Suspicious: {result2['is_suspicious']}")
        
        # Test with more lenient thresholds
        print("  Lenient thresholds:")
        analyzer.set_thresholds(entropy=8.0, variance=1.0, chi_square=5000)
        result3 = analyzer.analyze_file(temp_file_path)
        print(f"    Suspicious: {result3['is_suspicious']}")
        
    finally:
        os.unlink(temp_file_path)
    
    print("Entropy threshold test completed.\n")


def test_file_type_filtering():
    """
    Test that certain file types are filtered from analysis
    """
    print("Testing file type filtering...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create files with extensions that should be skipped
        skip_files = [
            ("test.zip", b"PK\x03\x04" + bytes([random.randint(0, 255) for _ in range(1000)])),
            ("test.jpg", b"\xff\xd8\xff" + bytes([random.randint(0, 255) for _ in range(1000)])),
            ("test.exe", b"MZ" + bytes([random.randint(0, 255) for _ in range(1000)])),
        ]
        
        # Create files that should be analyzed
        analyze_files = [
            ("test.txt", b"Normal text content " * 50),
            ("test.dat", bytes([random.randint(0, 255) for _ in range(1000)])),
        ]
        
        from fme import analyze_file_event
        
        print("  Files that should be skipped:")
        for filename, content in skip_files:
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(content)
            
            result = analyze_file_event(file_path)
            print(f"    {filename}: {'Skipped' if result is None else 'Analyzed'}")
        
        print("  Files that should be analyzed:")
        for filename, content in analyze_files:
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(content)
            
            result = analyze_file_event(file_path)
            print(f"    {filename}: {'Analyzed' if result is not None else 'Skipped'}")
    
    print("File type filtering test completed.\n")


if __name__ == "__main__":
    test_entropy_thresholds()
    test_file_type_filtering()
    test_monitor_fme_integration()
