"""
Test script for FME (File Monitoring Enhancement) entropy analysis
"""

import os
import sys
import tempfile
import random
import string

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fme import EntropyAnalyzer, analyze_file


def create_test_files():
    """
    Create test files with different entropy characteristics
    
    Returns:
        Dictionary mapping file types to file paths
    """
    test_files = {}
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Low entropy file (repeated text)
        low_entropy_file = os.path.join(temp_dir, "low_entropy.txt")
        with open(low_entropy_file, 'w') as f:
            f.write("A" * 1000 + "B" * 500 + "C" * 300)
        test_files['low_entropy'] = low_entropy_file
        
        # Medium entropy file (normal text)
        medium_entropy_file = os.path.join(temp_dir, "medium_entropy.txt")
        with open(medium_entropy_file, 'w') as f:
            f.write("This is a normal text file with regular English content. " * 50)
        test_files['medium_entropy'] = medium_entropy_file
        
        # High entropy file (random data simulating encryption)
        high_entropy_file = os.path.join(temp_dir, "high_entropy.bin")
        with open(high_entropy_file, 'wb') as f:
            random_data = bytes([random.randint(0, 255) for _ in range(2000)])
            f.write(random_data)
        test_files['high_entropy'] = high_entropy_file
        
        # Mixed entropy file (simulating entropy sharing)
        mixed_entropy_file = os.path.join(temp_dir, "mixed_entropy.bin")
        with open(mixed_entropy_file, 'wb') as f:
            # Low entropy start
            f.write(b'A' * 512)
            # High entropy middle
            random_middle = bytes([random.randint(0, 255) for _ in range(512)])
            f.write(random_middle)
            # Low entropy end
            f.write(b'B' * 512)
        test_files['mixed_entropy'] = mixed_entropy_file
        
        # Test each file type
        yield test_files


def test_entropy_calculation():
    """Test basic entropy calculation"""
    print("Testing entropy calculation...")
    
    analyzer = EntropyAnalyzer()
    
    # Test known entropy values
    test_cases = [
        (b'AAAAAAAA', "Low entropy (repeated bytes)"),
        (b'ABCDEFGH', "Medium entropy (sequential bytes)"),
        (bytes(range(256)), "High entropy (all byte values)")
    ]
    
    for data, description in test_cases:
        entropy = analyzer.calculate_shannon_entropy(data)
        print(f"  {description}: {entropy:.2f} bits")
    
    print("Entropy calculation test completed.\n")


def test_chi_square_calculation():
    """Test Chi-square calculation"""
    print("Testing Chi-square calculation...")
    
    analyzer = EntropyAnalyzer()
    
    # Test cases
    test_cases = [
        (b'A' * 256, "Uniform single byte"),
        (bytes(range(256)), "Sequential bytes"),
        (bytes([random.randint(0, 255) for _ in range(1000)]), "Random bytes")
    ]
    
    for data, description in test_cases:
        chi_square = analyzer.calculate_chi_square(data)
        print(f"  {description}: {chi_square:.2f}")
    
    print("Chi-square calculation test completed.\n")


def test_file_analysis():
    """Test complete file analysis"""
    print("Testing file analysis...")
    
    for test_files in create_test_files():
        analyzer = EntropyAnalyzer()
        
        for file_type, file_path in test_files.items():
            print(f"\nAnalyzing {file_type} file:")
            result = analyzer.analyze_file(file_path)
            
            print(f"  File: {os.path.basename(result['file_path'])}")
            print(f"  Segments: {result['segments_analyzed']}")
            print(f"  Entropies: {[f'{e:.2f}' for e in result['entropies']]}")
            print(f"  Mean entropy: {result['mean_entropy']:.2f}")
            print(f"  Entropy variance: {result['entropy_variance']:.2f}")
            print(f"  Chi-square: {result['chi_square']:.2f}")
            print(f"  Suspicious: {result['is_suspicious']}")
            if result['suspicion_reasons']:
                print(f"  Reasons: {', '.join(result['suspicion_reasons'])}")
            if result['error']:
                print(f"  Error: {result['error']}")
    
    print("\nFile analysis test completed.\n")


def test_threshold_adjustment():
    """Test threshold adjustment"""
    print("Testing threshold adjustment...")
    
    analyzer = EntropyAnalyzer()
    
    # Test default thresholds
    print(f"Default thresholds:")
    print(f"  Entropy: {analyzer.entropy_threshold}")
    print(f"  Variance: {analyzer.variance_threshold}")
    print(f"  Chi-square: {analyzer.chi_square_threshold}")
    
    # Adjust thresholds
    analyzer.set_thresholds(entropy=6.5, variance=0.3, chi_square=150)
    
    print(f"Updated thresholds:")
    print(f"  Entropy: {analyzer.entropy_threshold}")
    print(f"  Variance: {analyzer.variance_threshold}")
    print(f"  Chi-square: {analyzer.chi_square_threshold}")
    
    print("Threshold adjustment test completed.\n")


def test_segment_extraction():
    """Test file segment extraction"""
    print("Testing segment extraction...")
    
    analyzer = EntropyAnalyzer()
    
    # Create test file with known content
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        # Write 2000 bytes of known pattern
        temp_file.write(b'A' * 512)  # First segment
        temp_file.write(b'B' * 976)  # Middle padding
        temp_file.write(b'C' * 512)  # Last segment
        temp_file_path = temp_file.name
    
    try:
        segments = analyzer.get_file_segments(temp_file_path)
        print(f"  Extracted {len(segments)} segments")
        
        for i, segment in enumerate(segments):
            print(f"  Segment {i+1}: {len(segment)} bytes, starts with {segment[0]:02x}")
            
        # Verify segment content
        if len(segments) >= 2:
            if segments[0][0] == ord('A'):
                print("  ✓ First segment correct")
            else:
                print("  ✗ First segment incorrect")
                
            if segments[-1][0] == ord('C'):
                print("  ✓ Last segment correct")
            else:
                print("  ✗ Last segment incorrect")
    
    finally:
        os.unlink(temp_file_path)
    
    print("Segment extraction test completed.\n")


if __name__ == "__main__":
    test_entropy_calculation()
    test_chi_square_calculation()
    test_segment_extraction()
    test_file_analysis()
    test_threshold_adjustment()
