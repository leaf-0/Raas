"""
Test script for Enhanced FME Module
Tests the improved entropy analysis with dynamic segments and entropy sharing detection
"""

import os
import sys
import tempfile
import random

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fme import EntropyAnalyzer


def test_dynamic_segments():
    """Test dynamic segment sizing"""
    print("Testing dynamic segment sizing...")
    
    analyzer = EntropyAnalyzer()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Test small file (should use minimum segment size)
        small_file = os.path.join(temp_dir, "small.txt")
        with open(small_file, 'w') as f:
            f.write("Small file content" * 10)  # ~180 bytes
        
        segments = analyzer.get_dynamic_segments(small_file)
        print(f"  Small file ({os.path.getsize(small_file)} bytes): {len(segments)} segments")
        
        # Test medium file (should use 10% of file size)
        medium_file = os.path.join(temp_dir, "medium.txt")
        with open(medium_file, 'w') as f:
            f.write("Medium file content with more data " * 200)  # ~6KB
        
        segments = analyzer.get_dynamic_segments(medium_file)
        print(f"  Medium file ({os.path.getsize(medium_file)} bytes): {len(segments)} segments")
        
        # Test large file (should use maximum segment size)
        large_file = os.path.join(temp_dir, "large.txt")
        with open(large_file, 'w') as f:
            f.write("Large file with lots of content " * 2000)  # ~60KB
        
        segments = analyzer.get_dynamic_segments(large_file)
        print(f"  Large file ({os.path.getsize(large_file)} bytes): {len(segments)} segments")
    
    print("Dynamic segment sizing test completed.\n")


def test_entropy_sharing_detection():
    """Test entropy sharing detection"""
    print("Testing entropy sharing detection...")
    
    analyzer = EntropyAnalyzer()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create file with entropy sharing pattern
        sharing_file = os.path.join(temp_dir, "entropy_sharing.bin")
        with open(sharing_file, 'wb') as f:
            # Low entropy start (repeated bytes)
            f.write(b'A' * 1000)
            # High entropy middle (random bytes)
            random_data = bytes([random.randint(0, 255) for _ in range(1000)])
            f.write(random_data)
            # Low entropy end (repeated bytes)
            f.write(b'B' * 1000)
        
        result = analyzer.analyze_file(sharing_file)
        
        print(f"  Entropy sharing file:")
        print(f"    Entropies: {[f'{e:.2f}' for e in result['entropies']]}")
        print(f"    Mean entropy: {result['mean_entropy']:.2f}")
        print(f"    Entropy variance: {result['entropy_variance']:.2f}")
        print(f"    Entropy range: {result['entropy_range']:.2f}")
        print(f"    Has entropy sharing: {result['has_entropy_sharing']}")
        print(f"    Is suspicious: {result['is_suspicious']}")
        print(f"    Confidence score: {result['confidence_score']:.2f}")
        print(f"    Reasons: {result['suspicion_reasons']}")
        
        # Create uniform high entropy file (should not trigger entropy sharing)
        uniform_file = os.path.join(temp_dir, "uniform_high.bin")
        with open(uniform_file, 'wb') as f:
            # All high entropy
            for _ in range(3):
                random_data = bytes([random.randint(0, 255) for _ in range(1000)])
                f.write(random_data)
        
        result2 = analyzer.analyze_file(uniform_file)
        
        print(f"\n  Uniform high entropy file:")
        print(f"    Entropies: {[f'{e:.2f}' for e in result2['entropies']]}")
        print(f"    Mean entropy: {result2['mean_entropy']:.2f}")
        print(f"    Entropy variance: {result2['entropy_variance']:.2f}")
        print(f"    Has entropy sharing: {result2['has_entropy_sharing']}")
        print(f"    Is suspicious: {result2['is_suspicious']}")
        print(f"    Confidence score: {result2['confidence_score']:.2f}")
    
    print("Entropy sharing detection test completed.\n")


def test_optimized_chi_square():
    """Test optimized chi-square calculation"""
    print("Testing optimized chi-square calculation...")
    
    analyzer = EntropyAnalyzer()
    
    # Test with small data
    small_data = b'A' * 500
    chi_small = analyzer.calculate_optimized_chi_square(small_data)
    print(f"  Small data (500 bytes): Chi-square = {chi_small:.2f}")
    
    # Test with large data (should use sampling)
    large_data = b'A' * 50000
    chi_large = analyzer.calculate_optimized_chi_square(large_data)
    print(f"  Large data (50KB): Chi-square = {chi_large:.2f}")
    
    # Test with random data
    random_data = bytes([random.randint(0, 255) for _ in range(10000)])
    chi_random = analyzer.calculate_optimized_chi_square(random_data)
    print(f"  Random data (10KB): Chi-square = {chi_random:.2f}")
    
    print("Optimized chi-square test completed.\n")


def test_enhanced_suspicion_criteria():
    """Test enhanced suspicion criteria with confidence scoring"""
    print("Testing enhanced suspicion criteria...")
    
    analyzer = EntropyAnalyzer()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Test cases with different suspicion levels
        test_cases = [
            ("normal.txt", "Normal text content " * 100, "Normal file"),
            ("high_entropy.bin", bytes([random.randint(0, 255) for _ in range(2000)]), "High entropy file"),
            ("mixed_entropy.bin", b'A' * 600 + bytes([random.randint(0, 255) for _ in range(800)]) + b'B' * 600, "Mixed entropy file")
        ]
        
        for filename, content, description in test_cases:
            file_path = os.path.join(temp_dir, filename)
            
            if isinstance(content, str):
                with open(file_path, 'w') as f:
                    f.write(content)
            else:
                with open(file_path, 'wb') as f:
                    f.write(content)
            
            result = analyzer.analyze_file(file_path)
            
            print(f"  {description}:")
            print(f"    Mean entropy: {result['mean_entropy']:.2f}")
            print(f"    Confidence score: {result['confidence_score']:.2f}")
            print(f"    Is suspicious: {result['is_suspicious']}")
            print(f"    Reasons: {len(result['suspicion_reasons'])} indicators")
            for reason in result['suspicion_reasons']:
                print(f"      - {reason}")
            print()
    
    print("Enhanced suspicion criteria test completed.\n")


def test_threshold_adjustment():
    """Test threshold adjustment functionality"""
    print("Testing threshold adjustment...")
    
    analyzer = EntropyAnalyzer()
    
    # Test default thresholds
    print(f"  Default thresholds:")
    print(f"    Entropy: {analyzer.entropy_threshold}")
    print(f"    Variance: {analyzer.variance_threshold}")
    print(f"    Chi-square: {analyzer.chi_square_threshold}")
    
    # Adjust thresholds
    analyzer.set_thresholds(entropy=6.5, variance=0.3, chi_square=400)
    
    print(f"  Updated thresholds:")
    print(f"    Entropy: {analyzer.entropy_threshold}")
    print(f"    Variance: {analyzer.variance_threshold}")
    print(f"    Chi-square: {analyzer.chi_square_threshold}")
    
    print("Threshold adjustment test completed.\n")


def test_skip_extensions():
    """Test enhanced skip extensions"""
    print("Testing enhanced skip extensions...")
    
    analyzer = EntropyAnalyzer()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Test files that should be skipped
        skip_files = [
            "test.zip", "test.jpg", "test.mp4", "test.exe", 
            "test.iso", "test.vmdk", "test.tiff"
        ]
        
        for filename in skip_files:
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(b"test content")
            
            result = analyzer.analyze_file_event(file_path)
            status = "Skipped" if result is None else "Analyzed"
            print(f"  {filename}: {status}")
    
    print("Skip extensions test completed.\n")


def main():
    """Run all enhanced FME tests"""
    print("=" * 60)
    print("Enhanced FME Module Test Suite")
    print("=" * 60)
    
    test_dynamic_segments()
    test_entropy_sharing_detection()
    test_optimized_chi_square()
    test_enhanced_suspicion_criteria()
    test_threshold_adjustment()
    test_skip_extensions()
    
    print("All enhanced FME tests completed successfully!")


if __name__ == "__main__":
    main()
