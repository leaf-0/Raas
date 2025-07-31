"""
File Monitoring Enhancement (FME) Module for FME-ABT Detector

This module implements multi-segment entropy analysis with Chi-square tests
to detect encrypted/suspicious files based on entropy patterns.
"""

import os
import math
import statistics
from typing import Optional, Tuple, List
from collections import Counter

import scipy.stats as stats

from utils import setup_logger, log_error, safe_file_operation


class EntropyAnalyzer:
    """
    Analyzes file entropy across multiple segments to detect encryption patterns
    """
    
    def __init__(self):
        """Initialize the entropy analyzer"""
        self.logger = setup_logger(__name__)
        
        # Enhanced thresholds based on review
        self.entropy_threshold = 7.0      # Mean entropy threshold
        self.variance_threshold = 0.5     # Entropy variance threshold
        self.chi_square_threshold = 500   # Lowered from 1000 for better detection

        # Entropy sharing detection thresholds
        self.entropy_sharing_variance_threshold = 2.0  # High variance indicates sharing
        self.entropy_sharing_range_threshold = 4.0     # Large range between min/max entropy
        
    def calculate_shannon_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy for given data
        
        Args:
            data: Byte data to analyze
            
        Returns:
            Shannon entropy value (0-8 bits)
        """
        if not data:
            return 0.0
            
        # Count frequency of each byte value
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy: H = -Σ p(x) * log2(p(x))
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
    
    def get_dynamic_segments(self, file_path: str) -> List[bytes]:
        """
        Extract segments with dynamic sizing based on file length (10% of file size)
        - First segment
        - Middle segment
        - Last segment

        Args:
            file_path: Path to file to analyze

        Returns:
            List of byte segments with dynamic sizing
        """
        segments = []

        try:
            file_size = safe_file_operation(os.path.getsize, file_path)
            if not file_size or file_size == 0:
                return segments

            # Dynamic segment size: 10% of file length, minimum 256 bytes, maximum 2048 bytes
            segment_size = max(256, min(2048, int(file_size * 0.1)))

            def read_segments():
                with open(file_path, 'rb') as f:
                    segments_data = []

                    # First segment
                    first_segment = f.read(segment_size)
                    if first_segment:
                        segments_data.append(first_segment)

                    # Middle segment (if file is large enough)
                    if file_size > segment_size * 2:
                        middle_pos = (file_size - segment_size) // 2
                        f.seek(middle_pos)
                        middle_segment = f.read(segment_size)
                        if middle_segment:
                            segments_data.append(middle_segment)

                    # Last segment (if file is large enough and different from first)
                    if file_size > segment_size:
                        f.seek(max(0, file_size - segment_size))
                        last_segment = f.read(segment_size)
                        if last_segment and (len(segments_data) == 0 or last_segment != segments_data[0]):
                            segments_data.append(last_segment)

                    return segments_data

            segments = safe_file_operation(read_segments)
            if segments is None:
                segments = []

        except Exception as e:
            log_error(self.logger, e, f"Reading dynamic segments from {file_path}")

        return segments
    
    def calculate_optimized_chi_square(self, data: bytes) -> float:
        """
        Calculate optimized Chi-square test statistic for large files

        Args:
            data: Byte data to analyze

        Returns:
            Chi-square test statistic
        """
        if not data:
            return 0.0

        # For large datasets, use sampling to optimize performance
        if len(data) > 10000:
            # Sample every nth byte to maintain distribution characteristics
            sample_rate = len(data) // 5000
            sampled_data = data[::sample_rate]
        else:
            sampled_data = data

        # Count frequency of each byte value (0-255)
        byte_counts = [0] * 256
        for byte_val in sampled_data:
            byte_counts[byte_val] += 1

        # Expected frequency for uniform distribution
        expected_freq = len(sampled_data) / 256

        # Calculate chi-square statistic
        chi_square = 0.0
        for observed in byte_counts:
            if expected_freq > 0:
                chi_square += ((observed - expected_freq) ** 2) / expected_freq

        return chi_square

    def detect_entropy_sharing(self, entropies: List[float]) -> bool:
        """
        Detect entropy sharing patterns (mixed high/low entropy segments)

        Args:
            entropies: List of entropy values for different segments

        Returns:
            True if entropy sharing is detected
        """
        if len(entropies) < 2:
            return False

        # Calculate variance and range
        entropy_variance = statistics.variance(entropies)
        entropy_range = max(entropies) - min(entropies)

        # Check for entropy sharing indicators
        has_high_variance = entropy_variance > self.entropy_sharing_variance_threshold
        has_large_range = entropy_range > self.entropy_sharing_range_threshold

        # Additional check: mixed high and low entropy segments
        high_entropy_segments = sum(1 for e in entropies if e > 6.5)
        low_entropy_segments = sum(1 for e in entropies if e < 3.0)
        has_mixed_segments = high_entropy_segments > 0 and low_entropy_segments > 0

        return has_high_variance and (has_large_range or has_mixed_segments)
    
    def analyze_file(self, file_path: str) -> dict:
        """
        Perform complete entropy analysis on a file
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        result = {
            'file_path': file_path,
            'segments_analyzed': 0,
            'entropies': [],
            'mean_entropy': 0.0,
            'entropy_variance': 0.0,
            'entropy_range': 0.0,
            'chi_square': 0.0,
            'is_suspicious': False,
            'has_entropy_sharing': False,
            'suspicion_reasons': [],
            'confidence_score': 0.0,
            'error': None
        }

        try:
            # Get dynamic file segments
            segments = self.get_dynamic_segments(file_path)
            if not segments:
                result['error'] = "No readable segments found"
                return result
                
            result['segments_analyzed'] = len(segments)
            
            # Calculate entropy for each segment
            entropies = []
            combined_data = b''
            
            for segment in segments:
                entropy = self.calculate_shannon_entropy(segment)
                entropies.append(entropy)
                combined_data += segment
                
            result['entropies'] = entropies
            
            # Calculate statistics
            if entropies:
                result['mean_entropy'] = statistics.mean(entropies)
                if len(entropies) > 1:
                    result['entropy_variance'] = statistics.variance(entropies)
                    result['entropy_range'] = max(entropies) - min(entropies)
                else:
                    result['entropy_variance'] = 0.0
                    result['entropy_range'] = 0.0

            # Calculate optimized chi-square for combined segments
            if combined_data:
                result['chi_square'] = self.calculate_optimized_chi_square(combined_data)

            # Detect entropy sharing
            result['has_entropy_sharing'] = self.detect_entropy_sharing(entropies)

            # Enhanced suspicion detection with confidence scoring
            suspicion_reasons = []
            confidence_score = 0.0

            # High mean entropy (strong indicator)
            if result['mean_entropy'] > self.entropy_threshold:
                suspicion_reasons.append(f"High mean entropy: {result['mean_entropy']:.2f}")
                confidence_score += 0.4

            # High entropy variance (moderate indicator)
            if result['entropy_variance'] > self.variance_threshold:
                suspicion_reasons.append(f"High entropy variance: {result['entropy_variance']:.2f}")
                confidence_score += 0.2

            # High chi-square (moderate indicator)
            if result['chi_square'] > self.chi_square_threshold:
                suspicion_reasons.append(f"High chi-square: {result['chi_square']:.2f}")
                confidence_score += 0.2

            # Entropy sharing (strong indicator)
            if result['has_entropy_sharing']:
                suspicion_reasons.append(f"Entropy sharing detected (variance: {result['entropy_variance']:.2f})")
                confidence_score += 0.5

            result['suspicion_reasons'] = suspicion_reasons
            result['confidence_score'] = min(confidence_score, 1.0)

            # Relaxed suspicion criteria: one strong indicator OR multiple moderate indicators
            result['is_suspicious'] = (
                confidence_score >= 0.4 or  # One strong indicator
                len(suspicion_reasons) >= 2   # Multiple moderate indicators
            )

            self.logger.info(f"Analyzed {file_path}: entropy={result['mean_entropy']:.2f}, "
                           f"variance={result['entropy_variance']:.2f}, "
                           f"chi_square={result['chi_square']:.2f}, "
                           f"entropy_sharing={result['has_entropy_sharing']}, "
                           f"confidence={result['confidence_score']:.2f}, "
                           f"suspicious={result['is_suspicious']}")
                           
        except Exception as e:
            result['error'] = str(e)
            log_error(self.logger, e, f"Analyzing file {file_path}")
            
        return result
    
    def analyze_file_event(self, file_path: str) -> Optional[dict]:
        """
        Analyze a file and trigger alerts if suspicious
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Analysis result if suspicious, None otherwise
        """
        try:
            # Enhanced skip list with additional file types
            skip_extensions = {
                '.zip', '.rar', '.7z', '.gz', '.bz2', '.xz', '.tar',
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
                '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv',
                '.pdf', '.exe', '.dll', '.sys', '.msi',
                '.iso', '.img', '.vhd', '.vmdk'
            }

            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in skip_extensions:
                self.logger.debug(f"Skipping analysis for {file_path} (known high-entropy type: {file_ext})")
                return None

            # Analyze the file
            result = self.analyze_file(file_path)

            # Trigger alert if suspicious
            if result['is_suspicious']:
                self.logger.warning(f"Suspicious file detected: {file_path} "
                                  f"(confidence: {result['confidence_score']:.2f})")

                # Trigger alert through alert manager
                try:
                    from alert import get_alert_manager
                    alert_manager = get_alert_manager()
                    alert_manager.trigger_entropy_alert(result)
                except ImportError:
                    self.logger.warning("Alert module not available")
                    
                return result
                
        except Exception as e:
            log_error(self.logger, e, f"Analyzing file event for {file_path}")
            
        return None
    
    def set_thresholds(self, entropy: float = None, variance: float = None, 
                      chi_square: float = None) -> None:
        """
        Update detection thresholds
        
        Args:
            entropy: Mean entropy threshold
            variance: Entropy variance threshold
            chi_square: Chi-square threshold
        """
        if entropy is not None:
            self.entropy_threshold = entropy
            self.logger.info(f"Updated entropy threshold to {entropy}")
            
        if variance is not None:
            self.variance_threshold = variance
            self.logger.info(f"Updated variance threshold to {variance}")
            
        if chi_square is not None:
            self.chi_square_threshold = chi_square
            self.logger.info(f"Updated chi-square threshold to {chi_square}")


# Global analyzer instance
_analyzer = None

def get_analyzer() -> EntropyAnalyzer:
    """Get global entropy analyzer instance"""
    global _analyzer
    if _analyzer is None:
        _analyzer = EntropyAnalyzer()
    return _analyzer


def analyze_file(file_path: str) -> dict:
    """
    Convenience function to analyze a file
    
    Args:
        file_path: Path to file to analyze
        
    Returns:
        Analysis result dictionary
    """
    return get_analyzer().analyze_file(file_path)


def analyze_file_event(file_path: str) -> Optional[dict]:
    """
    Convenience function to analyze a file event
    
    Args:
        file_path: Path to file to analyze
        
    Returns:
        Analysis result if suspicious, None otherwise
    """
    return get_analyzer().analyze_file_event(file_path)
