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
        
        # Thresholds for suspicious file detection
        self.entropy_threshold = 7.0      # Mean entropy threshold
        self.variance_threshold = 0.5     # Entropy variance threshold
        self.chi_square_threshold = 1000  # Chi-square test threshold (adjusted for real-world data)
        
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
    
    def get_file_segments(self, file_path: str, segment_size: int = 512) -> List[bytes]:
        """
        Extract three non-contiguous segments from file:
        - First 512 bytes
        - Middle 512 bytes  
        - Last 512 bytes
        
        Args:
            file_path: Path to file to analyze
            segment_size: Size of each segment in bytes
            
        Returns:
            List of byte segments (may be fewer than 3 for small files)
        """
        segments = []
        
        try:
            file_size = safe_file_operation(os.path.getsize, file_path)
            if not file_size or file_size == 0:
                return segments
                
            with open(file_path, 'rb') as f:
                # First segment
                first_segment = f.read(segment_size)
                if first_segment:
                    segments.append(first_segment)
                
                # Middle segment (if file is large enough)
                if file_size > segment_size * 2:
                    middle_pos = (file_size - segment_size) // 2
                    f.seek(middle_pos)
                    middle_segment = f.read(segment_size)
                    if middle_segment:
                        segments.append(middle_segment)
                
                # Last segment (if file is large enough and different from first)
                if file_size > segment_size:
                    f.seek(max(0, file_size - segment_size))
                    last_segment = f.read(segment_size)
                    if last_segment and len(segments) == 0 or last_segment != segments[0]:
                        segments.append(last_segment)
                        
        except Exception as e:
            log_error(self.logger, e, f"Reading file segments from {file_path}")
            
        return segments
    
    def calculate_chi_square(self, data: bytes) -> float:
        """
        Calculate Chi-square test statistic for byte distribution
        
        Args:
            data: Byte data to analyze
            
        Returns:
            Chi-square test statistic
        """
        if not data:
            return 0.0
            
        # Count frequency of each byte value (0-255)
        byte_counts = [0] * 256
        for byte_val in data:
            byte_counts[byte_val] += 1
            
        # Expected frequency for uniform distribution
        expected_freq = len(data) / 256
        
        # Calculate chi-square statistic
        chi_square = 0.0
        for observed in byte_counts:
            if expected_freq > 0:
                chi_square += ((observed - expected_freq) ** 2) / expected_freq
                
        return chi_square
    
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
            'chi_square': 0.0,
            'is_suspicious': False,
            'suspicion_reasons': [],
            'error': None
        }
        
        try:
            # Get file segments
            segments = self.get_file_segments(file_path)
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
                else:
                    result['entropy_variance'] = 0.0
                    
            # Calculate chi-square for combined segments
            if combined_data:
                result['chi_square'] = self.calculate_chi_square(combined_data)
                
            # Determine if file is suspicious
            suspicion_reasons = []
            
            if result['mean_entropy'] > self.entropy_threshold:
                suspicion_reasons.append(f"High mean entropy: {result['mean_entropy']:.2f}")
                
            if result['entropy_variance'] > self.variance_threshold:
                suspicion_reasons.append(f"High entropy variance: {result['entropy_variance']:.2f}")
                
            if result['chi_square'] > self.chi_square_threshold:
                suspicion_reasons.append(f"High chi-square: {result['chi_square']:.2f}")
                
            result['suspicion_reasons'] = suspicion_reasons
            result['is_suspicious'] = len(suspicion_reasons) >= 2  # Require at least 2 indicators
            
            self.logger.info(f"Analyzed {file_path}: entropy={result['mean_entropy']:.2f}, "
                           f"variance={result['entropy_variance']:.2f}, "
                           f"chi_square={result['chi_square']:.2f}, "
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
            # Skip analysis for certain file types that are expected to have high entropy
            skip_extensions = {'.zip', '.rar', '.7z', '.gz', '.bz2', '.xz', 
                             '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', 
                             '.avi', '.mkv', '.pdf', '.exe', '.dll'}
            
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in skip_extensions:
                self.logger.debug(f"Skipping analysis for {file_path} (known high-entropy type)")
                return None
                
            # Analyze the file
            result = analyze_result = self.analyze_file(file_path)
            
            # Trigger alert if suspicious
            if result['is_suspicious']:
                self.logger.warning(f"Suspicious file detected: {file_path}")
                
                # Import here to avoid circular imports
                try:
                    from alert import AlertManager
                    alert_manager = AlertManager()
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
