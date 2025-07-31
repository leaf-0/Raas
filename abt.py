"""
Adaptive Burst Threshold (ABT) Module for FME-ABT Detector

This module implements granular adaptive burst detection with per-directory
and per-file-type baselines, adjusting for time-of-day and day-of-week patterns.
"""

import os
import sqlite3
import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, Counter
from pathlib import Path

from utils import setup_logger, log_error, get_timestamp


class BurstDetector:
    """
    Detects burst patterns in file modification activity using adaptive thresholds
    """
    
    def __init__(self, db_path: str = "file_events.db"):
        """
        Initialize burst detector
        
        Args:
            db_path: Path to SQLite database with file events
        """
        self.logger = setup_logger(__name__)
        self.db_path = db_path
        
        # Configuration
        self.baseline_days = 7          # Days to calculate baseline
        self.threshold_multiplier = 3.0 # Multiplier for burst threshold
        self.update_interval = 3600     # Update baselines every hour (seconds)
        self.min_events_for_baseline = 5  # Minimum events needed for reliable baseline
        
        # Time-of-day multipliers (24 hours)
        self.time_multipliers = self._get_default_time_multipliers()
        
        # Day-of-week multipliers (0=Monday, 6=Sunday)
        self.day_multipliers = self._get_default_day_multipliers()
        
        # Cache for baselines
        self._baseline_cache = {}
        self._last_update = 0
        
    def _get_default_time_multipliers(self) -> List[float]:
        """
        Get default time-of-day multipliers
        Higher during business hours (9 AM - 5 PM)
        
        Returns:
            List of 24 hourly multipliers
        """
        multipliers = [0.5] * 24  # Low activity at night
        
        # Higher activity during business hours
        for hour in range(9, 17):  # 9 AM to 5 PM
            multipliers[hour] = 1.5
            
        # Moderate activity in evening
        for hour in range(17, 22):  # 5 PM to 10 PM
            multipliers[hour] = 1.0
            
        return multipliers
    
    def _get_default_day_multipliers(self) -> List[float]:
        """
        Get default day-of-week multipliers
        Higher on weekdays, lower on weekends
        
        Returns:
            List of 7 daily multipliers (Monday=0, Sunday=6)
        """
        return [1.2, 1.2, 1.2, 1.2, 1.2, 0.8, 0.8]  # Weekdays higher, weekends lower
    
    def _get_directory_category(self, file_path: str) -> str:
        """
        Categorize directory for baseline calculation
        
        Args:
            file_path: Full file path
            
        Returns:
            Directory category string
        """
        path_obj = Path(file_path)
        path_parts = path_obj.parts
        
        # Common directory categories
        if any(part.lower() in ['documents', 'document'] for part in path_parts):
            return 'documents'
        elif any(part.lower() in ['desktop'] for part in path_parts):
            return 'desktop'
        elif any(part.lower() in ['downloads', 'download'] for part in path_parts):
            return 'downloads'
        elif any(part.lower() in ['temp', 'tmp', 'temporary'] for part in path_parts):
            return 'temp'
        elif any(part.lower() in ['appdata', 'programdata'] for part in path_parts):
            return 'system'
        else:
            return 'other'
    
    def _get_file_type_category(self, file_path: str) -> str:
        """
        Categorize file type for baseline calculation
        
        Args:
            file_path: Full file path
            
        Returns:
            File type category string
        """
        extension = Path(file_path).suffix.lower()
        
        # Document types
        if extension in ['.txt', '.doc', '.docx', '.pdf', '.rtf']:
            return 'documents'
        # Image types
        elif extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return 'images'
        # Archive types
        elif extension in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            return 'archives'
        # Executable types
        elif extension in ['.exe', '.dll', '.sys', '.msi']:
            return 'executables'
        # Data types
        elif extension in ['.dat', '.bin', '.tmp', '.log']:
            return 'data'
        else:
            return 'other'
    
    def _calculate_baseline(self, events: List[dict], category_key: str) -> float:
        """
        Calculate baseline modification rate for a category
        
        Args:
            events: List of file events
            category_key: Category identifier
            
        Returns:
            Baseline events per hour
        """
        if len(events) < self.min_events_for_baseline:
            return 1.0  # Default baseline
            
        # Group events by hour
        hourly_counts = defaultdict(int)
        
        for event in events:
            timestamp = event['timestamp']
            hour_key = int(timestamp // 3600)  # Hour since epoch
            hourly_counts[hour_key] += 1
            
        if not hourly_counts:
            return 1.0
            
        # Calculate average events per hour
        counts = list(hourly_counts.values())
        baseline = statistics.mean(counts)
        
        self.logger.debug(f"Calculated baseline for {category_key}: {baseline:.2f} events/hour")
        return max(baseline, 0.1)  # Minimum baseline
    
    def _get_time_adjustment(self, timestamp: float) -> float:
        """
        Get time-based adjustment factor
        
        Args:
            timestamp: Unix timestamp
            
        Returns:
            Adjustment multiplier
        """
        dt = datetime.fromtimestamp(timestamp)
        hour_multiplier = self.time_multipliers[dt.hour]
        day_multiplier = self.day_multipliers[dt.weekday()]
        
        return hour_multiplier * day_multiplier
    
    def _update_baselines(self) -> None:
        """
        Update baseline calculations from database
        """
        try:
            current_time = time.time()

            # Check if update is needed
            if current_time - self._last_update < self.update_interval:
                return

            self.logger.info("Updating burst detection baselines...")

            # Get events from the last baseline_days
            cutoff_time = current_time - (self.baseline_days * 24 * 3600)

            conn = sqlite3.connect(self.db_path)
            try:
                conn.row_factory = sqlite3.Row

                # Check if table exists
                cursor = conn.execute('''
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='file_events'
                ''')
                if not cursor.fetchone():
                    self.logger.debug("file_events table does not exist yet")
                    return

                cursor = conn.execute('''
                    SELECT * FROM file_events
                    WHERE timestamp > ? AND event_type = 'modified'
                    ORDER BY timestamp
                ''', (cutoff_time,))

                events = [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()
                
            if not events:
                self.logger.warning("No events found for baseline calculation")
                return
                
            # Group events by directory and file type
            dir_events = defaultdict(list)
            type_events = defaultdict(list)
            
            for event in events:
                file_path = event['path']
                dir_category = self._get_directory_category(file_path)
                type_category = self._get_file_type_category(file_path)
                
                dir_events[dir_category].append(event)
                type_events[type_category].append(event)
            
            # Calculate baselines
            new_baselines = {}
            
            # Directory baselines
            for dir_cat, dir_event_list in dir_events.items():
                baseline = self._calculate_baseline(dir_event_list, f"dir:{dir_cat}")
                new_baselines[f"dir:{dir_cat}"] = baseline
                
            # File type baselines
            for type_cat, type_event_list in type_events.items():
                baseline = self._calculate_baseline(type_event_list, f"type:{type_cat}")
                new_baselines[f"type:{type_cat}"] = baseline
            
            # Update cache
            self._baseline_cache = new_baselines
            self._last_update = current_time
            
            self.logger.info(f"Updated {len(new_baselines)} baselines")
            
        except Exception as e:
            log_error(self.logger, e, "Updating baselines")
    
    def _get_baseline(self, file_path: str) -> float:
        """
        Get baseline for a specific file path
        
        Args:
            file_path: File path to get baseline for
            
        Returns:
            Baseline events per hour
        """
        self._update_baselines()
        
        dir_category = self._get_directory_category(file_path)
        type_category = self._get_file_type_category(file_path)
        
        # Get baselines (with defaults)
        dir_baseline = self._baseline_cache.get(f"dir:{dir_category}", 1.0)
        type_baseline = self._baseline_cache.get(f"type:{type_category}", 1.0)
        
        # Use the higher of the two baselines (more conservative)
        return max(dir_baseline, type_baseline)
    
    def check_burst(self, file_path: str, window_minutes: int = 60) -> dict:
        """
        Check if current activity represents a burst for the given file path
        
        Args:
            file_path: File path to check
            window_minutes: Time window for burst detection (minutes)
            
        Returns:
            Dictionary with burst detection results
        """
        result = {
            'file_path': file_path,
            'is_burst': False,
            'current_rate': 0.0,
            'baseline': 0.0,
            'threshold': 0.0,
            'time_adjustment': 1.0,
            'events_in_window': 0,
            'burst_factor': 0.0,
            'error': None
        }
        
        try:
            current_time = time.time()
            window_start = current_time - (window_minutes * 60)
            
            # Get baseline for this file path
            baseline = self._get_baseline(file_path)
            
            # Get time adjustment
            time_adjustment = self._get_time_adjustment(current_time)
            
            # Calculate adjusted threshold
            adjusted_baseline = baseline * time_adjustment
            threshold = adjusted_baseline * self.threshold_multiplier
            
            # Count events in the time window for similar files
            dir_category = self._get_directory_category(file_path)
            type_category = self._get_file_type_category(file_path)
            
            conn = sqlite3.connect(self.db_path)
            try:
                # Check if table exists
                cursor = conn.execute('''
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='file_events'
                ''')
                if not cursor.fetchone():
                    events_in_window = 0
                else:
                    # Count events for same directory category and file type
                    cursor = conn.execute('''
                        SELECT COUNT(*) as count FROM file_events
                        WHERE timestamp > ? AND event_type = 'modified'
                    ''', (window_start,))

                    events_in_window = cursor.fetchone()[0]
            finally:
                conn.close()
            
            # Calculate current rate (events per hour)
            current_rate = (events_in_window / window_minutes) * 60
            
            # Determine if this is a burst
            is_burst = current_rate > threshold
            burst_factor = current_rate / threshold if threshold > 0 else 0
            
            # Update result
            result.update({
                'is_burst': is_burst,
                'current_rate': current_rate,
                'baseline': baseline,
                'threshold': threshold,
                'time_adjustment': time_adjustment,
                'events_in_window': events_in_window,
                'burst_factor': burst_factor
            })
            
            if is_burst:
                self.logger.warning(f"Burst detected for {file_path}: "
                                  f"rate={current_rate:.2f}, threshold={threshold:.2f}")
            else:
                self.logger.debug(f"No burst for {file_path}: "
                                f"rate={current_rate:.2f}, threshold={threshold:.2f}")
                                
        except Exception as e:
            result['error'] = str(e)
            log_error(self.logger, e, f"Checking burst for {file_path}")
            
        return result
    
    def check_burst_event(self, file_path: str) -> Optional[dict]:
        """
        Check for burst and trigger alerts if detected
        
        Args:
            file_path: File path to check
            
        Returns:
            Burst result if burst detected, None otherwise
        """
        try:
            result = self.check_burst(file_path)
            
            if result['is_burst']:
                self.logger.warning(f"Burst activity detected: {file_path}")
                
                # Import here to avoid circular imports
                try:
                    from alert import AlertManager
                    alert_manager = AlertManager()
                    alert_manager.trigger_burst_alert(result)
                except ImportError:
                    self.logger.warning("Alert module not available")
                    
                return result
                
        except Exception as e:
            log_error(self.logger, e, f"Checking burst event for {file_path}")
            
        return None
    
    def set_thresholds(self, multiplier: float = None, baseline_days: int = None) -> None:
        """
        Update burst detection thresholds
        
        Args:
            multiplier: Threshold multiplier
            baseline_days: Days for baseline calculation
        """
        if multiplier is not None:
            self.threshold_multiplier = multiplier
            self.logger.info(f"Updated threshold multiplier to {multiplier}")
            
        if baseline_days is not None:
            self.baseline_days = baseline_days
            self.logger.info(f"Updated baseline days to {baseline_days}")
            
        # Clear cache to force recalculation
        self._baseline_cache = {}
        self._last_update = 0


# Global detector instance
_detector = None

def get_detector() -> BurstDetector:
    """Get global burst detector instance"""
    global _detector
    if _detector is None:
        _detector = BurstDetector()
    return _detector


def check_burst(file_path: str) -> dict:
    """
    Convenience function to check for burst activity
    
    Args:
        file_path: File path to check
        
    Returns:
        Burst detection result
    """
    return get_detector().check_burst(file_path)


def check_burst_event(file_path: str) -> Optional[dict]:
    """
    Convenience function to check burst event
    
    Args:
        file_path: File path to check
        
    Returns:
        Burst result if burst detected, None otherwise
    """
    return get_detector().check_burst_event(file_path)
