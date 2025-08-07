#!/usr/bin/env python3
"""
Main Entry Point for FME-ABT Detector

This module provides a unified entry point for the FME-ABT ransomware detection system.
It orchestrates the file monitoring, entropy analysis, burst detection, and alerting components.
"""

import os
import sys
import time
import signal
import argparse
import threading
from typing import Optional

from utils import setup_logger, log_error
from monitor import FileMonitor
from alert import get_alert_manager


class FMEABTDetector:
    """
    Main detector class that orchestrates all components
    """
    
    def __init__(self, monitor_path: str = "./monitored", 
                 events_db: str = "file_events.db",
                 alerts_db: str = "alerts.db"):
        """
        Initialize the FME-ABT detector
        
        Args:
            monitor_path: Directory to monitor for file changes
            events_db: Path to file events database
            alerts_db: Path to alerts database
        """
        self.logger = setup_logger(__name__)
        self.monitor_path = os.path.abspath(monitor_path)
        self.events_db = events_db
        self.alerts_db = alerts_db
        
        # Components
        self.file_monitor: Optional[FileMonitor] = None
        self.alert_manager = None
        self.running = False
        
        # Ensure monitor directory exists
        os.makedirs(self.monitor_path, exist_ok=True)
        
    def start(self) -> None:
        """
        Start the FME-ABT detection system
        """
        try:
            self.logger.info("Starting FME-ABT Detector...")
            
            # Initialize alert manager
            self.alert_manager = get_alert_manager()
            self.logger.info("Alert manager initialized")
            
            # Initialize and start file monitor
            self.file_monitor = FileMonitor(
                monitor_path=self.monitor_path,
                db_path=self.events_db
            )
            self.file_monitor.start()
            self.logger.info(f"File monitoring started for: {self.monitor_path}")
            
            self.running = True
            self.logger.info("FME-ABT Detector is now running")
            
            # Print status information
            self._print_status()
            
        except Exception as e:
            log_error(self.logger, e, "Starting FME-ABT Detector")
            raise
    
    def stop(self) -> None:
        """
        Stop the FME-ABT detection system
        """
        try:
            self.logger.info("Stopping FME-ABT Detector...")
            self.running = False
            
            # Stop file monitor
            if self.file_monitor:
                self.file_monitor.stop()
                self.logger.info("File monitoring stopped")
            
            # Stop alert manager VSS monitoring
            if self.alert_manager:
                self.alert_manager.stop_vss_monitoring()
                self.logger.info("VSS monitoring stopped")
            
            self.logger.info("FME-ABT Detector stopped")
            
        except Exception as e:
            log_error(self.logger, e, "Stopping FME-ABT Detector")
    
    def _print_status(self) -> None:
        """
        Print current system status
        """
        print("\n" + "="*60)
        print("FME-ABT Ransomware Detection System")
        print("="*60)
        print(f"Monitor Path: {self.monitor_path}")
        print(f"Events DB: {self.events_db}")
        print(f"Alerts DB: {self.alerts_db}")
        print(f"Status: {'RUNNING' if self.running else 'STOPPED'}")
        print("\nFeatures Active:")
        print("  ✓ File System Monitoring (Watchdog)")
        print("  ✓ Entropy Analysis (FME)")
        print("  ✓ Burst Detection (ABT)")
        print("  ✓ Volume Shadow Copy Monitoring")
        print("  ✓ Process Identification")
        print("  ✓ Alert System")
        print("\nPress Ctrl+C to stop the detector")
        print("="*60)
    
    def get_stats(self) -> dict:
        """
        Get current system statistics
        
        Returns:
            Dictionary with system statistics
        """
        try:
            stats = {
                'running': self.running,
                'monitor_path': self.monitor_path,
                'recent_events': 0,
                'recent_alerts': 0
            }
            
            # Get recent events
            if self.file_monitor:
                recent_events = self.file_monitor.get_recent_events(hours=1)
                stats['recent_events'] = len(recent_events)
            
            # Get recent alerts
            if self.alert_manager:
                recent_alerts = self.alert_manager.get_recent_alerts(hours=1)
                stats['recent_alerts'] = len(recent_alerts)
            
            return stats
            
        except Exception as e:
            log_error(self.logger, e, "Getting system statistics")
            return {'error': str(e)}


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nShutdown signal received...")
    global detector
    if detector:
        detector.stop()
    sys.exit(0)


def main():
    """
    Main function
    """
    parser = argparse.ArgumentParser(
        description="FME-ABT Ransomware Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Monitor ./monitored directory
  python main.py -p /home/user/documents  # Monitor specific directory
  python main.py --stats                  # Show statistics and exit
        """
    )
    
    parser.add_argument(
        '-p', '--path',
        default='./monitored',
        help='Directory to monitor (default: ./monitored)'
    )
    
    parser.add_argument(
        '--events-db',
        default='file_events.db',
        help='File events database path (default: file_events.db)'
    )
    
    parser.add_argument(
        '--alerts-db',
        default='alerts.db',
        help='Alerts database path (default: alerts.db)'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show system statistics and exit'
    )
    
    args = parser.parse_args()
    
    global detector
    detector = FMEABTDetector(
        monitor_path=args.path,
        events_db=args.events_db,
        alerts_db=args.alerts_db
    )
    
    # Handle stats request
    if args.stats:
        try:
            detector.start()
            time.sleep(2)  # Let it initialize
            stats = detector.get_stats()
            print("\nSystem Statistics:")
            for key, value in stats.items():
                print(f"  {key}: {value}")
            detector.stop()
        except Exception as e:
            print(f"Error getting statistics: {e}")
        return
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start the detector
        detector.start()
        
        # Keep running until interrupted
        while detector.running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if detector:
            detector.stop()


if __name__ == "__main__":
    main()
