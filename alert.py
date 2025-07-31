"""
Alert and Mitigation Module for FME-ABT Detector

This module handles alerting and lightweight mitigation including:
- Pop-up alerts for suspicious activity
- Process termination for high-confidence detections
- Volume Shadow Copy deletion monitoring
- Alert logging to database
"""

import os
import sqlite3
import subprocess
import threading
import time
import tkinter as tk
from tkinter import messagebox
from typing import Optional, Dict, List
from datetime import datetime

import psutil

from utils import setup_logger, log_error, get_timestamp


class AlertManager:
    """
    Manages alerts and mitigation responses for suspicious activity
    """
    
    def __init__(self, alerts_db_path: str = "alerts.db"):
        """
        Initialize alert manager
        
        Args:
            alerts_db_path: Path to alerts database
        """
        self.logger = setup_logger(__name__)
        self.alerts_db_path = alerts_db_path
        self.mitigation_enabled = True
        self.vss_monitor_active = False
        self.vss_monitor_thread = None
        
        # Initialize alerts database
        self._init_alerts_database()
        
        # Start Volume Shadow Copy monitoring
        self.start_vss_monitoring()
        
    def _init_alerts_database(self) -> None:
        """
        Initialize SQLite database for alert logging
        """
        try:
            conn = sqlite3.connect(self.alerts_db_path)
            try:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_type TEXT NOT NULL,
                        message TEXT NOT NULL,
                        file_path TEXT,
                        process_id INTEGER,
                        process_name TEXT,
                        severity TEXT DEFAULT 'medium',
                        timestamp REAL NOT NULL,
                        action_taken TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create index for better query performance
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_alert_timestamp 
                    ON alerts(timestamp)
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_alert_type 
                    ON alerts(alert_type)
                ''')
                
                conn.commit()
                self.logger.info(f"Alerts database initialized: {self.alerts_db_path}")
            finally:
                conn.close()
                
        except Exception as e:
            log_error(self.logger, e, "Initializing alerts database")
    
    def _log_alert(self, alert_type: str, message: str, file_path: str = None,
                   process_id: int = None, process_name: str = None,
                   severity: str = "medium", action_taken: str = None) -> None:
        """
        Log alert to database
        
        Args:
            alert_type: Type of alert (entropy, burst, vss, etc.)
            message: Alert message
            file_path: Associated file path
            process_id: Associated process ID
            process_name: Associated process name
            severity: Alert severity (low, medium, high, critical)
            action_taken: Action taken in response
        """
        try:
            timestamp = get_timestamp()
            
            conn = sqlite3.connect(self.alerts_db_path)
            try:
                conn.execute('''
                    INSERT INTO alerts 
                    (alert_type, message, file_path, process_id, process_name, 
                     severity, timestamp, action_taken)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (alert_type, message, file_path, process_id, process_name,
                      severity, timestamp, action_taken))
                
                conn.commit()
            finally:
                conn.close()
                
            self.logger.info(f"Alert logged: {alert_type} - {message}")
            
        except Exception as e:
            log_error(self.logger, e, f"Logging alert: {alert_type}")
    
    def _show_popup_alert(self, title: str, message: str, severity: str = "medium") -> None:
        """
        Show popup alert using tkinter
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity for icon selection
        """
        try:
            # Create root window (hidden)
            root = tk.Tk()
            root.withdraw()  # Hide the root window
            
            # Determine icon based on severity
            icon_map = {
                "low": "info",
                "medium": "warning", 
                "high": "warning",
                "critical": "error"
            }
            icon = icon_map.get(severity, "warning")
            
            # Show message box
            messagebox.showwarning(title, message, icon=icon)
            
            # Clean up
            root.destroy()
            
        except Exception as e:
            log_error(self.logger, e, f"Showing popup alert: {title}")
    
    def _terminate_process(self, process_id: int, process_name: str = None) -> bool:
        """
        Terminate a suspicious process
        
        Args:
            process_id: Process ID to terminate
            process_name: Process name for logging
            
        Returns:
            True if process was terminated successfully
        """
        try:
            # Get process info
            process = psutil.Process(process_id)
            actual_name = process.name()
            
            # Confirm process details
            if process_name and actual_name.lower() != process_name.lower():
                self.logger.warning(f"Process name mismatch: expected {process_name}, "
                                  f"got {actual_name}")
            
            # Terminate process
            process.terminate()
            
            # Wait for termination (with timeout)
            try:
                process.wait(timeout=5)
                self.logger.warning(f"Terminated suspicious process: {actual_name} (PID: {process_id})")
                return True
            except psutil.TimeoutExpired:
                # Force kill if terminate didn't work
                process.kill()
                self.logger.warning(f"Force killed suspicious process: {actual_name} (PID: {process_id})")
                return True
                
        except psutil.NoSuchProcess:
            self.logger.info(f"Process {process_id} no longer exists")
            return True
        except psutil.AccessDenied:
            self.logger.error(f"Access denied terminating process {process_id}")
            return False
        except Exception as e:
            log_error(self.logger, e, f"Terminating process {process_id}")
            return False
    
    def trigger_entropy_alert(self, entropy_result: Dict) -> None:
        """
        Trigger alert for high entropy detection
        
        Args:
            entropy_result: Result from entropy analysis
        """
        try:
            file_path = entropy_result.get('file_path', 'Unknown')
            mean_entropy = entropy_result.get('mean_entropy', 0)
            variance = entropy_result.get('entropy_variance', 0)
            reasons = entropy_result.get('suspicion_reasons', [])
            
            # Create alert message
            message = (f"Suspicious file detected: {os.path.basename(file_path)}\n"
                      f"Mean Entropy: {mean_entropy:.2f}\n"
                      f"Entropy Variance: {variance:.2f}\n"
                      f"Reasons: {', '.join(reasons)}\n"
                      f"Full Path: {file_path}")
            
            # Determine severity
            severity = "high" if mean_entropy > 7.5 or variance > 10 else "medium"
            
            # Show popup alert
            self._show_popup_alert("Ransomware Detection - High Entropy", message, severity)
            
            # Log alert
            self._log_alert(
                alert_type="entropy",
                message=f"High entropy file: {file_path} (entropy={mean_entropy:.2f})",
                file_path=file_path,
                severity=severity
            )
            
        except Exception as e:
            log_error(self.logger, e, "Triggering entropy alert")
    
    def trigger_burst_alert(self, burst_result: Dict) -> None:
        """
        Trigger alert for burst activity detection
        
        Args:
            burst_result: Result from burst analysis
        """
        try:
            file_path = burst_result.get('file_path', 'Unknown')
            current_rate = burst_result.get('current_rate', 0)
            threshold = burst_result.get('threshold', 0)
            burst_factor = burst_result.get('burst_factor', 0)
            
            # Create alert message
            message = (f"Burst activity detected: {os.path.basename(file_path)}\n"
                      f"Current Rate: {current_rate:.1f} events/hour\n"
                      f"Threshold: {threshold:.1f} events/hour\n"
                      f"Burst Factor: {burst_factor:.1f}x normal\n"
                      f"Full Path: {file_path}")
            
            # Determine severity based on burst factor
            if burst_factor > 10:
                severity = "critical"
            elif burst_factor > 5:
                severity = "high"
            else:
                severity = "medium"
            
            # Show popup alert
            self._show_popup_alert("Ransomware Detection - Burst Activity", message, severity)
            
            # Log alert
            self._log_alert(
                alert_type="burst",
                message=f"Burst activity: {file_path} (rate={current_rate:.1f}/hr)",
                file_path=file_path,
                severity=severity
            )
            
            # Consider process termination for critical bursts
            if severity == "critical" and self.mitigation_enabled:
                self._consider_process_termination(file_path, burst_result)
                
        except Exception as e:
            log_error(self.logger, e, "Triggering burst alert")
    
    def _consider_process_termination(self, file_path: str, detection_result: Dict) -> None:
        """
        Consider terminating processes for high-confidence detections
        
        Args:
            file_path: File path associated with detection
            detection_result: Detection result data
        """
        try:
            # This is a simplified heuristic - in practice, you'd want more
            # sophisticated logic to determine when to terminate processes
            
            # Look for recently active processes that might be responsible
            suspicious_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'exe']):
                try:
                    proc_info = proc.info
                    
                    # Skip system processes
                    if proc_info['name'].lower() in ['system', 'csrss.exe', 'winlogon.exe']:
                        continue
                    
                    # Look for recently created processes
                    if time.time() - proc_info['create_time'] < 3600:  # Last hour
                        suspicious_processes.append(proc_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # For demo purposes, we'll be very conservative and not actually terminate
            # In a real implementation, you'd have more sophisticated detection logic
            if suspicious_processes:
                self.logger.warning(f"Found {len(suspicious_processes)} recently active processes, "
                                  f"but not terminating (safety measure)")
                
                # Log what we would have done
                self._log_alert(
                    alert_type="mitigation",
                    message=f"Would consider terminating {len(suspicious_processes)} processes",
                    file_path=file_path,
                    severity="high",
                    action_taken="evaluation_only"
                )
            
        except Exception as e:
            log_error(self.logger, e, "Considering process termination")
    
    def _monitor_vss_deletion(self) -> None:
        """
        Monitor for Volume Shadow Copy deletion attempts
        """
        try:
            while self.vss_monitor_active:
                try:
                    # Check for vssadmin processes
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            proc_info = proc.info
                            
                            if (proc_info['name'].lower() == 'vssadmin.exe' and 
                                proc_info['cmdline']):
                                
                                cmdline = ' '.join(proc_info['cmdline']).lower()
                                
                                # Check for shadow copy deletion commands
                                if 'delete' in cmdline and 'shadows' in cmdline:
                                    self._trigger_vss_alert(proc_info)
                                    
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
                    time.sleep(2)  # Check every 2 seconds
                    
                except Exception as e:
                    log_error(self.logger, e, "VSS monitoring loop")
                    time.sleep(5)  # Wait longer on error
                    
        except Exception as e:
            log_error(self.logger, e, "VSS monitoring thread")
    
    def _trigger_vss_alert(self, process_info: Dict) -> None:
        """
        Trigger alert for Volume Shadow Copy deletion attempt
        
        Args:
            process_info: Process information
        """
        try:
            cmdline = ' '.join(process_info['cmdline'])
            
            message = (f"Volume Shadow Copy deletion detected!\n"
                      f"Process: {process_info['name']}\n"
                      f"PID: {process_info['pid']}\n"
                      f"Command: {cmdline}\n"
                      f"This is a common ransomware behavior!")
            
            # Show critical alert
            self._show_popup_alert("CRITICAL: Shadow Copy Deletion", message, "critical")
            
            # Log alert
            self._log_alert(
                alert_type="vss_deletion",
                message=f"VSS deletion attempt: {cmdline}",
                process_id=process_info['pid'],
                process_name=process_info['name'],
                severity="critical"
            )
            
            self.logger.critical(f"Volume Shadow Copy deletion detected: {cmdline}")
            
        except Exception as e:
            log_error(self.logger, e, "Triggering VSS alert")
    
    def start_vss_monitoring(self) -> None:
        """
        Start Volume Shadow Copy monitoring in background thread
        """
        try:
            if not self.vss_monitor_active:
                self.vss_monitor_active = True
                self.vss_monitor_thread = threading.Thread(
                    target=self._monitor_vss_deletion,
                    daemon=True
                )
                self.vss_monitor_thread.start()
                self.logger.info("Started Volume Shadow Copy monitoring")
                
        except Exception as e:
            log_error(self.logger, e, "Starting VSS monitoring")
    
    def stop_vss_monitoring(self) -> None:
        """
        Stop Volume Shadow Copy monitoring
        """
        try:
            self.vss_monitor_active = False
            if self.vss_monitor_thread:
                self.vss_monitor_thread.join(timeout=5)
            self.logger.info("Stopped Volume Shadow Copy monitoring")
            
        except Exception as e:
            log_error(self.logger, e, "Stopping VSS monitoring")
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """
        Get recent alerts from database
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of recent alerts
        """
        try:
            cutoff_time = time.time() - (hours * 3600)
            
            conn = sqlite3.connect(self.alerts_db_path)
            try:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM alerts 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC
                ''', (cutoff_time,))
                
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()
                
        except Exception as e:
            log_error(self.logger, e, "Getting recent alerts")
            return []
    
    def set_mitigation_enabled(self, enabled: bool) -> None:
        """
        Enable or disable automatic mitigation
        
        Args:
            enabled: Whether to enable mitigation
        """
        self.mitigation_enabled = enabled
        status = "enabled" if enabled else "disabled"
        self.logger.info(f"Automatic mitigation {status}")


# Global alert manager instance
_alert_manager = None

def get_alert_manager() -> AlertManager:
    """Get global alert manager instance"""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager
