"""
File System and Process Monitoring Module for FME-ABT Detector

This module monitors file events (create, modify, delete) in the monitored directory
and logs them to SQLite database with associated process information.
"""

import os
import sqlite3
import time
from datetime import datetime
from typing import Optional, Set
from pathlib import Path

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from utils import setup_logger, log_error, get_timestamp, safe_file_operation


class FileEventHandler(FileSystemEventHandler):
    """
    Custom file system event handler that logs events to database
    """
    
    def __init__(self, db_path: str = "file_events.db"):
        """
        Initialize the event handler
        
        Args:
            db_path: Path to SQLite database file
        """
        self.logger = setup_logger(__name__)
        self.db_path = db_path
        self.whitelist = self._load_process_whitelist()
        self._init_database()
        
    def _load_process_whitelist(self) -> Set[str]:
        """
        Load whitelisted process names to filter noise
        
        Returns:
            Set of whitelisted process names
        """
        # Common system processes that should be whitelisted
        default_whitelist = {
            'explorer.exe', 'notepad.exe', 'winword.exe', 'excel.exe',
            'powerpnt.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe',
            'code.exe', 'devenv.exe', 'python.exe', 'pythonw.exe',
            'svchost.exe', 'dwm.exe', 'csrss.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'wininit.exe', 'smss.exe',
            'conhost.exe', 'dllhost.exe', 'rundll32.exe', 'msiexec.exe',
            'taskhostw.exe', 'searchindexer.exe', 'audiodg.exe'
        }
        
        # Try to load additional whitelist from file
        whitelist_file = "process_whitelist.txt"
        if os.path.exists(whitelist_file):
            try:
                with open(whitelist_file, 'r') as f:
                    additional = {line.strip().lower() for line in f if line.strip()}
                    default_whitelist.update(additional)
            except Exception as e:
                log_error(self.logger, e, "Loading process whitelist")
        
        return {name.lower() for name in default_whitelist}
    
    def _init_database(self) -> None:
        """
        Initialize SQLite database with required table
        """
        try:
            conn = sqlite3.connect(self.db_path)
            try:
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

                # Create index for better query performance
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_timestamp
                    ON file_events(timestamp)
                ''')

                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_event_type
                    ON file_events(event_type)
                ''')

                conn.commit()
                self.logger.info(f"Database initialized: {self.db_path}")
            finally:
                conn.close()

        except Exception as e:
            log_error(self.logger, e, "Database initialization")
    
    def _get_file_size(self, file_path: str) -> Optional[int]:
        """
        Safely get file size

        Args:
            file_path: Path to file

        Returns:
            File size in bytes or None if error
        """
        try:
            if os.path.exists(file_path):
                return safe_file_operation(os.path.getsize, file_path)
            return None
        except (FileNotFoundError, OSError):
            # File might be temporarily unavailable during file operations
            return None
        except Exception as e:
            log_error(self.logger, e, f"Getting file size for {file_path}")
            return None
    
    def _get_process_info(self) -> tuple[Optional[int], Optional[str]]:
        """
        Get current process information that might be responsible for file changes
        
        Returns:
            Tuple of (process_id, process_name) or (None, None) if error
        """
        try:
            # Get all running processes and find the most likely candidate
            # This is a simplified approach - in reality, determining which process
            # modified a file is complex and may require more advanced techniques
            current_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower() if proc_info['name'] else ''
                    
                    # Skip whitelisted processes
                    if proc_name in self.whitelist:
                        continue
                        
                    # Focus on recently active processes
                    if time.time() - proc_info['create_time'] < 300:  # 5 minutes
                        current_processes.append((proc_info['pid'], proc_info['name']))
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Return the first non-whitelisted process (simplified heuristic)
            if current_processes:
                return current_processes[0]
                
        except Exception as e:
            log_error(self.logger, e, "Getting process information")
        
        return None, None
    
    def _log_event(self, event_type: str, file_path: str) -> None:
        """
        Log file event to database

        Args:
            event_type: Type of file event (created, modified, deleted)
            file_path: Path to the file
        """
        try:
            timestamp = get_timestamp()
            file_size = self._get_file_size(file_path) if event_type != 'deleted' else None
            pid, process_name = self._get_process_info()

            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    INSERT INTO file_events
                    (path, event_type, timestamp, size, pid, process_name)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (file_path, event_type, timestamp, file_size, pid, process_name))

                conn.commit()
            finally:
                conn.close()

            self.logger.info(f"Logged {event_type} event: {file_path} "
                           f"(PID: {pid}, Process: {process_name})")

        except Exception as e:
            log_error(self.logger, e, f"Logging {event_type} event for {file_path}")
    
    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events"""
        if not event.is_directory:
            self._log_event('created', event.src_path)
    
    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events"""
        if not event.is_directory:
            self._log_event('modified', event.src_path)
    
    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file deletion events"""
        if not event.is_directory:
            self._log_event('deleted', event.src_path)


class FileMonitor:
    """
    Main file monitoring class
    """
    
    def __init__(self, monitor_path: str = "./monitored", db_path: str = "file_events.db"):
        """
        Initialize file monitor
        
        Args:
            monitor_path: Directory to monitor
            db_path: Path to SQLite database
        """
        self.logger = setup_logger(__name__)
        self.monitor_path = os.path.abspath(monitor_path)
        self.db_path = db_path
        self.observer = None
        self.event_handler = None
        
        # Ensure monitor directory exists
        os.makedirs(self.monitor_path, exist_ok=True)
        
    def start(self) -> None:
        """
        Start file monitoring
        """
        try:
            self.event_handler = FileEventHandler(self.db_path)
            self.observer = Observer()
            self.observer.schedule(
                self.event_handler, 
                self.monitor_path, 
                recursive=True
            )
            
            self.observer.start()
            self.logger.info(f"Started monitoring: {self.monitor_path}")
            
        except Exception as e:
            log_error(self.logger, e, "Starting file monitor")
            raise
    
    def stop(self) -> None:
        """
        Stop file monitoring
        """
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.logger.info("Stopped file monitoring")
                
        except Exception as e:
            log_error(self.logger, e, "Stopping file monitor")
    
    def get_recent_events(self, hours: int = 24) -> list:
        """
        Get recent file events from database

        Args:
            hours: Number of hours to look back

        Returns:
            List of recent events
        """
        try:
            cutoff_time = time.time() - (hours * 3600)

            conn = sqlite3.connect(self.db_path)
            try:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM file_events
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (cutoff_time,))

                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

        except Exception as e:
            log_error(self.logger, e, "Getting recent events")
            return []


def main():
    """
    Main function for testing the monitor
    """
    monitor = FileMonitor()
    
    try:
        monitor.start()
        print("File monitor started. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Monitor stopped.")


if __name__ == "__main__":
    main()
