"""
Enhanced File System and Process Monitoring Module for FME-ABT Detector

This module monitors file events with improved process identification,
VSS deletion monitoring, batch database writes, and dynamic whitelisting.
"""

import os
import sqlite3
import time
import threading
from datetime import datetime
from typing import Optional, Set, List, Dict
from pathlib import Path
from collections import deque

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from utils import setup_logger, log_error, get_timestamp, safe_file_operation, get_db_connection, validate_file_path


class FileEventHandler(FileSystemEventHandler):
    """
    Enhanced file system event handler with improved process identification
    and batch database operations
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
        self.whitelist_last_modified = 0
        self.event_queue = deque()
        self.batch_size = 10
        self.batch_timeout = 5.0  # seconds
        self.last_batch_time = time.time()
        
        # File type filtering
        self.skip_extensions = {
            '.tmp', '.temp', '.log', '.cache', '.bak', '.swp', '.swo',
            '.lock', '.pid', '.sock', '.db-journal', '.db-wal'
        }
        
        self._init_database()
        self._start_batch_processor()
        self._start_vss_monitor()
        
    def _load_process_whitelist(self) -> Set[str]:
        """
        Load whitelisted process names with dynamic reloading
        
        Returns:
            Set of whitelisted process names
        """
        # Enhanced default whitelist
        default_whitelist = {
            'explorer.exe', 'notepad.exe', 'winword.exe', 'excel.exe',
            'powerpnt.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe',
            'code.exe', 'devenv.exe', 'python.exe', 'pythonw.exe',
            'svchost.exe', 'dwm.exe', 'csrss.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'wininit.exe', 'smss.exe',
            'conhost.exe', 'dllhost.exe', 'rundll32.exe', 'msiexec.exe',
            'taskhostw.exe', 'searchindexer.exe', 'audiodg.exe',
            'spoolsv.exe', 'wuauclt.exe', 'wmiprvse.exe', 'fontdrvhost.exe'
        }
        
        # Load additional whitelist from file with safe file operation
        whitelist_file = "process_whitelist.txt"
        if os.path.exists(whitelist_file):
            try:
                def read_whitelist():
                    with open(whitelist_file, 'r', encoding='utf-8') as f:
                        return {line.strip().lower() for line in f if line.strip()}
                
                additional = safe_file_operation(read_whitelist)
                if additional:
                    default_whitelist.update(additional)
                    self.whitelist_last_modified = os.path.getmtime(whitelist_file)
            except Exception as e:
                log_error(self.logger, e, "Loading process whitelist")
        
        return {name.lower() for name in default_whitelist}
    
    def _reload_whitelist_if_needed(self):
        """
        Reload whitelist if file has been modified
        """
        whitelist_file = "process_whitelist.txt"
        if os.path.exists(whitelist_file):
            try:
                current_mtime = os.path.getmtime(whitelist_file)
                if current_mtime > self.whitelist_last_modified:
                    self.whitelist = self._load_process_whitelist()
                    self.logger.info("Process whitelist reloaded")
            except Exception as e:
                log_error(self.logger, e, "Checking whitelist modification time")
    
    def _init_database(self) -> None:
        """
        Initialize SQLite database with enhanced schema
        """
        try:
            conn = get_db_connection(self.db_path)
            if not conn:
                self.logger.error("Failed to connect to database")
                return
                
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
                        process_path TEXT,
                        file_hash TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Enhanced indexes for better performance
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_timestamp_type 
                    ON file_events(timestamp, event_type)
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_process_name 
                    ON file_events(process_name)
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_path 
                    ON file_events(path)
                ''')
                
                self.logger.info(f"Database initialized: {self.db_path}")
            finally:
                conn.close()
                
        except Exception as e:
            log_error(self.logger, e, "Database initialization")
    
    def _get_file_size(self, file_path: str) -> Optional[int]:
        """
        Safely get file size with validation
        
        Args:
            file_path: Path to file
            
        Returns:
            File size in bytes or None if error
        """
        try:
            if not validate_file_path(file_path) or not os.path.exists(file_path):
                return None
            return safe_file_operation(os.path.getsize, file_path)
        except (FileNotFoundError, OSError):
            return None
        except Exception as e:
            log_error(self.logger, e, f"Getting file size for {file_path}")
            return None
    
    def _get_process_info(self, file_path: str) -> tuple[Optional[int], Optional[str], Optional[str]]:
        """
        Enhanced process identification with file access checks
        
        Args:
            file_path: Path to file being accessed
            
        Returns:
            Tuple of (process_id, process_name, process_path) or (None, None, None)
        """
        try:
            # Reload whitelist if needed
            self._reload_whitelist_if_needed()
            
            current_processes = []
            file_dir = os.path.dirname(file_path)
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'open_files']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower() if proc_info['name'] else ''
                    
                    # Skip whitelisted processes
                    if proc_name in self.whitelist:
                        continue
                    
                    # Check if process has file handles in the same directory
                    try:
                        open_files = proc.open_files()
                        for open_file in open_files:
                            if os.path.dirname(open_file.path) == file_dir:
                                current_processes.append((
                                    proc_info['pid'],
                                    proc_info['name'],
                                    proc_info.get('exe', ''),
                                    proc_info['create_time']
                                ))
                                break
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        # If we can't check open files, consider recently created processes
                        if time.time() - proc_info['create_time'] < 300:  # 5 minutes
                            current_processes.append((
                                proc_info['pid'],
                                proc_info['name'],
                                proc_info.get('exe', ''),
                                proc_info['create_time']
                            ))
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Return the most recently created process
            if current_processes:
                current_processes.sort(key=lambda x: x[3], reverse=True)
                pid, name, exe, _ = current_processes[0]
                return pid, name, exe
                
        except Exception as e:
            log_error(self.logger, e, "Getting process information")
        
        return None, None, None
    
    def _should_skip_file(self, file_path: str) -> bool:
        """
        Check if file should be skipped based on extension and path
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file should be skipped
        """
        try:
            path = Path(file_path)
            
            # Skip based on extension
            if path.suffix.lower() in self.skip_extensions:
                return True
                
            # Skip system directories
            path_str = str(path).lower()
            system_dirs = ['\\windows\\', '\\system32\\', '\\syswow64\\', '\\programdata\\']
            
            for sys_dir in system_dirs:
                if sys_dir in path_str:
                    return True
                    
            return False
            
        except Exception:
            return True  # Skip on error
    
    def _queue_event(self, event_type: str, file_path: str) -> None:
        """
        Queue file event for batch processing

        Args:
            event_type: Type of file event
            file_path: Path to the file
        """
        try:
            if self._should_skip_file(file_path):
                return

            timestamp = get_timestamp()
            file_size = self._get_file_size(file_path) if event_type != 'deleted' else None
            pid, process_name, process_path = self._get_process_info(file_path)

            event_data = {
                'path': file_path,
                'event_type': event_type,
                'timestamp': timestamp,
                'size': file_size,
                'pid': pid,
                'process_name': process_name,
                'process_path': process_path
            }

            self.event_queue.append(event_data)

            # Process batch if queue is full or timeout reached
            if (len(self.event_queue) >= self.batch_size or
                time.time() - self.last_batch_time >= self.batch_timeout):
                self._process_batch()

        except Exception as e:
            log_error(self.logger, e, f"Queueing {event_type} event for {file_path}")

    def _process_batch(self) -> None:
        """
        Process queued events in batch
        """
        if not self.event_queue:
            return

        try:
            conn = get_db_connection(self.db_path)
            if not conn:
                self.logger.error("Failed to connect to database for batch processing")
                return

            try:
                events_to_process = []
                while self.event_queue and len(events_to_process) < self.batch_size:
                    events_to_process.append(self.event_queue.popleft())

                # Batch insert
                conn.executemany('''
                    INSERT INTO file_events
                    (path, event_type, timestamp, size, pid, process_name, process_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', [
                    (event['path'], event['event_type'], event['timestamp'],
                     event['size'], event['pid'], event['process_name'], event['process_path'])
                    for event in events_to_process
                ])

                self.last_batch_time = time.time()
                self.logger.debug(f"Processed batch of {len(events_to_process)} events")

                # Trigger analysis for each event
                for event in events_to_process:
                    self._analyze_file_event(event)

            finally:
                conn.close()

        except Exception as e:
            log_error(self.logger, e, "Processing event batch")

    def _analyze_file_event(self, event: Dict) -> None:
        """
        Trigger entropy and burst analysis for file events

        Args:
            event: Event data dictionary
        """
        try:
            file_path = event['path']
            event_type = event['event_type']

            # Only analyze created and modified events
            if event_type in ['created', 'modified']:
                # Import here to avoid circular imports
                try:
                    from fme import analyze_file_event
                    from abt import check_burst_event

                    # Analyze entropy (will trigger alerts if suspicious)
                    analyze_file_event(file_path)

                    # Check for burst activity
                    check_burst_event(file_path)

                except ImportError as e:
                    self.logger.warning(f"Analysis modules not available: {e}")

        except Exception as e:
            log_error(self.logger, e, f"Analyzing file event for {event.get('path', 'unknown')}")

    def _start_batch_processor(self) -> None:
        """
        Start background thread for batch processing
        """
        def batch_processor():
            while True:
                try:
                    time.sleep(self.batch_timeout)
                    if self.event_queue:
                        self._process_batch()
                except Exception as e:
                    log_error(self.logger, e, "Batch processor thread")

        batch_thread = threading.Thread(target=batch_processor, daemon=True)
        batch_thread.start()
        self.logger.info("Started batch processor thread")

    def _start_vss_monitor(self) -> None:
        """
        Start Volume Shadow Copy deletion monitoring
        """
        def vss_monitor():
            while True:
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            proc_info = proc.info
                            proc_name = proc_info['name'].lower()
                            cmdline = ' '.join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ''

                            # Monitor various VSS deletion methods
                            vss_indicators = [
                                ('vssadmin.exe', ['delete', 'shadows']),
                                ('powershell.exe', ['get-wmiobject', 'win32_shadowcopy', 'delete']),
                                ('wmic.exe', ['shadowcopy', 'delete']),
                                ('cmd.exe', ['vssadmin', 'delete'])
                            ]

                            for process_name, keywords in vss_indicators:
                                if proc_name == process_name and all(kw in cmdline for kw in keywords):
                                    self._trigger_vss_alert(proc_info, cmdline)

                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                    time.sleep(5)  # Check every 5 seconds

                except Exception as e:
                    log_error(self.logger, e, "VSS monitoring thread")
                    time.sleep(10)  # Wait longer on error

        vss_thread = threading.Thread(target=vss_monitor, daemon=True)
        vss_thread.start()
        self.logger.info("Started VSS deletion monitoring")

    def _trigger_vss_alert(self, process_info: Dict, cmdline: str) -> None:
        """
        Trigger alert for VSS deletion attempt

        Args:
            process_info: Process information
            cmdline: Command line
        """
        try:
            from alert import get_alert_manager

            alert_manager = get_alert_manager()
            alert_manager._log_alert(
                alert_type="vss_deletion",
                message=f"Volume Shadow Copy deletion detected: {cmdline}",
                process_id=process_info['pid'],
                process_name=process_info['name'],
                severity="critical"
            )

            self.logger.critical(f"VSS deletion detected: PID {process_info['pid']}, CMD: {cmdline}")

        except Exception as e:
            log_error(self.logger, e, "Triggering VSS alert")

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events"""
        if not event.is_directory:
            self._queue_event('created', event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events"""
        if not event.is_directory:
            self._queue_event('modified', event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file deletion events"""
        if not event.is_directory:
            self._queue_event('deleted', event.src_path)


class FileMonitor:
    """
    Enhanced file monitoring class with improved functionality
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
        Start file monitoring with recursive monitoring
        """
        try:
            self.event_handler = FileEventHandler(self.db_path)
            self.observer = Observer()
            self.observer.schedule(
                self.event_handler,
                self.monitor_path,
                recursive=True  # Enable recursive monitoring
            )

            self.observer.start()
            self.logger.info(f"Started recursive monitoring: {self.monitor_path}")

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

            conn = get_db_connection(self.db_path)
            if not conn:
                return []

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
    Main function for testing the enhanced monitor
    """
    monitor = FileMonitor()

    try:
        monitor.start()
        print("Enhanced file monitor started. Press Ctrl+C to stop.")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Monitor stopped.")


if __name__ == "__main__":
    main()
