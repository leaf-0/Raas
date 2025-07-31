"""
Utility functions for FME-ABT Detector
Provides common logging, database, and error handling functionality
"""

import logging
import os
import sqlite3
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Any


def setup_logger(name: str, log_file: str = "errors.log") -> logging.Logger:
    """
    Set up a logger with rotating file and console handlers

    Args:
        name: Logger name
        log_file: Path to log file

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Rotating file handler with log rotation
    try:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file) if os.path.dirname(log_file) else '.'
        os.makedirs(log_dir, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        # Use temporary logger to log file handler errors
        temp_logger = logging.getLogger('temp_setup')
        temp_handler = logging.StreamHandler()
        temp_handler.setFormatter(formatter)
        temp_logger.addHandler(temp_handler)
        temp_logger.error(f"Could not create rotating file handler for {log_file}: {e}")

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def log_error(logger: logging.Logger, error: Exception, context: str = "") -> None:
    """
    Log an error with context information
    
    Args:
        logger: Logger instance
        error: Exception to log
        context: Additional context information
    """
    error_msg = f"{context}: {str(error)}" if context else str(error)
    logger.error(error_msg, exc_info=True)


def ensure_directory_exists(directory: str) -> bool:
    """
    Ensure a directory exists, create if it doesn't

    Args:
        directory: Directory path to check/create

    Returns:
        True if directory exists or was created successfully
    """
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        logger = setup_logger(__name__)
        logger.error(f"Error creating directory {directory}: {e}")
        return False


def get_timestamp() -> float:
    """
    Get current timestamp with high precision

    Returns:
        Current timestamp with microsecond precision
    """
    return time.time()


def format_timestamp(timestamp: float) -> str:
    """
    Format timestamp for display
    
    Args:
        timestamp: Unix timestamp
        
    Returns:
        Formatted timestamp string
    """
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def safe_file_operation(operation, *args, **kwargs):
    """
    Safely execute a file operation with retry logic and logging

    Args:
        operation: Function to execute
        *args: Arguments for the operation
        **kwargs: Keyword arguments for the operation

    Returns:
        Result of operation or None if failed
    """
    max_retries = 3
    retry_delay = 0.1
    logger = setup_logger(__name__)

    for attempt in range(max_retries):
        try:
            return operation(*args, **kwargs)
        except (OSError, PermissionError, FileNotFoundError) as e:
            if attempt == max_retries - 1:
                logger.error(f"File operation failed after {max_retries} attempts: {e}")
                raise e
            logger.debug(f"File operation attempt {attempt + 1} failed: {e}, retrying...")
            time.sleep(retry_delay * (attempt + 1))

    return None


def validate_file_path(file_path: str) -> bool:
    """
    Validate if a file path is safe and accessible

    Args:
        file_path: Path to validate

    Returns:
        True if path is valid and safe
    """
    try:
        # Convert to Path object for better handling
        path = Path(file_path)

        # Check if path is absolute and exists
        if not path.is_absolute():
            return False

        # Check if parent directory exists
        if not path.parent.exists():
            return False

        # Check for suspicious path patterns
        suspicious_patterns = ['..', '~', '$']
        path_str = str(path).lower()

        for pattern in suspicious_patterns:
            if pattern in path_str:
                return False

        return True

    except Exception:
        return False


def get_db_connection(db_path: str, timeout: float = 30.0) -> Optional[sqlite3.Connection]:
    """
    Get database connection with retry logic and proper configuration

    Args:
        db_path: Path to SQLite database
        timeout: Connection timeout in seconds

    Returns:
        Database connection or None if failed
    """
    max_retries = 3
    retry_delay = 0.5
    logger = setup_logger(__name__)

    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(
                db_path,
                timeout=timeout,
                check_same_thread=False,
                isolation_level=None  # Autocommit mode
            )

            # Configure connection for better performance
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")

            return conn

        except sqlite3.Error as e:
            if attempt == max_retries - 1:
                logger.error(f"Database connection failed after {max_retries} attempts: {e}")
                return None
            logger.debug(f"Database connection attempt {attempt + 1} failed: {e}, retrying...")
            time.sleep(retry_delay * (attempt + 1))

    return None
