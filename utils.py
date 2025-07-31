"""
Utility functions for FME-ABT Detector
Provides common logging and error handling functionality
"""

import logging
import os
from datetime import datetime
from typing import Optional


def setup_logger(name: str, log_file: str = "errors.log") -> logging.Logger:
    """
    Set up a logger with file and console handlers
    
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
    
    # File handler
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not create file handler for {log_file}: {e}")
    
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
        print(f"Error creating directory {directory}: {e}")
        return False


def get_timestamp() -> float:
    """
    Get current timestamp as float
    
    Returns:
        Current timestamp
    """
    return datetime.now().timestamp()


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
    Safely execute a file operation with retry logic
    
    Args:
        operation: Function to execute
        *args: Arguments for the operation
        **kwargs: Keyword arguments for the operation
        
    Returns:
        Result of operation or None if failed
    """
    max_retries = 3
    retry_delay = 0.1
    
    for attempt in range(max_retries):
        try:
            return operation(*args, **kwargs)
        except (OSError, IOError, PermissionError) as e:
            if attempt == max_retries - 1:
                raise e
            import time
            time.sleep(retry_delay * (attempt + 1))
    
    return None
