"""
Logging configuration and setup utilities.
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    max_log_size: str = "10MB",
    backup_count: int = 5,
    console_output: bool = True
) -> logging.Logger:
    """
    Set up logging configuration for the LAN Security System.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        max_log_size: Maximum size of log file before rotation
        backup_count: Number of backup log files to keep
        console_output: Whether to output logs to console
    
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    logger = logging.getLogger("lan_security_system")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add console handler if requested
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # Add file handler if log file specified
    if log_file:
        # Parse max_log_size
        size_multipliers = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3}
        size_str = max_log_size.upper()
        
        max_bytes = 10 * 1024 * 1024  # Default 10MB
        for suffix, multiplier in size_multipliers.items():
            if size_str.endswith(suffix):
                try:
                    size_value = float(size_str[:-len(suffix)])
                    max_bytes = int(size_value * multiplier)
                except ValueError:
                    pass
                break
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific component."""
    return logging.getLogger(f"lan_security_system.{name}")