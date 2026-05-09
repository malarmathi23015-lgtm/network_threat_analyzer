"""
============================================================
core/logger.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Sets up a centralized logging system used by every module.
    All logs go to both the terminal (with colors) and a log file.

BEGINNER NOTE:
    Logging is like print() but smarter:
    - It adds timestamps automatically
    - You can control how much detail to show (DEBUG/INFO/WARNING/ERROR)
    - Logs are saved to a file for later review
============================================================
"""

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

try:
    import colorlog  # Adds color to terminal output
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


def setup_logger(name: str, log_level: str = "INFO") -> logging.Logger:
    """
    Create and return a logger with the given name.

    Args:
        name (str): Logger name, usually the module name e.g. 'PacketCapture'
        log_level (str): Minimum level to log. Options: DEBUG, INFO, WARNING, ERROR

    Returns:
        logging.Logger: Configured logger instance

    Example:
        logger = setup_logger("MyModule", "DEBUG")
        logger.info("System started")
        logger.error("Something went wrong!")
    """

    # Make sure the logs directory exists
    os.makedirs("logs", exist_ok=True)

    # Convert string level to logging constant (e.g. "INFO" -> 20)
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Create a logger with the given name
    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # -----------------------------------------------------------------
    # FILE HANDLER: Saves logs to a rotating file (max 5MB, keeps 3 files)
    # -----------------------------------------------------------------
    log_filename = f"logs/analyzer_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=5 * 1024 * 1024,  # 5 MB max per file
        backupCount=3               # Keep last 3 log files
    )
    file_handler.setLevel(numeric_level)

    # Format: 2024-01-01 12:00:00 | INFO     | PacketCapture | Message here
    file_format = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)

    # -----------------------------------------------------------------
    # CONSOLE HANDLER: Prints logs to terminal, with color if available
    # -----------------------------------------------------------------
    if HAS_COLOR:
        # Color scheme: DEBUG=cyan, INFO=green, WARNING=yellow, ERROR=red
        console_format = colorlog.ColoredFormatter(
            fmt="%(log_color)s%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s%(reset)s",
            datefmt="%H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "bold_red",
            }
        )
    else:
        # Plain format without colors
        console_format = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
            datefmt="%H:%M:%S"
        )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(console_format)

    # Add both handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Quick shorthand to get an existing logger or create one with defaults.

    Args:
        name (str): Logger name

    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(name)
