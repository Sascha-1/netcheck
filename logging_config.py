"""
Logging configuration for netcheck.

Provides structured logging throughout the application with configurable
verbosity levels. Replaces scattered print() statements with proper logging.

UPDATED:
- Default mode shows WARNING+ only (not INFO)
- Verbose mode shows DEBUG+ including third-party libraries
- Third-party library noise (urllib3, requests) suppressed in default mode

Security:
    All log messages should use sanitize_for_log() from utils.system
    to prevent log injection attacks.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class VerboseFilter(logging.Filter):
    """
    Filter that shows verbose messages only when verbose mode is enabled.

    Messages at WARNING level and above always pass through.
    DEBUG and INFO messages only pass when verbose mode is enabled.

    This allows users to run the tool in quiet mode (default) or verbose mode (-v).
    
    UPDATED: Default mode now shows only WARNING+ (not INFO+)
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize the filter.

        Args:
            verbose: If True, allow DEBUG and INFO messages through
        """
        super().__init__()
        self.verbose = verbose

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Determine if record should be logged.

        Args:
            record: Log record to filter

        Returns:
            True if record should be logged
        """
        # WARNING and above always pass through
        if record.levelno >= logging.WARNING:
            return True
        
        # DEBUG and INFO only pass in verbose mode
        return self.verbose


class ColoredFormatter(logging.Formatter):
    """
    Formatter that adds color codes to log messages for terminal output.

    Uses ANSI escape codes for colored output in terminals that support it.

    Color scheme:
        DEBUG: Cyan (informational)
        INFO: Green (success/progress)
        WARNING: Yellow (caution)
        ERROR: Red (error)
        CRITICAL: Magenta (severe)
    """

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with color codes.

        Args:
            record: Log record to format

        Returns:
            Formatted log message with color codes
        """
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(
    verbose: bool = False,
    log_file: Optional[Path] = None,
    use_colors: bool = True
) -> None:
    """
    Configure application-wide logging.

    Sets up logging handlers for both console and optional file output.
    Console output uses colored formatting, file output uses plain text.

    UPDATED Logging Behavior:
        Default mode (verbose=False):
            - Shows WARNING and above only
            - Suppresses urllib3/requests DEBUG noise
            - Clean output for normal usage
        
        Verbose mode (verbose=True):
            - Shows DEBUG and above for all loggers
            - Includes urllib3/requests connection details
            - Complete debugging information

    Logging Levels:
        DEBUG: Detailed diagnostic information (only shown with -v)
        INFO: General informational messages (only shown with -v)
        WARNING: Warning messages (always shown)
        ERROR: Error messages (always shown)
        CRITICAL: Critical errors (always shown)

    Args:
        verbose: If True, enable DEBUG level logging (shows everything)
        log_file: Optional file path to write logs to
        use_colors: If True, use colored output for console (default: True)
                   Set to False with --no-color flag (if implemented)

    Examples:
        Default mode (quiet):
        >>> setup_logging(verbose=False)
        >>> # Only warnings/errors shown
        
        Verbose mode (debugging):
        >>> setup_logging(verbose=True)
        >>> # Shows DEBUG, INFO, WARNING, ERROR, CRITICAL
        
        With log file:
        >>> setup_logging(verbose=True, log_file=Path("netcheck.log"))
        >>> # Logs everything to file, respects verbose for console

    Security:
        All log messages should use sanitize_for_log() from utils.system
        to prevent log injection attacks.
    """
    # UPDATED: Default level is WARNING (not INFO)
    # This makes default mode quiet - only shows warnings and errors
    level = logging.DEBUG if verbose else logging.WARNING

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    # Add verbose filter to console handler
    console_handler.addFilter(VerboseFilter(verbose))

    # Choose formatter based on color preference FOR CONSOLE ONLY
    console_formatter: logging.Formatter
    if use_colors:
        console_formatter = ColoredFormatter(
            '%(levelname)s: %(message)s'
        )
    else:
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )

    console_handler.setFormatter(console_formatter)

    # Prepare list of handlers
    handlers: list[logging.Handler] = [console_handler]

    # Add file handler if log file specified - ALWAYS use plain formatter
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file

        # ALWAYS use plain formatter for files (NO COLOR CODES)
        # File logs should never contain ANSI escape sequences
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=logging.DEBUG,  # Root level is DEBUG, handlers filter
        handlers=handlers,
        force=True  # Override any existing configuration
    )

    # UPDATED: Suppress third-party library noise in default mode only
    # urllib3 and requests log verbose DEBUG messages about HTTP connections
    # that are not useful for normal users
    #
    # Examples of suppressed messages:
    #   DEBUG: Starting new HTTPS connection (1): ipinfo.io:443
    #   DEBUG: https://ipinfo.io:443 "GET /json HTTP/1.1" 200 None
    #
    # In verbose mode (-v), these are shown for complete debugging
    if not verbose:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
    # In verbose mode, leave them at DEBUG level (show everything)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Best Practice:
        Call this at module level with __name__:

        ```python
        from logging_config import get_logger
        logger = get_logger(__name__)

        # Then use throughout the module with PEP 391 style:
        logger.debug("Debug message: %s", variable)
        logger.info("Info message: %s %s", var1, var2)
        logger.warning("Warning message: %s", variable)
        logger.error("Error message: %s", variable)
        ```

    Security:
        Always sanitize user-controlled data before logging:

        ```python
        from utils.system import sanitize_for_log

        # WRONG - Potential log injection:
        logger.debug("Processing %s", user_input)

        # CORRECT - Sanitized:
        logger.debug("Processing %s", sanitize_for_log(user_input))
        ```

    Args:
        name: Module name, typically __name__

    Returns:
        Logger instance for the module
    """
    return logging.getLogger(name)
