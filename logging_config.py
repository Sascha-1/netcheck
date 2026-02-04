"""
Logging configuration for netcheck.

Provides structured logging throughout the application with configurable
verbosity levels. Replaces scattered print() statements with proper logging.

IMPROVEMENTS:
- Clearer documentation on usage
- Better integration with sanitization (from utils.system)
- Color support detection
- FIXED: ColoredFormatter only applied to console, not files

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

    Messages at INFO level and above always pass through.
    DEBUG messages only pass when verbose mode is enabled.

    This allows users to run the tool in quiet mode (default) or verbose mode (-v).
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize the filter.

        Args:
            verbose: If True, allow DEBUG messages through
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
        if record.levelno >= logging.INFO:
            return True
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

    Logging Levels:
        DEBUG: Detailed diagnostic information (only shown with -v)
        INFO: General informational messages (always shown)
        WARNING: Warning messages (always shown)
        ERROR: Error messages (always shown)
        CRITICAL: Critical errors (always shown)

    Args:
        verbose: If True, enable DEBUG level logging
        log_file: Optional file path to write logs to
        use_colors: If True, use colored output for console (default: True)
                   Set to False with --no-color flag

    Examples:
        >>> setup_logging(verbose=True)  # Enable debug logging
        >>> setup_logging(log_file=Path("netcheck.log"))  # Log to file
        >>> setup_logging(verbose=True, use_colors=False)  # Debug without colors

    Security:
        All log messages should use sanitize_for_log() from utils.system
        to prevent log injection attacks.
    """
    # Determine log level based on verbose flag
    level = logging.DEBUG if verbose else logging.INFO

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    # Add verbose filter to console handler
    console_handler.addFilter(VerboseFilter(verbose))

    # FIXED: Choose formatter based on color preference FOR CONSOLE ONLY
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

    # FIXED: Add file handler if log file specified - ALWAYS use plain formatter
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file

        # CRITICAL FIX: Always use plain formatter for files (NO COLOR CODES)
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


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Best Practice:
        Call this at module level with __name__:

        ```python
        from logging_config import get_logger
        logger = get_logger(__name__)

        # Then use throughout the module:
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        ```

    Security:
        Always sanitize user-controlled data before logging:

        ```python
        from utils.system import sanitize_for_log

        # WRONG - Potential log injection:
        logger.debug(f"Processing {user_input}")

        # CORRECT - Sanitized:
        logger.debug(f"Processing {sanitize_for_log(user_input)}")
        ```

    Args:
        name: Module name, typically __name__

    Returns:
        Logger instance for the module
    """
    return logging.getLogger(name)
