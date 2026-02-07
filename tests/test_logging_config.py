"""
Tests for logging configuration - UPDATED for WARNING default level.

Verifies logging setup and filtering work correctly with new behavior:
- Default mode: Shows WARNING and above only
- Verbose mode: Shows DEBUG and above (everything)
"""

import pytest
import logging
from logging_config import VerboseFilter, setup_logging, get_logger


class TestVerboseFilter:
    """Test VerboseFilter class."""

    def test_verbose_mode_allows_debug(self) -> None:
        """Test that verbose mode allows DEBUG messages."""
        verbose_filter = VerboseFilter(verbose=True)

        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None
        )

        assert verbose_filter.filter(record) is True

    def test_non_verbose_blocks_debug(self) -> None:
        """Test that non-verbose mode blocks DEBUG messages."""
        verbose_filter = VerboseFilter(verbose=False)

        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None
        )

        assert verbose_filter.filter(record) is False

    def test_non_verbose_blocks_info(self) -> None:
        """Test that non-verbose mode blocks INFO messages."""
        verbose_filter = VerboseFilter(verbose=False)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None
        )

        # UPDATED: INFO is now blocked in default mode (like DEBUG)
        assert verbose_filter.filter(record) is False

    def test_always_allows_warning_and_above(self) -> None:
        """Test that WARNING and above always pass through."""
        verbose_filter = VerboseFilter(verbose=False)

        # UPDATED: Only WARNING and above pass in default mode
        for level in [logging.WARNING, logging.ERROR, logging.CRITICAL]:
            record = logging.LogRecord(
                name="test",
                level=level,
                pathname="",
                lineno=0,
                msg="test",
                args=(),
                exc_info=None
            )
            assert verbose_filter.filter(record) is True


class TestLoggingSetup:
    """Test logging setup function."""

    def test_default_mode_uses_warning_filter(self) -> None:
        """Test that default mode filters out DEBUG and INFO messages."""
        setup_logging(verbose=False, use_colors=False)
        logger = get_logger("test")

        # Root logger is always DEBUG, filtering happens at handler level
        assert logger.getEffectiveLevel() == logging.DEBUG

        # Check that console handler has the verbose filter configured for WARNING
        root = logging.getLogger()
        assert len(root.handlers) > 0
        console_handler = root.handlers[0]
        assert console_handler.level == logging.WARNING

    def test_verbose_mode_enables_debug(self) -> None:
        """Test that verbose mode enables DEBUG level on handler."""
        setup_logging(verbose=True, use_colors=False)
        logger = get_logger("test")

        # Root logger is DEBUG
        assert logger.getEffectiveLevel() == logging.DEBUG

        # Console handler should be DEBUG too
        root = logging.getLogger()
        console_handler = root.handlers[0]
        assert console_handler.level == logging.DEBUG

    def test_urllib3_suppressed_in_default_mode(self) -> None:
        """Test that urllib3 is suppressed in default mode."""
        setup_logging(verbose=False, use_colors=False)
        urllib3_logger = logging.getLogger('urllib3')

        assert urllib3_logger.level == logging.WARNING

    def test_requests_suppressed_in_default_mode(self) -> None:
        """Test that requests is suppressed in default mode."""
        setup_logging(verbose=False, use_colors=False)
        requests_logger = logging.getLogger('requests')

        assert requests_logger.level == logging.WARNING

    def test_urllib3_not_suppressed_in_verbose_mode(self) -> None:
        """Test that urllib3 is reset to NOTSET in verbose mode (inherits DEBUG)."""
        setup_logging(verbose=True, use_colors=False)
        urllib3_logger = logging.getLogger('urllib3')

        # In verbose mode, we explicitly set to NOTSET so it inherits from root
        assert urllib3_logger.level == logging.NOTSET

    def test_requests_not_suppressed_in_verbose_mode(self) -> None:
        """Test that requests is reset to NOTSET in verbose mode (inherits DEBUG)."""
        setup_logging(verbose=True, use_colors=False)
        requests_logger = logging.getLogger('requests')

        # In verbose mode, we explicitly set to NOTSET so it inherits from root
        assert requests_logger.level == logging.NOTSET

    def test_get_logger(self) -> None:
        """Test get_logger function."""
        logger1 = get_logger("module1")
        logger2 = get_logger("module2")

        assert logger1.name == "module1"
        assert logger2.name == "module2"
        assert logger1 is not logger2
