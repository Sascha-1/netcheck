"""
Tests for logging configuration.

Verifies logging setup and filtering work correctly.
"""

from models import InterfaceInfo, EgressInfo

from typing import Any, Dict, List, Optional, Generator
from pathlib import Path
from unittest.mock import MagicMock
from _pytest.logging import LogCaptureFixture
from _pytest.capture import CaptureFixture
from _pytest.config import Config
from _pytest.monkeypatch import MonkeyPatch


import pytest
import logging
from logging_config import VerboseFilter, setup_logging, get_logger


class TestVerboseFilter:
    """Test VerboseFilter class."""

    def test_verbose_mode_allows_debug(self) -> None:

        """Test that verbose mode allows DEBUG messages."""
        filter = VerboseFilter(verbose=True)

        # Create mock record
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None
        )

        assert filter.filter(record) is True

    def test_non_verbose_blocks_debug(self) -> None:

        """Test that non-verbose mode blocks DEBUG messages."""
        filter = VerboseFilter(verbose=False)

        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None
        )

        assert filter.filter(record) is False

    def test_always_allows_info_and_above(self) -> None:

        """Test that INFO and above always pass through."""
        filter = VerboseFilter(verbose=False)

        for level in [logging.INFO, logging.WARNING, logging.ERROR]:
            record = logging.LogRecord(
                name="test",
                level=level,
                pathname="",
                lineno=0,
                msg="test",
                args=(),
                exc_info=None
            )
            assert filter.filter(record) is True


class TestLoggingSetup:
    """Test logging setup function."""

    def test_setup_logging_basic(self) -> None:

        """Test basic logging setup."""
        setup_logging(verbose=False, use_colors=False)
        logger = get_logger("test")

        # Should have logger
        assert logger is not None
        assert logger.name == "test"

    def test_get_logger(self) -> None:

        """Test get_logger function."""
        logger1 = get_logger("module1")
        logger2 = get_logger("module2")

        assert logger1.name == "module1"
        assert logger2.name == "module2"
        assert logger1 is not logger2

