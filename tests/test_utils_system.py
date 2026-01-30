"""
Tests for utils.system module.

Tests command execution and IP address validation functions.
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
import subprocess
from unittest.mock import Mock, patch
from utils.system import (
    run_command,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_ip
)


class TestRunCommand:
    """Test run_command function."""
    
    def test_successful_command(self, mock_subprocess_run: MagicMock) -> None:

        """Test successful command execution."""
        mock_result = Mock()
        mock_result.stdout = "command output\n"
        mock_subprocess_run.return_value = mock_result
        
        result = run_command(["echo", "test"])
        
        assert result == "command output"
        mock_subprocess_run.assert_called_once()
        call_args = mock_subprocess_run.call_args
        assert call_args[0][0] == ["echo", "test"]
        assert call_args[1]["capture_output"] is True
        assert call_args[1]["text"] is True
        assert call_args[1]["check"] is True
    
    def test_command_with_timeout(self, mock_subprocess_run: MagicMock) -> None:

        """Test that timeout is configured."""
        mock_result = Mock()
        mock_result.stdout = "output"
        mock_subprocess_run.return_value = mock_result
        
        run_command(["test"])
        
        call_args = mock_subprocess_run.call_args
        assert "timeout" in call_args[1]
        assert call_args[1]["timeout"] > 0
    
    def test_command_failure(self, mock_subprocess_run: MagicMock) -> None:

        """Test handling of command failure."""
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "cmd")
        
        result = run_command(["false"])
        
        assert result is None
    
    def test_command_timeout(self, mock_subprocess_run: MagicMock) -> None:

        """Test handling of command timeout."""
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired("cmd", 10)
        
        result = run_command(["sleep", "100"])
        
        assert result is None
    
    def test_command_not_found(self, mock_subprocess_run: MagicMock) -> None:

        """Test handling of command not found."""
        mock_subprocess_run.side_effect = FileNotFoundError()
        
        result = run_command(["nonexistent"])
        
        assert result is None
    
    def test_output_stripping(self, mock_subprocess_run: MagicMock) -> None:

        """Test that output is stripped of whitespace."""
        mock_result = Mock()
        mock_result.stdout = "  output with spaces  \n"
        mock_subprocess_run.return_value = mock_result
        
        result = run_command(["test"])
        
        assert result == "output with spaces"
    
    def test_empty_output(self, mock_subprocess_run: MagicMock) -> None:

        """Test handling of empty output."""
        mock_result = Mock()
        mock_result.stdout = ""
        mock_subprocess_run.return_value = mock_result
        
        result = run_command(["test"])
        
        assert result == ""


class TestIsValidIPv4:
    """Test IPv4 address validation."""
    
    def test_valid_ipv4_addresses(self) -> None:

        """Test various valid IPv4 addresses."""
        valid_addresses = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "255.255.255.255",
            "0.0.0.0",
            "127.0.0.1",
            "1.2.3.4"
        ]
        
        for addr in valid_addresses:
            assert is_valid_ipv4(addr) is True, f"{addr} should be valid"
    
    def test_invalid_ipv4_addresses(self) -> None:

        """Test various invalid IPv4 addresses."""
        invalid_addresses = [
            "256.1.1.1",      # Octet > 255
            "1.2.3",          # Too few octets
            "1.2.3.4.5",      # Too many octets
            "1.2.3.abc",      # Non-numeric
            "1.2.3.-4",       # Negative number
            "1.2.3.4.5.6",    # Way too many octets
            "",               # Empty string
            "not an ip",      # Not an IP
            "2001:db8::1",    # IPv6, not IPv4
            "192.168.1",      # Incomplete
            "192.168.1.1.1",  # Too many parts
        ]
        
        for addr in invalid_addresses:
            assert is_valid_ipv4(addr) is False, f"{addr} should be invalid"
    
    def test_ipv4_edge_cases(self) -> None:

        """Test edge cases for IPv4 validation."""
        assert is_valid_ipv4(None) is False
        assert is_valid_ipv4("") is False
        assert is_valid_ipv4("   ") is False
    
    def test_ipv4_with_whitespace(self) -> None:

        """Test IPv4 with whitespace (should be invalid)."""
        assert is_valid_ipv4(" 192.168.1.1") is False
        assert is_valid_ipv4("192.168.1.1 ") is False
        assert is_valid_ipv4("192. 168.1.1") is False
    
    def test_ipv4_boundary_values(self) -> None:

        """Test boundary values for IPv4 octets."""
        assert is_valid_ipv4("0.0.0.0") is True
        assert is_valid_ipv4("255.255.255.255") is True
        assert is_valid_ipv4("256.0.0.0") is False
        assert is_valid_ipv4("0.0.0.256") is False
    
    def test_ipv4_caching(self) -> None:

        """Test that function caching works."""
        # Call twice with same input
        result1 = is_valid_ipv4("192.168.1.1")
        result2 = is_valid_ipv4("192.168.1.1")
        
        # Both should return True
        assert result1 is True
        assert result2 is True


class TestIsValidIPv6:
    """Test IPv6 address validation."""
    
    def test_valid_ipv6_addresses(self) -> None:

        """Test various valid IPv6 addresses."""
        valid_addresses = [
            "2001:db8::1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "::1",
            "::",
            "fe80::1",
            "2001:db8:85a3::8a2e:370:7334",
            "2001:db8::8a2e:370:7334",
            "::ffff:192.0.2.1",  # IPv4-mapped IPv6
            "2001:db8::",
            "::2001:db8:1",
            "2a07:b944::2:2"
        ]
        
        for addr in valid_addresses:
            assert is_valid_ipv6(addr) is True, f"{addr} should be valid"
    
    def test_invalid_ipv6_addresses(self) -> None:

        """Test various invalid IPv6 addresses."""
        invalid_addresses = [
            "192.168.1.1",         # IPv4, not IPv6
            "gggg::1",             # Invalid hex
            "2001:db8::1::2",      # Double ::
            ":2001:db8::1",        # Starts with single :
            "2001:db8::1:",        # Ends with single :
            "",                    # Empty string
            "not an ip",           # Not an IP
            "2001:db8:0:0:0:0:0:0:0",  # Too many groups
            ":::",                 # Triple colon
            "2001:db8::gggg",      # Invalid hex characters
            "2001:db8::12345",     # Group too long (>4 hex digits)
        ]
        
        for addr in invalid_addresses:
            assert is_valid_ipv6(addr) is False, f"{addr} should be invalid"
    
    def test_ipv6_edge_cases(self) -> None:

        """Test edge cases for IPv6 validation."""
        assert is_valid_ipv6(None) is False
        assert is_valid_ipv6("") is False
        assert is_valid_ipv6("   ") is False
    
    def test_ipv6_compression(self) -> None:

        """Test IPv6 address compression (::)."""
        # Various compression formats
        assert is_valid_ipv6("::") is True
        assert is_valid_ipv6("::1") is True
        assert is_valid_ipv6("2001::") is True
        assert is_valid_ipv6("2001:db8::1") is True
        assert is_valid_ipv6("::ffff:192.0.2.1") is True
    
    def test_ipv6_case_insensitive(self) -> None:

        """Test that IPv6 validation is case-insensitive."""
        assert is_valid_ipv6("2001:DB8::1") is True
        assert is_valid_ipv6("2001:Db8::1") is True
        assert is_valid_ipv6("ABCD:EF01::1") is True
    
    def test_ipv6_full_address(self) -> None:

        """Test full uncompressed IPv6 addresses."""
        full_addr = "2001:0db8:0000:0000:0000:0000:0000:0001"
        assert is_valid_ipv6(full_addr) is True
    
    def test_ipv6_link_local(self) -> None:

        """Test link-local IPv6 addresses."""
        assert is_valid_ipv6("fe80::1") is True
        assert is_valid_ipv6("fe80::211:22ff:fe33:4455") is True
    
    def test_ipv6_caching(self) -> None:

        """Test that function caching works."""
        result1 = is_valid_ipv6("2001:db8::1")
        result2 = is_valid_ipv6("2001:db8::1")
        
        assert result1 is True
        assert result2 is True


class TestIsValidIP:
    """Test combined IP (IPv4 or IPv6) validation."""
    
    def test_valid_ipv4_via_is_valid_ip(self) -> None:

        """Test that valid IPv4 passes through is_valid_ip."""
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("10.0.0.1") is True
    
    def test_valid_ipv6_via_is_valid_ip(self) -> None:

        """Test that valid IPv6 passes through is_valid_ip."""
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("::1") is True
        assert is_valid_ip("fe80::1") is True
    
    def test_invalid_addresses(self) -> None:

        """Test that invalid addresses fail."""
        assert is_valid_ip("") is False
        assert is_valid_ip("not an ip") is False
        assert is_valid_ip("256.256.256.256") is False
        assert is_valid_ip("gggg::1") is False
    
    def test_edge_cases(self) -> None:

        """Test edge cases."""
        assert is_valid_ip(None) is False
        assert is_valid_ip("") is False
        assert is_valid_ip("   ") is False
    
    def test_caching(self) -> None:

        """Test that caching works for is_valid_ip."""
        # Call multiple times
        result1 = is_valid_ip("192.168.1.1")
        result2 = is_valid_ip("192.168.1.1")
        result3 = is_valid_ip("2001:db8::1")
        result4 = is_valid_ip("2001:db8::1")
        
        assert result1 is True
        assert result2 is True
        assert result3 is True
        assert result4 is True


class TestFunctionCaching:
    """Test that @cache decorator works correctly."""
    
    def test_ipv4_cache_different_inputs(self) -> None:

        """Test that cache stores different results for different inputs."""
        assert is_valid_ipv4("192.168.1.1") is True
        assert is_valid_ipv4("invalid") is False
        assert is_valid_ipv4("10.0.0.1") is True
        
        # Calling again should return cached results
        assert is_valid_ipv4("192.168.1.1") is True
        assert is_valid_ipv4("invalid") is False
    
    def test_ipv6_cache_different_inputs(self) -> None:

        """Test IPv6 cache with different inputs."""
        assert is_valid_ipv6("2001:db8::1") is True
        assert is_valid_ipv6("invalid") is False
        assert is_valid_ipv6("::1") is True
        
        # Cached results
        assert is_valid_ipv6("2001:db8::1") is True
        assert is_valid_ipv6("invalid") is False
