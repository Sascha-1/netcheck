"""
Tests for utils.system module.

Tests command execution and IP address validation functions.
Enhanced with comprehensive edge case testing.
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
    is_valid_ip,
    validate_interface_name,
    sanitize_for_log,
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


class TestValidateInterfaceName:
    """Test validate_interface_name function."""

    def test_valid_interface_names(self) -> None:
        """Test various valid interface names."""
        valid_names = [
            "eth0", "eth1", "wlan0",
            "enp3s0", "wlp8s0",
            "tun0", "tap0", "vpn0",
            "br0", "docker0",
            "veth123abc",
            "usb0",
            "lo",
        ]
        for name in valid_names:
            assert validate_interface_name(name) is True, f"{name} should be valid"

    def test_invalid_interface_names(self) -> None:
        """Test various invalid interface names (injection attempts)."""
        invalid_names = [
            "eth0; rm -rf /",      # Command injection
            "eth0 && curl evil",   # Command chaining
            "eth0|nc",            # Pipe
            "eth0`whoami`",       # Command substitution
            "eth0$(whoami)",      # Command substitution
            "eth0'test",          # Quote
            'eth0"test',          # Quote
            "eth0<test",          # Redirect
            "eth0>test",          # Redirect
            "/etc/passwd",        # Path separator
            "eth0\\test",         # Backslash
            "eth0\neth1",         # Newline injection
            "eth0\reth1",         # Carriage return
        ]
        for name in invalid_names:
            assert validate_interface_name(name) is False, f"{name} should be invalid"

    def test_edge_cases(self) -> None:
        """Test edge cases for interface name validation."""
        assert validate_interface_name("") is False
        assert validate_interface_name("a" * 65) is False  # Too long
        assert validate_interface_name("a" * 64) is True   # Max length

    def test_special_characters_allowed(self) -> None:
        """Test that allowed special characters work."""
        valid_with_special = [
            "eth0.100",     # VLAN
            "eth0:1",       # Alias
            "eth-wan",      # Hyphen
            "eth_backup",   # Underscore
        ]
        for name in valid_with_special:
            assert validate_interface_name(name) is True, f"{name} should be valid"


class TestSanitizeForLog:
    """Test sanitize_for_log function."""

    def test_normal_text(self) -> None:
        """Test that normal text passes through unchanged."""
        assert sanitize_for_log("normal text") == "normal text"
        assert sanitize_for_log("test123") == "test123"

    def test_newline_replacement(self) -> None:
        """Test that newlines are replaced with spaces."""
        assert sanitize_for_log("line1\nline2") == "line1 line2"
        assert sanitize_for_log("line1\rline2") == "line1 line2"
        assert sanitize_for_log("line1\r\nline2") == "line1  line2"

    def test_ansi_escape_removal(self) -> None:
        """Test that ANSI escape codes are removed."""
        assert sanitize_for_log("\x1b[31mred\x1b[0m") == "red"
        assert sanitize_for_log("\x1b[1;32mgreen\x1b[0m") == "green"
        assert sanitize_for_log("normal\x1b[91mred\x1b[0m") == "normalred"

    def test_control_character_removal(self) -> None:
        """Test that control characters are removed."""
        assert sanitize_for_log("test\x00null") == "testnull"
        assert sanitize_for_log("test\x07bell") == "testbell"
        assert sanitize_for_log("test\x1b[31m\nred") == "test red"

    def test_none_handling(self) -> None:
        """Test that None is converted to 'None'."""
        assert sanitize_for_log(None) == "None"

    def test_length_limiting(self) -> None:
        """Test that long strings are truncated."""
        long_text = "a" * 300
        result = sanitize_for_log(long_text)
        assert len(result) <= 200
        assert result.endswith("...")

    def test_combined_attacks(self) -> None:
        """Test combination of multiple attack vectors."""
        malicious = "normal\ntext\x1b[31m\x00with\x07stuff"
        result = sanitize_for_log(malicious)
        assert "\n" not in result
        assert "\x00" not in result
        assert "\x07" not in result
        assert "\x1b" not in result

    def test_various_types(self) -> None:
        """Test sanitization of various types."""
        assert sanitize_for_log(123) == "123"
        assert sanitize_for_log(45.67) == "45.67"
        assert sanitize_for_log(True) == "True"


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

    def test_ipv4_leading_zeros(self) -> None:
        """Test IPv4 with leading zeros."""
        # Leading zeros are technically valid in the regex
        assert is_valid_ipv4("192.168.001.001") is True
        assert is_valid_ipv4("010.010.010.010") is True

    def test_ipv4_private_ranges(self) -> None:
        """Test common private IPv4 ranges."""
        private_ranges = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "127.0.0.1",
        ]
        for addr in private_ranges:
            assert is_valid_ipv4(addr) is True, f"{addr} should be valid"


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

    def test_ipv6_mixed_notation(self) -> None:
        """Test IPv6 with embedded IPv4 (mixed notation)."""
        assert is_valid_ipv6("::192.0.2.1") is True
        assert is_valid_ipv6("::ffff:192.0.2.1") is True
        assert is_valid_ipv6("64:ff9b::192.0.2.1") is True

    def test_ipv6_multicast(self) -> None:
        """Test IPv6 multicast addresses."""
        assert is_valid_ipv6("ff02::1") is True
        assert is_valid_ipv6("ff02::2") is True

    def test_ipv6_all_zeros(self) -> None:
        """Test various representations of all-zeros address."""
        assert is_valid_ipv6("::") is True
        assert is_valid_ipv6("0:0:0:0:0:0:0:0") is True
        assert is_valid_ipv6("0000:0000:0000:0000:0000:0000:0000:0000") is True

    def test_ipv6_loopback(self) -> None:
        """Test IPv6 loopback address representations."""
        assert is_valid_ipv6("::1") is True
        assert is_valid_ipv6("0:0:0:0:0:0:0:1") is True


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

    def test_mixed_notation(self) -> None:
        """Test IPv6 addresses with embedded IPv4."""
        assert is_valid_ip("::ffff:192.0.2.1") is True
        assert is_valid_ip("::192.0.2.1") is True


class TestIPValidationConsistency:
    """Test consistency and correctness of IP validation."""

    def test_ipv4_does_not_validate_as_ipv6(self) -> None:
        """Test that IPv4 addresses don't validate as IPv6."""
        ipv4_addresses = ["192.168.1.1", "8.8.8.8", "10.0.0.1"]
        for addr in ipv4_addresses:
            assert is_valid_ipv4(addr) is True
            assert is_valid_ipv6(addr) is False
            assert is_valid_ip(addr) is True

    def test_ipv6_does_not_validate_as_ipv4(self) -> None:
        """Test that IPv6 addresses don't validate as IPv4."""
        ipv6_addresses = ["2001:db8::1", "::1", "fe80::1"]
        for addr in ipv6_addresses:
            assert is_valid_ipv6(addr) is True
            assert is_valid_ipv4(addr) is False
            assert is_valid_ip(addr) is True

    def test_completely_invalid(self) -> None:
        """Test completely invalid inputs fail all validators."""
        invalid = ["not-an-ip", "xyz", "12.34.56", "gggg::1"]
        for addr in invalid:
            assert is_valid_ipv4(addr) is False
            assert is_valid_ipv6(addr) is False
            assert is_valid_ip(addr) is False

    def test_repeated_validation_consistency(self) -> None:
        """Test that repeated validation gives consistent results."""
        test_cases = [
            ("192.168.1.1", True),
            ("2001:db8::1", True),
            ("invalid", False),
            ("256.256.256.256", False),
        ]

        for addr, expected in test_cases:
            # Validate multiple times to ensure consistency
            for _ in range(3):
                result = is_valid_ip(addr)
                assert result == expected, f"Inconsistent result for {addr}"
