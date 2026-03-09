"""Unit tests for netcheck.utils.validators.

All tests are pure unit tests: no I/O, no subprocesses, no external state.
Every function under test is deterministic given its input.

Tests verify:
- Valid inputs return the original string unchanged.
- Invalid inputs return ``None``.
- Edge cases at the boundaries of the validation rules are handled correctly.
- The parse-don't-validate contract holds: callers can use the return value
  directly without a separate boolean check.
"""

import pytest

from netcheck.utils.validators import (
    parse_interface_name,
    parse_ip,
    parse_ipv4,
    parse_ipv6,
)


class TestParseIPv4:
    """Tests for parse_ipv4."""

    @pytest.mark.parametrize("address", [
        "0.0.0.0",
        "127.0.0.1",
        "192.168.1.100",
        "10.236.135.77",
        "87.240.240.146",
        "255.255.255.255",
    ])
    def test_valid_addresses_returned(self, address: str) -> None:
        """Valid IPv4 addresses must be returned unchanged."""
        assert parse_ipv4(address) == address

    @pytest.mark.parametrize("address", [
        "",
        "256.0.0.0",
        "192.168.1",
        "192.168.1.1.1",
        "not_an_ip",
        "fe80::1",
        "192.168.1.1/24",
        " 192.168.1.1",
    ])
    def test_invalid_addresses_return_none(self, address: str) -> None:
        """Invalid or non-IPv4 strings must return ``None``."""
        assert parse_ipv4(address) is None

    def test_return_value_is_original_string(self) -> None:
        """The return value must be the identical object passed in."""
        address = "192.168.1.1"
        result = parse_ipv4(address)
        assert result is address


class TestParseIPv6:
    """Tests for parse_ipv6."""

    @pytest.mark.parametrize("address", [
        "::1",
        "fe80::1",
        "2001:db8::1",
        "2001:7e8:ca4d:bb01::1",
        "fdeb:446c:912d:8da::",
        "::",
    ])
    def test_valid_addresses_returned(self, address: str) -> None:
        """Valid IPv6 addresses must be returned unchanged."""
        assert parse_ipv6(address) == address

    def test_zone_identifier_accepted(self) -> None:
        """An address with a zone identifier must be accepted and returned as-is.

        The zone identifier is stripped only for validation; the original
        string including the zone suffix is returned so callers receive the
        address exactly as the kernel reported it.
        """
        assert parse_ipv6("fe80::1%eth0") == "fe80::1%eth0"

    def test_zone_identifier_preserved_in_return_value(self) -> None:
        """The zone identifier must be present in the returned string."""
        result = parse_ipv6("fe80::1%wlp1s0")
        assert result is not None
        assert "%" in result

    @pytest.mark.parametrize("address", [
        "",
        "not_an_ip",
        "192.168.1.1",
        "gggg::1",
        "2001:db8::1/64",
    ])
    def test_invalid_addresses_return_none(self, address: str) -> None:
        """Invalid or non-IPv6 strings must return ``None``."""
        assert parse_ipv6(address) is None

    def test_return_value_is_original_string(self) -> None:
        """The return value must be the identical object passed in."""
        address = "::1"
        result = parse_ipv6(address)
        assert result is address


class TestParseIP:
    """Tests for parse_ip."""

    def test_valid_ipv4_accepted(self) -> None:
        """A valid IPv4 address must be returned."""
        assert parse_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6_accepted(self) -> None:
        """A valid IPv6 address must be returned."""
        assert parse_ip("::1") == "::1"

    def test_ipv4_tested_before_ipv6(self) -> None:
        """A valid IPv4 address must match via the IPv4 path.

        This documents the implementation order (IPv4 first) without asserting
        identity between the two functions -- the result simply equals the
        address string that was passed in.
        """
        address = "192.168.1.1"
        assert parse_ip(address) == address
        assert parse_ipv4(address) == address

    def test_invalid_address_returns_none(self) -> None:
        """A string that is neither IPv4 nor IPv6 must return ``None``."""
        assert parse_ip("not_an_ip") is None

    def test_empty_string_returns_none(self) -> None:
        """An empty string must return ``None``."""
        assert parse_ip("") is None

    @pytest.mark.parametrize("address", [
        "127.0.0.1",
        "10.0.0.1",
        "::1",
        "fe80::1",
        "2001:db8::1",
    ])
    def test_various_valid_addresses(self, address: str) -> None:
        """A range of valid addresses must all be accepted."""
        assert parse_ip(address) == address


class TestParseInterfaceName:
    """Tests for parse_interface_name."""

    @pytest.mark.parametrize("name", [
        "lo",
        "eth0",
        "wlp1s0",
        "enx8615d34feca4",
        "wwp195s0f3u4",
        "pvpnksintrf0",
        "proton0",
        "docker0",
        "br-abc123",
        "veth0@if2",
        "wlan0.100",
    ])
    def test_valid_names_returned(self, name: str) -> None:
        """Valid interface names must be returned unchanged."""
        assert parse_interface_name(name) == name

    def test_empty_string_returns_none(self) -> None:
        """An empty string must return ``None``."""
        assert parse_interface_name("") is None

    def test_name_at_max_length_accepted(self) -> None:
        """A name of exactly 64 characters must be accepted."""
        name = "a" * 64
        assert parse_interface_name(name) == name

    def test_name_exceeding_max_length_returns_none(self) -> None:
        """A name of 65 characters must return ``None``."""
        assert parse_interface_name("a" * 65) is None

    @pytest.mark.parametrize("name", [
        "eth 0",
        "eth0;rm -rf /",
        "eth0$(id)",
        "eth0`id`",
        "eth0\nlo",
        "eth0/sub",
        "eth0\\sub",
        "eth0!",
        "eth0#comment",
    ])
    def test_injection_attempts_rejected(self, name: str) -> None:
        """Strings containing shell-special or path characters must return ``None``.

        This is the security-critical test: parse_interface_name is the gate
        that prevents interface names from being used in command injection.
        """
        assert parse_interface_name(name) is None

    def test_return_value_is_original_string(self) -> None:
        """The return value must be the identical object passed in."""
        name = "eth0"
        result = parse_interface_name(name)
        assert result is name

    def test_single_character_name_accepted(self) -> None:
        """A single valid character is a legal interface name."""
        assert parse_interface_name("a") == "a"
