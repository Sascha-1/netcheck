"""
Tests for configuration constants.

Ensures that all constants in config.py are properly defined,
sorted, and contain expected values.
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
from config import (
    REQUIRED_COMMANDS,
    INTERFACE_TYPE_PATTERNS,
    USB_TETHER_DRIVERS,
    PUBLIC_DNS_SERVERS,
    DNS_CURRENT_SERVER_MARKER,
    DNS_SERVERS_MARKER,
    DNS_GLOBAL_SECTION_MARKER,
    DNS_LINK_SECTION_MARKER,
    IPINFO_URL,
    IPINFO_IPv6_URL,
    DEVICE_NAME_CLEANUP,
    TIMEOUT_SECONDS,
    TABLE_COLUMNS,
    Colors,
)


class TestRequiredCommands:
    """Test REQUIRED_COMMANDS constant."""

    def test_required_commands_exist(self) -> None:
        """Test that REQUIRED_COMMANDS is defined."""
        assert REQUIRED_COMMANDS is not None
        assert isinstance(REQUIRED_COMMANDS, list)

    def test_required_commands_content(self) -> None:
        """Test that all expected commands are present."""
        expected = ["ip", "lspci", "lsusb", "ethtool", "resolvectl", "ss"]
        assert set(REQUIRED_COMMANDS) == set(expected)

    def test_no_duplicates(self) -> None:
        """Test that there are no duplicate commands."""
        assert len(REQUIRED_COMMANDS) == len(set(REQUIRED_COMMANDS))


class TestInterfaceTypePatterns:
    """Test INTERFACE_TYPE_PATTERNS constant."""

    def test_interface_patterns_exist(self) -> None:
        """Test that INTERFACE_TYPE_PATTERNS is defined."""
        assert INTERFACE_TYPE_PATTERNS is not None
        assert isinstance(INTERFACE_TYPE_PATTERNS, dict)

    def test_loopback_pattern(self) -> None:
        """Test loopback interface pattern."""
        assert INTERFACE_TYPE_PATTERNS["lo"] == "loopback"

    def test_ethernet_patterns(self) -> None:
        """Test ethernet interface patterns."""
        assert INTERFACE_TYPE_PATTERNS["eth"] == "ethernet"
        assert INTERFACE_TYPE_PATTERNS["en"] == "ethernet"

    def test_wireless_pattern(self) -> None:
        """Test wireless interface pattern."""
        assert INTERFACE_TYPE_PATTERNS["wl"] == "wireless"

    def test_vpn_patterns(self) -> None:
        """Test VPN interface patterns."""
        assert INTERFACE_TYPE_PATTERNS["vpn"] == "vpn"
        assert INTERFACE_TYPE_PATTERNS["tun"] == "vpn"
        assert INTERFACE_TYPE_PATTERNS["tap"] == "vpn"
        assert INTERFACE_TYPE_PATTERNS["ppp"] == "vpn"


class TestUsbTetherDrivers:
    """Test USB_TETHER_DRIVERS constant."""

    def test_usb_drivers_exist(self) -> None:
        """Test that USB_TETHER_DRIVERS is defined."""
        assert USB_TETHER_DRIVERS is not None
        assert isinstance(USB_TETHER_DRIVERS, list)

    def test_usb_drivers_sorted(self) -> None:
        """Test that USB drivers are alphabetically sorted."""
        assert USB_TETHER_DRIVERS == sorted(USB_TETHER_DRIVERS)

    def test_expected_drivers(self) -> None:
        """Test that expected drivers are present."""
        expected = ["cdc_ether", "cdc_mbim", "cdc_ncm", "ipheth", "rndis_host"]
        assert set(USB_TETHER_DRIVERS) == set(expected)

    def test_no_duplicates(self) -> None:
        """Test that there are no duplicate drivers."""
        assert len(USB_TETHER_DRIVERS) == len(set(USB_TETHER_DRIVERS))


class TestPublicDnsServers:
    """Test PUBLIC_DNS_SERVERS constant."""

    def test_public_dns_exist(self) -> None:
        """Test that PUBLIC_DNS_SERVERS is defined."""
        assert PUBLIC_DNS_SERVERS is not None
        assert isinstance(PUBLIC_DNS_SERVERS, set)

    def test_cloudflare_dns(self) -> None:
        """Test Cloudflare DNS servers are present."""
        assert "1.1.1.1" in PUBLIC_DNS_SERVERS
        assert "1.0.0.1" in PUBLIC_DNS_SERVERS
        assert "2606:4700:4700::1111" in PUBLIC_DNS_SERVERS

    def test_google_dns(self) -> None:
        """Test Google DNS servers are present."""
        assert "8.8.8.8" in PUBLIC_DNS_SERVERS
        assert "8.8.4.4" in PUBLIC_DNS_SERVERS
        assert "2001:4860:4860::8888" in PUBLIC_DNS_SERVERS

    def test_quad9_dns(self) -> None:
        """Test Quad9 DNS servers are present."""
        assert "9.9.9.9" in PUBLIC_DNS_SERVERS
        assert "149.112.112.112" in PUBLIC_DNS_SERVERS

    def test_opendns(self) -> None:
        """Test OpenDNS servers are present."""
        assert "208.67.222.222" in PUBLIC_DNS_SERVERS
        assert "208.67.220.220" in PUBLIC_DNS_SERVERS

    def test_adguard_dns(self) -> None:
        """Test AdGuard DNS servers are present."""
        assert "94.140.14.14" in PUBLIC_DNS_SERVERS
        assert "94.140.15.15" in PUBLIC_DNS_SERVERS

    def test_cloudflare_families(self) -> None:
        """Test Cloudflare for Families variants are present."""
        assert "1.1.1.2" in PUBLIC_DNS_SERVERS  # Malware blocking
        assert "1.1.1.3" in PUBLIC_DNS_SERVERS  # Malware + Adult content

    def test_no_invalid_ips(self) -> None:
        """Test that all entries are valid IP format."""
        from utils.system import is_valid_ip

        for dns in PUBLIC_DNS_SERVERS:
            assert is_valid_ip(dns), f"{dns} is not a valid IP"

    def test_ipv4_and_ipv6(self) -> None:
        """Test that both IPv4 and IPv6 addresses are present."""
        has_ipv4 = any("." in dns for dns in PUBLIC_DNS_SERVERS)
        has_ipv6 = any(":" in dns for dns in PUBLIC_DNS_SERVERS)

        assert has_ipv4, "Should contain IPv4 addresses"
        assert has_ipv6, "Should contain IPv6 addresses"


class TestDnsMarkers:
    """Test DNS parsing marker constants."""

    def test_current_server_marker(self) -> None:
        """Test DNS_CURRENT_SERVER_MARKER is defined."""
        assert DNS_CURRENT_SERVER_MARKER == "Current DNS Server:"

    def test_servers_marker(self) -> None:
        """Test DNS_SERVERS_MARKER is defined."""
        assert DNS_SERVERS_MARKER == "DNS Servers:"

    def test_global_section_marker(self) -> None:
        """Test DNS_GLOBAL_SECTION_MARKER is defined."""
        assert DNS_GLOBAL_SECTION_MARKER == "Global"

    def test_link_section_marker(self) -> None:
        """Test DNS_LINK_SECTION_MARKER is defined."""
        assert DNS_LINK_SECTION_MARKER == "Link "

    def test_markers_are_strings(self) -> None:
        """Test that all markers are strings."""
        assert isinstance(DNS_CURRENT_SERVER_MARKER, str)
        assert isinstance(DNS_SERVERS_MARKER, str)
        assert isinstance(DNS_GLOBAL_SECTION_MARKER, str)
        assert isinstance(DNS_LINK_SECTION_MARKER, str)

    def test_markers_not_empty(self) -> None:
        """Test that markers are not empty strings."""
        assert len(DNS_CURRENT_SERVER_MARKER) > 0
        assert len(DNS_SERVERS_MARKER) > 0
        assert len(DNS_GLOBAL_SECTION_MARKER) > 0
        assert len(DNS_LINK_SECTION_MARKER) > 0


class TestApiUrls:
    """Test external API URL constants."""

    def test_ipinfo_url(self) -> None:
        """Test IPINFO_URL is defined."""
        assert IPINFO_URL == "https://ipinfo.io/json"

    def test_ipinfo_ipv6_url(self) -> None:
        """Test IPINFO_IPv6_URL is defined."""
        assert IPINFO_IPv6_URL == "https://v6.ipinfo.io/json"

    def test_urls_are_https(self) -> None:
        """Test that URLs use HTTPS."""
        assert IPINFO_URL.startswith("https://")
        assert IPINFO_IPv6_URL.startswith("https://")


class TestDeviceNameCleanup:
    """Test DEVICE_NAME_CLEANUP constant."""

    def test_cleanup_list_exists(self) -> None:
        """Test that DEVICE_NAME_CLEANUP is defined."""
        assert DEVICE_NAME_CLEANUP is not None
        assert isinstance(DEVICE_NAME_CLEANUP, list)

    def test_cleanup_list_sorted(self) -> None:
        """Test that cleanup list is sorted (within groups)."""
        # Company suffixes should be sorted
        company_terms = ["co.", "company", "corp.", "corporation", "inc.", "incorporated", "limited", "ltd."]
        company_indices = [DEVICE_NAME_CLEANUP.index(term) for term in company_terms if term in DEVICE_NAME_CLEANUP]
        assert company_indices == sorted(company_indices), "Company suffixes should be grouped together"

    def test_expected_terms_present(self) -> None:
        """Test that expected cleanup terms are present."""
        expected_terms = [
            "corporation", "corp.", "ethernet", "controller",
            "wireless", "802.11ac", "802.11ax", "pci", "pcie",
        ]

        for term in expected_terms:
            assert term in DEVICE_NAME_CLEANUP, f"Expected term '{term}' not found"

    def test_no_duplicates(self) -> None:
        """Test that there are no duplicate terms."""
        assert len(DEVICE_NAME_CLEANUP) == len(set(DEVICE_NAME_CLEANUP))

    def test_all_lowercase(self) -> None:
        """Test that all terms are lowercase (for case-insensitive matching)."""
        for term in DEVICE_NAME_CLEANUP:
            assert term == term.lower(), f"Term '{term}' should be lowercase"

    def test_wifi_standards_sorted(self) -> None:
        """Test that WiFi standards are sorted by generation."""
        wifi_standards = [term for term in DEVICE_NAME_CLEANUP if term.startswith("802.11")]
        expected_order = ["802.11a", "802.11b", "802.11g", "802.11n", "802.11ac", "802.11ax"]

        # Find indices
        indices = []
        for std in expected_order:
            if std in DEVICE_NAME_CLEANUP:
                indices.append(DEVICE_NAME_CLEANUP.index(std))

        # Should be in order
        assert indices == sorted(indices), "WiFi standards should be sorted by generation"

    def test_speed_standards_sorted(self) -> None:
        """Test that speed standards are sorted by speed."""
        speed_standards = [term for term in DEVICE_NAME_CLEANUP if "base-t" in term]
        expected_order = ["10base-t", "100base-t", "1000base-t", "2.5gbase-t", "5gbase-t", "10gbase-t"]

        # Find indices
        indices = []
        for std in expected_order:
            if std in DEVICE_NAME_CLEANUP:
                indices.append(DEVICE_NAME_CLEANUP.index(std))

        # Should be in order
        assert indices == sorted(indices), "Speed standards should be sorted"


class TestTimeout:
    """Test TIMEOUT_SECONDS constant."""

    def test_timeout_exists(self) -> None:
        """Test that TIMEOUT_SECONDS is defined."""
        assert TIMEOUT_SECONDS is not None

    def test_timeout_is_positive(self) -> None:
        """Test that timeout is a positive integer."""
        assert isinstance(TIMEOUT_SECONDS, int)
        assert TIMEOUT_SECONDS > 0

    def test_timeout_reasonable_value(self) -> None:
        """Test that timeout is a reasonable value."""
        assert 1 <= TIMEOUT_SECONDS <= 60


class TestTableColumns:
    """Test TABLE_COLUMNS constant."""

    def test_table_columns_exist(self) -> None:
        """Test that TABLE_COLUMNS is defined."""
        assert TABLE_COLUMNS is not None
        assert isinstance(TABLE_COLUMNS, list)

    def test_column_structure(self) -> None:
        """Test that each column is a tuple of (name, width)."""
        for column in TABLE_COLUMNS:
            assert isinstance(column, tuple)
            assert len(column) == 2
            assert isinstance(column[0], str)
            assert isinstance(column[1], int)

    def test_expected_columns(self) -> None:
        """Test that expected columns are present."""
        column_names = [col[0] for col in TABLE_COLUMNS]

        # Updated: Removed DNS_LEAK - status shown by row color instead
        expected = [
            "INTERFACE", "TYPE", "DEVICE", "INTERNAL_IPv4", "INTERNAL_IPv6",
            "DNS_SERVER", "EXTERNAL_IPv4", "EXTERNAL_IPv6",
            "ISP", "COUNTRY", "GATEWAY", "METRIC"
        ]

        assert column_names == expected

    def test_column_widths_positive(self) -> None:
        """Test that all column widths are positive."""
        for name, width in TABLE_COLUMNS:
            assert width > 0, f"Column '{name}' has non-positive width"

    def test_total_width(self) -> None:
        """Test that total width is reasonable for terminal."""
        total_width = sum(width for _, width in TABLE_COLUMNS)

        # Should be optimized for typical terminal (around 185 chars)
        assert 150 <= total_width <= 200


class TestColors:
    """Test Colors class."""

    def test_colors_exist(self) -> None:
        """Test that Colors class is defined."""
        assert Colors is not None

    def test_color_attributes(self) -> None:
        """Test that all expected color attributes exist."""
        assert hasattr(Colors, "GREEN")
        assert hasattr(Colors, "CYAN")
        assert hasattr(Colors, "RED")
        assert hasattr(Colors, "YELLOW")
        assert hasattr(Colors, "RESET")

    def test_ansi_codes(self) -> None:
        """Test that colors are ANSI escape codes."""
        assert Colors.GREEN.startswith("\033[")
        assert Colors.CYAN.startswith("\033[")
        assert Colors.RED.startswith("\033[")
        assert Colors.YELLOW.startswith("\033[")
        assert Colors.RESET.startswith("\033[")

    def test_color_values(self) -> None:
        """Test specific color values."""
        assert Colors.GREEN == '\033[92m'
        assert Colors.CYAN == '\033[96m'
        assert Colors.RED == '\033[91m'
        assert Colors.YELLOW == '\033[93m'
        assert Colors.RESET == '\033[0m'
