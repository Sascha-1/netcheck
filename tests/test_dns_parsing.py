"""
Tests for DNS parsing helper functions.

Tests the refactored DNS parsing logic that extracts common functionality
from get_interface_dns() and get_system_dns().
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
from network.dns import (
    _extract_ips_from_text,
    _parse_dns_section,
    _extract_current_dns,
    _check_isp_dns_leak,
    _check_vpn_dns_usage,
    _check_public_dns_usage
)


class TestExtractIpsFromText:
    """Test IP extraction from space-separated text."""
    
    def test_ipv4_only(self) -> None:

        """Test extracting IPv4 addresses."""
        result = _extract_ips_from_text("8.8.8.8 8.8.4.4")
        assert result == ["8.8.8.8", "8.8.4.4"]
    
    def test_ipv6_only(self) -> None:

        """Test extracting IPv6 addresses."""
        result = _extract_ips_from_text("2001:db8::1 2001:db8::2")
        assert result == ["2001:db8::1", "2001:db8::2"]
    
    def test_mixed_valid_invalid(self) -> None:

        """Test filtering out invalid tokens."""
        result = _extract_ips_from_text("8.8.8.8 invalid 2001:db8::1 not-ip")
        assert result == ["8.8.8.8", "2001:db8::1"]
    
    def test_empty_text(self) -> None:

        """Test empty input."""
        assert _extract_ips_from_text("") == []
    
    def test_no_valid_ips(self) -> None:

        """Test text with no valid IPs."""
        assert _extract_ips_from_text("invalid text here") == []
    
    def test_mixed_ipv4_ipv6(self) -> None:

        """Test mixing IPv4 and IPv6."""
        result = _extract_ips_from_text("8.8.8.8 2001:db8::1 1.1.1.1")
        assert result == ["8.8.8.8", "2001:db8::1", "1.1.1.1"]
    
    def test_single_ip(self) -> None:

        """Test single IP address."""
        assert _extract_ips_from_text("8.8.8.8") == ["8.8.8.8"]
    
    def test_whitespace_handling(self) -> None:

        """Test various whitespace."""
        result = _extract_ips_from_text("  8.8.8.8   8.8.4.4  ")
        assert result == ["8.8.8.8", "8.8.4.4"]


class TestParseDnsSection:
    """Test DNS section parsing from resolvectl output."""
    
    def test_single_line_single_dns(self) -> None:

        """Test DNS on same line as marker."""
        lines = ["DNS Servers: 8.8.8.8"]
        result = _parse_dns_section(lines)
        assert result == ["8.8.8.8"]
    
    def test_single_line_multiple_dns(self) -> None:

        """Test multiple DNS on same line."""
        lines = ["DNS Servers: 8.8.8.8 8.8.4.4"]
        result = _parse_dns_section(lines)
        assert result == ["8.8.8.8", "8.8.4.4"]
    
    def test_multi_line_continuation(self) -> None:

        """Test DNS on multiple indented lines."""
        lines = [
            "DNS Servers: 8.8.8.8",
            "             8.8.4.4",
            "             1.1.1.1"
        ]
        result = _parse_dns_section(lines)
        assert result == ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
    
    def test_section_boundary(self) -> None:

        """Test parsing stops at section boundary."""
        lines = [
            "DNS Servers: 8.8.8.8",
            "             8.8.4.4",
            "DNS Domain: example.com",
            "             9.9.9.9"  # Should not be included
        ]
        result = _parse_dns_section(lines)
        assert result == ["8.8.8.8", "8.8.4.4"]
    
    def test_ipv6_addresses(self) -> None:

        """Test parsing IPv6 addresses."""
        lines = [
            "DNS Servers: 2001:db8::1",
            "             2001:db8::2"
        ]
        result = _parse_dns_section(lines)
        assert result == ["2001:db8::1", "2001:db8::2"]
    
    def test_mixed_ipv4_ipv6(self) -> None:

        """Test mixing IPv4 and IPv6."""
        lines = [
            "DNS Servers: 8.8.8.8",
            "             2001:db8::1",
            "             8.8.4.4"
        ]
        result = _parse_dns_section(lines)
        assert result == ["8.8.8.8", "2001:db8::1", "8.8.4.4"]
    
    def test_removes_duplicates(self) -> None:

        """Test duplicate removal while preserving order."""
        lines = [
            "DNS Servers: 8.8.8.8",
            "             8.8.8.8",  # Duplicate
            "             8.8.4.4"
        ]
        result = _parse_dns_section(lines)
        assert result == ["8.8.8.8", "8.8.4.4"]
    
    def test_empty_section(self) -> None:

        """Test empty DNS section."""
        lines = ["DNS Servers:", "DNS Domain: example.com"]
        result = _parse_dns_section(lines)
        assert result == []
    
    def test_no_dns_marker(self) -> None:

        """Test when marker not present."""
        lines = ["Some other content", "More content"]
        result = _parse_dns_section(lines)
        assert result == []
    
    def test_empty_lines_ignored(self) -> None:

        """Test that empty lines are ignored."""
        lines = [
            "DNS Servers: 8.8.8.8",
            "",
            "             8.8.4.4",
            "",
            "DNS Domain: example.com"
        ]
        result = _parse_dns_section(lines)
        assert result == ["8.8.8.8", "8.8.4.4"]
    
    def test_custom_marker(self) -> None:

        """Test with custom start marker."""
        lines = [
            "Custom DNS: 8.8.8.8",
            "            8.8.4.4"
        ]
        result = _parse_dns_section(lines, start_marker="Custom DNS:")
        assert result == ["8.8.8.8", "8.8.4.4"]


class TestExtractCurrentDns:
    """Test current DNS extraction."""
    
    def test_current_dns_present(self) -> None:

        """Test extracting current DNS."""
        lines = ["Current DNS Server: 8.8.8.8"]
        result = _extract_current_dns(lines)
        assert result == "8.8.8.8"
    
    def test_current_dns_not_present(self) -> None:

        """Test when no current DNS."""
        lines = ["DNS Servers: 8.8.8.8"]
        result = _extract_current_dns(lines)
        assert result is None
    
    def test_current_dns_ipv6(self) -> None:

        """Test IPv6 current DNS."""
        lines = ["Current DNS Server: 2001:db8::1"]
        result = _extract_current_dns(lines)
        assert result == "2001:db8::1"
    
    def test_current_dns_takes_first(self) -> None:

        """Test takes first when multiple listed."""
        lines = ["Current DNS Server: 8.8.8.8 8.8.4.4"]
        result = _extract_current_dns(lines)
        assert result == "8.8.8.8"
    
    def test_current_dns_empty_value(self) -> None:

        """Test when current DNS line has no value."""
        lines = ["Current DNS Server:"]
        result = _extract_current_dns(lines)
        assert result is None
    
    def test_current_dns_invalid_value(self) -> None:

        """Test when current DNS has invalid IP."""
        lines = ["Current DNS Server: not-an-ip"]
        result = _extract_current_dns(lines)
        assert result is None
    
    def test_current_dns_in_middle_of_output(self) -> None:

        """Test finding current DNS among other lines."""
        lines = [
            "Link 2 (eth0)",
            "Current DNS Server: 8.8.8.8",
            "DNS Servers: 8.8.8.8 8.8.4.4"
        ]
        result = _extract_current_dns(lines)
        assert result == "8.8.8.8"


class TestCheckIspDnsLeak:
    """Test ISP DNS leak detection."""
    
    def test_no_leak(self) -> None:

        """Test when no ISP DNS is configured."""
        configured = ["8.8.8.8", "8.8.4.4"]
        isp_dns = ["192.168.1.1", "192.168.1.2"]
        result = _check_isp_dns_leak(configured, isp_dns)
        assert result is None
    
    def test_single_leak(self) -> None:

        """Test single ISP DNS leak."""
        configured = ["192.168.1.1", "8.8.8.8"]
        isp_dns = ["192.168.1.1"]
        result = _check_isp_dns_leak(configured, isp_dns)
        assert result == ["192.168.1.1"]
    
    def test_multiple_leaks(self) -> None:

        """Test multiple ISP DNS leaks."""
        configured = ["192.168.1.1", "192.168.1.2"]
        isp_dns = ["192.168.1.1", "192.168.1.2"]
        result = _check_isp_dns_leak(configured, isp_dns)
        assert result == ["192.168.1.1", "192.168.1.2"]
    
    def test_partial_leak(self) -> None:

        """Test partial leak (some ISP, some not)."""
        configured = ["192.168.1.1", "8.8.8.8", "192.168.1.2"]
        isp_dns = ["192.168.1.1", "192.168.1.2"]
        result = _check_isp_dns_leak(configured, isp_dns)
        assert result == ["192.168.1.1", "192.168.1.2"]
    
    def test_empty_configured(self) -> None:

        """Test with no configured DNS."""
        result = _check_isp_dns_leak([], ["192.168.1.1"])
        assert result is None
    
    def test_empty_isp_dns(self) -> None:

        """Test with no known ISP DNS."""
        result = _check_isp_dns_leak(["8.8.8.8"], [])
        assert result is None


class TestCheckVpnDnsUsage:
    """Test VPN DNS usage detection."""
    
    def test_using_vpn_dns(self) -> None:

        """Test when using VPN DNS."""
        configured = ["10.2.0.1"]
        vpn_dns = ["10.2.0.1"]
        result = _check_vpn_dns_usage(configured, vpn_dns)
        assert result == ["10.2.0.1"]
    
    def test_not_using_vpn_dns(self) -> None:

        """Test when not using VPN DNS."""
        configured = ["8.8.8.8"]
        vpn_dns = ["10.2.0.1"]
        result = _check_vpn_dns_usage(configured, vpn_dns)
        assert result is None
    
    def test_multiple_vpn_dns(self) -> None:

        """Test multiple VPN DNS servers."""
        configured = ["10.2.0.1", "10.2.0.2"]
        vpn_dns = ["10.2.0.1", "10.2.0.2"]
        result = _check_vpn_dns_usage(configured, vpn_dns)
        assert result == ["10.2.0.1", "10.2.0.2"]
    
    def test_partial_vpn_dns(self) -> None:

        """Test partial VPN DNS usage."""
        configured = ["10.2.0.1", "8.8.8.8"]
        vpn_dns = ["10.2.0.1", "10.2.0.2"]
        result = _check_vpn_dns_usage(configured, vpn_dns)
        assert result == ["10.2.0.1"]
    
    def test_empty_configured(self) -> None:

        """Test with no configured DNS."""
        result = _check_vpn_dns_usage([], ["10.2.0.1"])
        assert result is None
    
    def test_empty_vpn_dns(self) -> None:

        """Test with no VPN DNS."""
        result = _check_vpn_dns_usage(["8.8.8.8"], [])
        assert result is None


class TestCheckPublicDnsUsage:
    """Test public DNS provider detection."""
    
    def test_cloudflare_ipv4(self) -> None:

        """Test Cloudflare IPv4 DNS."""
        result = _check_public_dns_usage(["1.1.1.1"])
        assert result == ["1.1.1.1"]
    
    def test_cloudflare_alternate(self) -> None:

        """Test Cloudflare alternate DNS."""
        result = _check_public_dns_usage(["1.0.0.1"])
        assert result == ["1.0.0.1"]
    
    def test_google_dns(self) -> None:

        """Test Google DNS."""
        result = _check_public_dns_usage(["8.8.8.8", "8.8.4.4"])
        assert result == ["8.8.8.8", "8.8.4.4"]
    
    def test_quad9_dns(self) -> None:

        """Test Quad9 DNS."""
        result = _check_public_dns_usage(["9.9.9.9"])
        assert result == ["9.9.9.9"]
    
    def test_opendns(self) -> None:

        """Test OpenDNS."""
        result = _check_public_dns_usage(["208.67.222.222"])
        assert result == ["208.67.222.222"]
    
    def test_cloudflare_ipv6(self) -> None:

        """Test Cloudflare IPv6 DNS."""
        result = _check_public_dns_usage(["2606:4700:4700::1111"])
        assert result == ["2606:4700:4700::1111"]
    
    def test_google_ipv6(self) -> None:

        """Test Google IPv6 DNS."""
        result = _check_public_dns_usage(["2001:4860:4860::8888"])
        assert result == ["2001:4860:4860::8888"]
    
    def test_not_public_dns(self) -> None:

        """Test non-public DNS."""
        result = _check_public_dns_usage(["192.168.1.1"])
        assert result is None
    
    def test_mixed_public_private(self) -> None:

        """Test mix of public and private DNS."""
        result = _check_public_dns_usage(["8.8.8.8", "192.168.1.1", "1.1.1.1"])
        assert result == ["8.8.8.8", "1.1.1.1"]
    
    def test_empty_configured(self) -> None:

        """Test with no configured DNS."""
        result = _check_public_dns_usage([])
        assert result is None
    
    def test_multiple_providers(self) -> None:

        """Test multiple different providers."""
        result = _check_public_dns_usage(["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        assert result == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class TestIntegration:
    """Integration tests for DNS parsing functions."""
    
    def test_realistic_interface_output(self) -> None:

        """Test with realistic resolvectl interface output."""
        output = """Link 2 (eth0)
    Current Scopes: DNS
     DefaultRoute setting: yes
      LLMNR setting: yes
MulticastDNS setting: no
  DNSOverTLS setting: no
      DNSSEC setting: no
    DNSSEC supported: no
  Current DNS Server: 8.8.8.8
         DNS Servers: 8.8.8.8
                      8.8.4.4
          DNS Domain: ~."""
        
        lines = output.split('\n')
        
        # Test current DNS extraction
        current = _extract_current_dns(lines)
        assert current == "8.8.8.8"
        
        # Test DNS section parsing
        dns_list = _parse_dns_section(lines)
        assert dns_list == ["8.8.8.8", "8.8.4.4"]
    
    def test_realistic_vpn_output(self) -> None:

        """Test with realistic VPN interface output."""
        output = """Link 3 (tun0)
    Current Scopes: DNS
     DefaultRoute setting: yes
  Current DNS Server: 10.2.0.1
         DNS Servers: 10.2.0.1"""
        
        lines = output.split('\n')
        
        current = _extract_current_dns(lines)
        assert current == "10.2.0.1"
        
        dns_list = _parse_dns_section(lines)
        assert dns_list == ["10.2.0.1"]
    
    def test_realistic_global_section(self) -> None:

        """Test with realistic global DNS section."""
        output = """Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub
Current DNS Server: 8.8.8.8
       DNS Servers: 8.8.8.8
                    8.8.4.4

Link 2 (eth0)
       DNS Servers: 192.168.1.1"""
        
        lines = output.split('\n')
        
        # Extract just the global section
        global_lines = []
        in_global = False
        for line in lines:
            if "Global" in line:
                in_global = True
                continue
            if "Link " in line and in_global:
                break
            if in_global:
                global_lines.append(line)
        
        # Test global DNS parsing
        dns_list = _parse_dns_section(global_lines)
        assert dns_list == ["8.8.8.8", "8.8.4.4"]
    
    def test_leak_detection_workflow(self) -> None:

        """Test complete leak detection workflow."""
        # Scenario: VPN active, but interface using ISP DNS (LEAK)
        configured_dns = ["192.168.1.1"]
        vpn_dns = ["10.2.0.1"]
        isp_dns = ["192.168.1.1"]
        
        # Should detect ISP leak
        leak = _check_isp_dns_leak(configured_dns, isp_dns)
        assert leak == ["192.168.1.1"]
        
        # Should not detect VPN usage
        vpn_usage = _check_vpn_dns_usage(configured_dns, vpn_dns)
        assert vpn_usage is None
        
        # Should not be public DNS
        public = _check_public_dns_usage(configured_dns)
        assert public is None
    
    def test_secure_vpn_workflow(self) -> None:

        """Test secure VPN configuration workflow."""
        # Scenario: VPN active, using VPN DNS (OK)
        configured_dns = ["10.2.0.1"]
        vpn_dns = ["10.2.0.1"]
        isp_dns = ["192.168.1.1"]
        
        # Should not detect ISP leak
        leak = _check_isp_dns_leak(configured_dns, isp_dns)
        assert leak is None
        
        # Should detect VPN usage
        vpn_usage = _check_vpn_dns_usage(configured_dns, vpn_dns)
        assert vpn_usage == ["10.2.0.1"]
    
    def test_public_dns_workflow(self) -> None:

        """Test public DNS usage workflow."""
        # Scenario: VPN active, using public DNS (OK)
        configured_dns = ["1.1.1.1", "8.8.8.8"]
        vpn_dns = ["10.2.0.1"]
        isp_dns = ["192.168.1.1"]
        
        # Should not detect ISP leak
        leak = _check_isp_dns_leak(configured_dns, isp_dns)
        assert leak is None
        
        # Should not detect VPN usage
        vpn_usage = _check_vpn_dns_usage(configured_dns, vpn_dns)
        assert vpn_usage is None
        
        # Should detect public DNS
        public = _check_public_dns_usage(configured_dns)
        assert public == ["1.1.1.1", "8.8.8.8"]
