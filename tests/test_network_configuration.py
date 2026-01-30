"""
Tests for network.configuration module.

Tests IP address, routing, and gateway configuration queries.
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
from unittest.mock import patch
from network.configuration import (
    get_internal_ipv4,
    get_internal_ipv6,
    get_default_gateway,
    get_route_metric,
    get_active_interface
)


class TestGetInternalIPv4:
    """Test IPv4 address retrieval."""
    
    @patch('network.configuration.run_command')
    def test_basic_ipv4_address(self, mock_run_cmd: Any) -> None:

        """Test retrieving basic IPv4 address."""
        mock_run_cmd.return_value = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86395sec preferred_lft 86395sec"""
        
        result = get_internal_ipv4("eth0")
        
        assert result == "192.168.1.100"
        mock_run_cmd.assert_called_once_with(["ip", "-4", "addr", "show", "eth0"])
    
    @patch('network.configuration.run_command')
    def test_no_ipv4_address(self, mock_run_cmd: Any) -> None:

        """Test interface without IPv4 address."""
        mock_run_cmd.return_value = """3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"""
        
        result = get_internal_ipv4("wlan0")
        
        assert result == "N/A"
    
    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: Any) -> None:

        """Test handling of command failure."""
        mock_run_cmd.return_value = None
        
        result = get_internal_ipv4("eth0")
        
        assert result == "N/A"
    
    @patch('network.configuration.run_command')
    def test_vpn_ipv4_address(self, mock_run_cmd: Any) -> None:

        """Test VPN interface IPv4 address."""
        mock_run_cmd.return_value = """4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500
    inet 10.2.0.2/32 scope global tun0
       valid_lft forever preferred_lft forever"""
        
        result = get_internal_ipv4("tun0")
        
        assert result == "10.2.0.2"
    
    @patch('network.configuration.run_command')
    def test_multiple_addresses_returns_first(self, mock_run_cmd: Any) -> None:

        """Test that first IPv4 address is returned when multiple exist."""
        mock_run_cmd.return_value = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.100/24 scope global eth0
    inet 192.168.1.101/24 scope global secondary eth0"""
        
        result = get_internal_ipv4("eth0")
        
        assert result == "192.168.1.100"
    
    @patch('network.configuration.run_command')
    def test_loopback_address(self, mock_run_cmd: Any) -> None:

        """Test loopback interface."""
        mock_run_cmd.return_value = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever"""
        
        result = get_internal_ipv4("lo")
        
        assert result == "127.0.0.1"


class TestGetInternalIPv6:
    """Test IPv6 address retrieval."""
    
    @patch('network.configuration.run_command')
    def test_basic_ipv6_address(self, mock_run_cmd: Any) -> None:

        """Test retrieving basic global IPv6 address."""
        mock_run_cmd.return_value = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 2001:db8::1/64 scope global dynamic
       valid_lft 86395sec preferred_lft 86395sec
    inet6 fe80::211:22ff:fe33:4455/64 scope link
       valid_lft forever preferred_lft forever"""
        
        result = get_internal_ipv6("eth0")
        
        assert result == "2001:db8::1"
        mock_run_cmd.assert_called_once_with(["ip", "-6", "addr", "show", "eth0"])
    
    @patch('network.configuration.run_command')
    def test_ignores_link_local(self, mock_run_cmd: Any) -> None:

        """Test that link-local addresses are ignored."""
        mock_run_cmd.return_value = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 fe80::211:22ff:fe33:4455/64 scope link
       valid_lft forever preferred_lft forever"""
        
        result = get_internal_ipv6("eth0")
        
        assert result == "N/A"
    
    @patch('network.configuration.run_command')
    def test_ignores_temporary(self, mock_run_cmd: Any) -> None:

        """Test that temporary addresses are ignored."""
        mock_run_cmd.return_value = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 2001:db8::temp:1234/64 scope global temporary dynamic
       valid_lft 86395sec preferred_lft 86395sec
    inet6 2001:db8::1/64 scope global dynamic
       valid_lft 86395sec preferred_lft 86395sec"""
        
        result = get_internal_ipv6("eth0")
        
        # Should return the non-temporary address
        assert result == "2001:db8::1"
    
    @patch('network.configuration.run_command')
    def test_ignores_deprecated(self, mock_run_cmd: Any) -> None:

        """Test that deprecated addresses are ignored."""
        mock_run_cmd.return_value = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 2001:db8::old/64 scope global deprecated dynamic
       valid_lft 86395sec preferred_lft 0sec
    inet6 2001:db8::1/64 scope global dynamic
       valid_lft 86395sec preferred_lft 86395sec"""
        
        result = get_internal_ipv6("eth0")
        
        assert result == "2001:db8::1"
    
    @patch('network.configuration.run_command')
    def test_no_ipv6_address(self, mock_run_cmd: Any) -> None:

        """Test interface without IPv6 address."""
        mock_run_cmd.return_value = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff"""
        
        result = get_internal_ipv6("eth0")
        
        assert result == "N/A"
    
    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: Any) -> None:

        """Test handling of command failure."""
        mock_run_cmd.return_value = None
        
        result = get_internal_ipv6("eth0")
        
        assert result == "N/A"
    
    @patch('network.configuration.run_command')
    def test_vpn_ipv6_address(self, mock_run_cmd: Any) -> None:

        """Test VPN interface IPv6 address."""
        mock_run_cmd.return_value = """4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500
    inet6 2a07:b944::2:2/128 scope global
       valid_lft forever preferred_lft forever"""
        
        result = get_internal_ipv6("tun0")
        
        assert result == "2a07:b944::2:2"


class TestGetDefaultGateway:
    """Test default gateway retrieval."""
    
    @patch('network.configuration.run_command')
    def test_basic_gateway(self, mock_run_cmd: Any) -> None:

        """Test retrieving basic gateway address."""
        mock_run_cmd.return_value = """default via 192.168.1.1 proto dhcp src 192.168.1.100 metric 100
192.168.1.0/24 proto kernel scope link src 192.168.1.100 metric 100"""
        
        result = get_default_gateway("eth0")
        
        assert result == "192.168.1.1"
        mock_run_cmd.assert_called_once_with(["ip", "route", "show", "dev", "eth0"])
    
    @patch('network.configuration.run_command')
    def test_no_default_gateway(self, mock_run_cmd: Any) -> None:

        """Test interface without default gateway."""
        mock_run_cmd.return_value = """192.168.1.0/24 proto kernel scope link src 192.168.1.100"""
        
        result = get_default_gateway("eth0")
        
        assert result == "NONE"
    
    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: Any) -> None:

        """Test handling of command failure."""
        mock_run_cmd.return_value = None
        
        result = get_default_gateway("eth0")
        
        assert result == "NONE"
    
    @patch('network.configuration.run_command')
    def test_vpn_gateway(self, mock_run_cmd: Any) -> None:

        """Test VPN interface gateway."""
        mock_run_cmd.return_value = """default via 100.85.0.1 proto static metric 98"""
        
        result = get_default_gateway("pvpnksintrf0")
        
        assert result == "100.85.0.1"
    
    @patch('network.configuration.run_command')
    def test_empty_output(self, mock_run_cmd: Any) -> None:

        """Test empty command output."""
        mock_run_cmd.return_value = ""
        
        result = get_default_gateway("eth0")
        
        assert result == "NONE"
    
    @patch('network.configuration.run_command')
    def test_ipv6_gateway(self, mock_run_cmd: Any) -> None:

        """Test IPv6 gateway address."""
        mock_run_cmd.return_value = """default via fe80::1 proto ra metric 100"""
        
        result = get_default_gateway("eth0")
        
        assert result == "fe80::1"


class TestGetRouteMetric:
    """Test route metric retrieval."""
    
    @patch('network.configuration.run_command')
    def test_explicit_metric(self, mock_run_cmd: Any) -> None:

        """Test route with explicit metric."""
        mock_run_cmd.return_value = """default via 192.168.1.1 proto dhcp src 192.168.1.100 metric 100"""
        
        result = get_route_metric("eth0")
        
        assert result == "100"
        mock_run_cmd.assert_called_once_with(["ip", "route", "show", "dev", "eth0"])
    
    @patch('network.configuration.run_command')
    def test_default_metric(self, mock_run_cmd: Any) -> None:

        """Test route with kernel-assigned default metric."""
        mock_run_cmd.return_value = """default via 192.168.1.1 proto dhcp"""
        
        result = get_route_metric("eth0")
        
        assert result == "DEFAULT"
    
    @patch('network.configuration.run_command')
    def test_no_default_route(self, mock_run_cmd: Any) -> None:

        """Test interface without default route."""
        mock_run_cmd.return_value = """192.168.1.0/24 proto kernel scope link src 192.168.1.100"""
        
        result = get_route_metric("eth0")
        
        assert result == "NONE"
    
    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: Any) -> None:

        """Test handling of command failure."""
        mock_run_cmd.return_value = None
        
        result = get_route_metric("eth0")
        
        assert result == "NONE"
    
    @patch('network.configuration.run_command')
    def test_vpn_low_metric(self, mock_run_cmd: Any) -> None:

        """Test VPN with low metric (high priority)."""
        mock_run_cmd.return_value = """default via 100.85.0.1 proto static metric 98"""
        
        result = get_route_metric("pvpnksintrf0")
        
        assert result == "98"
    
    @patch('network.configuration.run_command')
    def test_high_metric(self, mock_run_cmd: Any) -> None:

        """Test interface with high metric (low priority)."""
        mock_run_cmd.return_value = """default via 10.188.39.53 metric 101"""
        
        result = get_route_metric("usb0")
        
        assert result == "101"


class TestGetActiveInterface:
    """Test active interface detection."""
    
    @patch('network.configuration.run_command')
    def test_basic_active_interface(self, mock_run_cmd: Any) -> None:

        """Test finding basic active interface."""
        mock_run_cmd.return_value = """default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100"""
        
        result = get_active_interface()
        
        assert result == "eth0"
        mock_run_cmd.assert_called_once_with(["ip", "route", "show", "default"])
    
    @patch('network.configuration.run_command')
    def test_vpn_active(self, mock_run_cmd: Any) -> None:

        """Test VPN as active interface."""
        mock_run_cmd.return_value = """default via 100.85.0.1 dev pvpnksintrf0 proto static metric 98"""
        
        result = get_active_interface()
        
        assert result == "pvpnksintrf0"
    
    @patch('network.configuration.run_command')
    def test_no_default_route(self, mock_run_cmd: Any) -> None:

        """Test system without default route."""
        mock_run_cmd.return_value = None
        
        result = get_active_interface()
        
        assert result is None
    
    @patch('network.configuration.run_command')
    def test_empty_output(self, mock_run_cmd: Any) -> None:

        """Test empty command output."""
        mock_run_cmd.return_value = ""
        
        result = get_active_interface()
        
        assert result is None
    
    @patch('network.configuration.run_command')
    def test_multiple_default_routes(self, mock_run_cmd: Any) -> None:

        """Test system with multiple default routes (returns first)."""
        mock_run_cmd.return_value = """default via 100.85.0.1 dev pvpnksintrf0 proto static metric 98
default via 192.168.1.1 dev eth0 proto dhcp metric 100"""
        
        result = get_active_interface()
        
        # Should return first (lowest metric)
        assert result == "pvpnksintrf0"
    
    @patch('network.configuration.run_command')
    def test_malformed_output(self, mock_run_cmd: Any) -> None:

        """Test handling of malformed output."""
        mock_run_cmd.return_value = """malformed route output without dev keyword"""
        
        result = get_active_interface()
        
        assert result is None
    
    @patch('network.configuration.run_command')
    def test_usb_tethering_active(self, mock_run_cmd: Any) -> None:

        """Test USB tethering as active interface."""
        mock_run_cmd.return_value = """default via 10.188.39.53 dev enx9e0217482fa4 proto dhcp metric 101"""
        
        result = get_active_interface()
        
        assert result == "enx9e0217482fa4"


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @patch('network.configuration.run_command')
    def test_interface_down(self, mock_run_cmd: Any) -> None:

        """Test querying interface that's down."""
        mock_run_cmd.return_value = """2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff"""
        
        ipv4 = get_internal_ipv4("eth0")
        ipv6 = get_internal_ipv6("eth0")
        
        assert ipv4 == "N/A"
        assert ipv6 == "N/A"
    
    @patch('network.configuration.run_command')
    def test_nonexistent_interface(self, mock_run_cmd: Any) -> None:

        """Test querying non-existent interface."""
        mock_run_cmd.return_value = None
        
        ipv4 = get_internal_ipv4("fake0")
        ipv6 = get_internal_ipv6("fake0")
        gateway = get_default_gateway("fake0")
        metric = get_route_metric("fake0")
        
        assert ipv4 == "N/A"
        assert ipv6 == "N/A"
        assert gateway == "NONE"
        assert metric == "NONE"
    
    @patch('network.configuration.run_command')
    def test_whitespace_handling(self, mock_run_cmd: Any) -> None:

        """Test handling of extra whitespace in output."""
        mock_run_cmd.return_value = """
        
        default   via   192.168.1.1   dev   eth0   metric   100
        
        """
        
        result = get_active_interface()
        
        assert result == "eth0"
