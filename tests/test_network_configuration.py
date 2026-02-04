"""
Tests for network configuration module.

Tests IP address queries and routing configuration with batched API.
All tests have proper type annotations for mypy strict compliance.
"""

import pytest
from unittest.mock import patch, MagicMock

from network.configuration import (
    get_all_ipv4_addresses,
    get_all_ipv6_addresses,
    get_internal_ipv4,
    get_internal_ipv6,
    get_route_info,
    get_default_gateway,
    get_route_metric,
    get_active_interface,
)


class TestGetAllIPv4Addresses:
    """Tests for get_all_ipv4_addresses function (batched query)."""

    @patch('network.configuration.run_command')
    def test_single_interface_single_ip(self, mock_run_cmd: MagicMock) -> None:
        """Test parsing single interface with single IPv4."""
        mock_run_cmd.return_value = """1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"""

        result = get_all_ipv4_addresses()

        assert result == {
            "lo": "127.0.0.1",
            "eth0": "192.168.1.100"
        }
        mock_run_cmd.assert_called_once_with(["ip", "-4", "addr", "show"])

    @patch('network.configuration.run_command')
    def test_multiple_interfaces(self, mock_run_cmd: MagicMock) -> None:
        """Test parsing multiple interfaces."""
        mock_run_cmd.return_value = """1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.101/24 brd 192.168.1.255 scope global wlan0"""

        result = get_all_ipv4_addresses()

        assert result == {
            "lo": "127.0.0.1",
            "eth0": "192.168.1.100",
            "wlan0": "192.168.1.101"
        }

    @patch('network.configuration.run_command')
    def test_interface_without_ip(self, mock_run_cmd: MagicMock) -> None:
        """Test interface without IP address is not in result."""
        mock_run_cmd.return_value = """1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"""

        result = get_all_ipv4_addresses()

        assert result == {"lo": "127.0.0.1"}
        assert "eth0" not in result

    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: MagicMock) -> None:
        """Test handling of command failure."""
        mock_run_cmd.return_value = None

        result = get_all_ipv4_addresses()

        assert result == {}


class TestGetAllIPv6Addresses:
    """Tests for get_all_ipv6_addresses function (batched query)."""

    @patch('network.configuration.run_command')
    def test_single_interface_global_ipv6(self, mock_run_cmd: MagicMock) -> None:
        """Test parsing single interface with global IPv6."""
        mock_run_cmd.return_value = """1: lo: <LOOPBACK,UP,LOWER_UP>
    inet6 ::1/128 scope host
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet6 2001:db8::1/64 scope global"""

        result = get_all_ipv6_addresses()

        assert result == {
            "eth0": "2001:db8::1"
        }
        mock_run_cmd.assert_called_once_with(["ip", "-6", "addr", "show"])

    @patch('network.configuration.run_command')
    def test_ignores_link_local(self, mock_run_cmd: MagicMock) -> None:
        """Test that link-local addresses are ignored."""
        mock_run_cmd.return_value = """1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet6 fe80::1/64 scope link
    inet6 2001:db8::1/64 scope global"""

        result = get_all_ipv6_addresses()

        assert result == {"eth0": "2001:db8::1"}
        assert "fe80::1" not in str(result)

    @patch('network.configuration.run_command')
    def test_ignores_temporary(self, mock_run_cmd: MagicMock) -> None:
        """Test that temporary addresses are ignored."""
        mock_run_cmd.return_value = """1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet6 2001:db8::1/64 scope global temporary
    inet6 2001:db8::2/64 scope global"""

        result = get_all_ipv6_addresses()

        assert result == {"eth0": "2001:db8::2"}

    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: MagicMock) -> None:
        """Test handling of command failure."""
        mock_run_cmd.return_value = None

        result = get_all_ipv6_addresses()

        assert result == {}


class TestGetInternalIPv4:
    """Tests for get_internal_ipv4 function (wrapper around batched query)."""

    @patch('network.configuration.get_all_ipv4_addresses')
    def test_basic_ipv4_address(self, mock_all_ipv4: MagicMock) -> None:
        """Test retrieving IPv4 for specific interface."""
        mock_all_ipv4.return_value = {
            "lo": "127.0.0.1",
            "eth0": "192.168.1.100"
        }

        result = get_internal_ipv4("eth0")

        assert result == "192.168.1.100"
        mock_all_ipv4.assert_called_once()

    @patch('network.configuration.get_all_ipv4_addresses')
    def test_interface_not_found(self, mock_all_ipv4: MagicMock) -> None:
        """Test when interface has no IPv4."""
        mock_all_ipv4.return_value = {"lo": "127.0.0.1"}

        result = get_internal_ipv4("eth0")

        assert result == "N/A"

    @patch('network.configuration.get_all_ipv4_addresses')
    def test_multiple_addresses_returns_first(self, mock_all_ipv4: MagicMock) -> None:
        """Test that function returns the address for requested interface."""
        mock_all_ipv4.return_value = {
            "eth0": "192.168.1.100",
            "wlan0": "192.168.1.101"
        }

        result = get_internal_ipv4("eth0")

        assert result == "192.168.1.100"


class TestGetInternalIPv6:
    """Tests for get_internal_ipv6 function (wrapper around batched query)."""

    @patch('network.configuration.get_all_ipv6_addresses')
    def test_basic_ipv6_address(self, mock_all_ipv6: MagicMock) -> None:
        """Test retrieving IPv6 for specific interface."""
        mock_all_ipv6.return_value = {
            "eth0": "2001:db8::1"
        }

        result = get_internal_ipv6("eth0")

        assert result == "2001:db8::1"
        mock_all_ipv6.assert_called_once()

    @patch('network.configuration.get_all_ipv6_addresses')
    def test_interface_not_found(self, mock_all_ipv6: MagicMock) -> None:
        """Test when interface has no IPv6."""
        mock_all_ipv6.return_value = {}

        result = get_internal_ipv6("eth0")

        assert result == "N/A"


class TestGetRouteInfo:
    """Tests for get_route_info function (batched gateway + metric)."""

    @patch('network.configuration.run_command')
    def test_default_route_with_metric(self, mock_run_cmd: MagicMock) -> None:
        """Test parsing default route with explicit metric."""
        mock_run_cmd.return_value = "default via 192.168.1.1 dev eth0 proto dhcp metric 100"

        gateway, metric = get_route_info("eth0")

        assert gateway == "192.168.1.1"
        assert metric == "100"

    @patch('network.configuration.run_command')
    def test_default_route_without_metric(self, mock_run_cmd: MagicMock) -> None:
        """Test parsing default route without explicit metric."""
        mock_run_cmd.return_value = "default via 192.168.1.1 dev eth0 proto dhcp"

        gateway, metric = get_route_info("eth0")

        assert gateway == "192.168.1.1"
        assert metric == "DEFAULT"

    @patch('network.configuration.run_command')
    def test_no_default_route(self, mock_run_cmd: MagicMock) -> None:
        """Test when no default route exists."""
        mock_run_cmd.return_value = "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100"

        gateway, metric = get_route_info("eth0")

        assert gateway == "NONE"
        assert metric == "NONE"

    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: MagicMock) -> None:
        """Test handling of command failure."""
        mock_run_cmd.return_value = None

        gateway, metric = get_route_info("eth0")

        assert gateway == "NONE"
        assert metric == "NONE"


class TestGetDefaultGateway:
    """Tests for get_default_gateway function (wrapper)."""

    @patch('network.configuration.get_route_info')
    def test_returns_gateway(self, mock_route_info: MagicMock) -> None:
        """Test that it returns gateway from get_route_info."""
        mock_route_info.return_value = ("192.168.1.1", "100")

        result = get_default_gateway("eth0")

        assert result == "192.168.1.1"
        mock_route_info.assert_called_once_with("eth0")


class TestGetRouteMetric:
    """Tests for get_route_metric function (wrapper)."""

    @patch('network.configuration.get_route_info')
    def test_returns_metric(self, mock_route_info: MagicMock) -> None:
        """Test that it returns metric from get_route_info."""
        mock_route_info.return_value = ("192.168.1.1", "100")

        result = get_route_metric("eth0")

        assert result == "100"
        mock_route_info.assert_called_once_with("eth0")


class TestGetActiveInterface:
    """Tests for get_active_interface function."""

    @patch('network.configuration.run_command')
    def test_active_interface_found(self, mock_run_cmd: MagicMock) -> None:
        """Test finding active interface."""
        mock_run_cmd.return_value = "default via 192.168.1.1 dev eth0 proto dhcp metric 100"

        result = get_active_interface()

        assert result == "eth0"

    @patch('network.configuration.run_command')
    def test_multiple_default_routes(self, mock_run_cmd: MagicMock) -> None:
        """Test with multiple default routes (returns first)."""
        mock_run_cmd.return_value = """default via 192.168.1.1 dev eth0 proto dhcp metric 100
default via 10.0.0.1 dev wlan0 proto dhcp metric 200"""

        result = get_active_interface()

        assert result == "eth0"

    @patch('network.configuration.run_command')
    def test_no_default_route(self, mock_run_cmd: MagicMock) -> None:
        """Test when no default route exists."""
        mock_run_cmd.return_value = "192.168.1.0/24 dev eth0 proto kernel scope link"

        result = get_active_interface()

        assert result is None

    @patch('network.configuration.run_command')
    def test_command_failure(self, mock_run_cmd: MagicMock) -> None:
        """Test handling of command failure."""
        mock_run_cmd.return_value = None

        result = get_active_interface()

        assert result is None
