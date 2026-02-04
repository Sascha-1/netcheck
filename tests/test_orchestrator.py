"""Tests for orchestrator module with proper batched API mocking."""

import pytest
from unittest.mock import patch, MagicMock

from orchestrator import (
    check_dependencies,
    collect_network_data,
    process_single_interface,
)
from models import InterfaceInfo, EgressInfo
from enums import InterfaceType, DataMarker


class TestCheckDependencies:
    """Tests for dependency checking."""

    @patch('orchestrator.shutil.which')
    def test_all_dependencies_present(self, mock_which: MagicMock) -> None:
        """Test when all dependencies are present."""
        mock_which.return_value = '/usr/bin/command'

        result = check_dependencies()
        assert result is True

    @patch('orchestrator.shutil.which')
    def test_missing_dependency(self, mock_which: MagicMock) -> None:
        """Test when a dependency is missing."""
        mock_which.side_effect = lambda cmd: None if cmd == 'ip' else '/usr/bin/command'

        result = check_dependencies()
        assert result is False


class TestCollectNetworkData:
    """Tests for network data collection with batched API."""

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_collect_single_interface(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test collecting data for a single interface."""
        # Setup mocks
        mock_get_list.return_value = ["eth0"]
        mock_detect_type.return_value = InterfaceType.ETHERNET
        mock_device_name.return_value = "Test Device"
        mock_dns.return_value = (["8.8.8.8"], "8.8.8.8")

        # Batched queries return dictionaries
        mock_all_ipv4.return_value = {"eth0": "192.168.1.100"}
        mock_all_ipv6.return_value = {}

        mock_active.return_value = None
        mock_egress.return_value = EgressInfo.create_error()

        # FIXED: Mock get_route_info at the module where it's used
        with patch('orchestrator.get_route_info', return_value=("192.168.1.1", "100")):
            result = collect_network_data(parallel=False)

        # Verify
        assert len(result) == 1
        assert result[0].name == "eth0"
        assert result[0].interface_type == InterfaceType.ETHERNET
        assert result[0].device == "Test Device"
        assert result[0].internal_ipv4 == "192.168.1.100"
        assert result[0].internal_ipv6 == DataMarker.NOT_AVAILABLE
        assert result[0].default_gateway == "192.168.1.1"
        assert result[0].metric == "100"

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_collect_no_interfaces(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test when no interfaces are found."""
        mock_get_list.return_value = []

        result = collect_network_data(parallel=False)

        assert result == []

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_collect_multiple_interfaces(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test collecting data for multiple interfaces."""
        # Setup mocks
        mock_get_list.return_value = ["eth0", "wlan0"]
        mock_detect_type.side_effect = [InterfaceType.ETHERNET, InterfaceType.WIRELESS]
        mock_device_name.side_effect = ["Ethernet Device", "WiFi Device"]
        mock_dns.return_value = ([], None)

        # Batched queries with data for both interfaces
        mock_all_ipv4.return_value = {
            "eth0": "192.168.1.100",
            "wlan0": "192.168.1.101"
        }
        mock_all_ipv6.return_value = {}

        mock_active.return_value = None
        mock_egress.return_value = EgressInfo.create_error()

        # FIXED: Mock get_route_info with side_effect for multiple calls
        with patch('orchestrator.get_route_info', side_effect=[
            ("192.168.1.1", "100"),
            ("192.168.1.1", "200")
        ]):
            result = collect_network_data(parallel=False)

        # Verify
        assert len(result) == 2
        assert result[0].name == "eth0"
        assert result[1].name == "wlan0"
        assert result[0].internal_ipv4 == "192.168.1.100"
        assert result[1].internal_ipv4 == "192.168.1.101"
        assert result[0].metric == "100"
        assert result[1].metric == "200"

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_egress_info_attached_to_active_interface(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test that egress info is only attached to active interface."""
        # Setup mocks
        mock_get_list.return_value = ["eth0", "wlan0"]
        mock_detect_type.return_value = InterfaceType.ETHERNET
        mock_device_name.return_value = "Test Device"
        mock_dns.return_value = ([], None)

        mock_all_ipv4.return_value = {
            "eth0": "192.168.1.100",
            "wlan0": "192.168.1.101"
        }
        mock_all_ipv6.return_value = {}

        # eth0 is active
        mock_active.return_value = "eth0"

        # Egress info available
        mock_egress.return_value = EgressInfo(
            external_ip="1.2.3.4",
            external_ipv6="--",
            isp="Test ISP",
            country="US"
        )

        with patch('orchestrator.get_route_info', return_value=("192.168.1.1", "100")):
            result = collect_network_data(parallel=False)

        # Verify egress attached to eth0 only
        assert result[0].name == "eth0"
        assert result[0].external_ipv4 == "1.2.3.4"
        assert result[0].egress_isp == "Test ISP"

        assert result[1].name == "wlan0"
        assert result[1].external_ipv4 == DataMarker.NOT_APPLICABLE
        assert result[1].egress_isp == DataMarker.NOT_APPLICABLE

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_dns_leak_check_called(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test that DNS leak check is called."""
        # Setup mocks
        mock_get_list.return_value = ["eth0"]
        mock_detect_type.return_value = InterfaceType.ETHERNET
        mock_device_name.return_value = "Test Device"
        mock_dns.return_value = ([], None)

        mock_all_ipv4.return_value = {"eth0": "192.168.1.100"}
        mock_all_ipv6.return_value = {}

        mock_active.return_value = None
        mock_egress.return_value = EgressInfo.create_error()

        with patch('orchestrator.get_route_info', return_value=("192.168.1.1", "100")):
            collect_network_data(parallel=False)

        # Verify DNS leak check was called
        assert mock_dns_leaks.called
        call_args = mock_dns_leaks.call_args[0][0]
        assert len(call_args) == 1
        assert isinstance(call_args[0], InterfaceInfo)

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_vpn_underlay_detection_called(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test that VPN underlay detection is called."""
        # Setup mocks
        mock_get_list.return_value = ["eth0"]
        mock_detect_type.return_value = InterfaceType.ETHERNET
        mock_device_name.return_value = "Test Device"
        mock_dns.return_value = ([], None)

        mock_all_ipv4.return_value = {"eth0": "192.168.1.100"}
        mock_all_ipv6.return_value = {}

        mock_active.return_value = None
        mock_egress.return_value = EgressInfo.create_error()

        with patch('orchestrator.get_route_info', return_value=("192.168.1.1", "100")):
            collect_network_data(parallel=False)

        # Verify VPN underlay detection was called
        assert mock_vpn_underlay.called


class TestDataIntegrity:
    """Tests for data integrity and consistency."""

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_interface_data_completeness(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test that all interface data fields are populated."""
        # Setup mocks
        mock_get_list.return_value = ["eth0"]
        mock_detect_type.return_value = InterfaceType.ETHERNET
        mock_device_name.return_value = "Test Device"
        mock_dns.return_value = (["8.8.8.8"], "8.8.8.8")

        mock_all_ipv4.return_value = {"eth0": "192.168.1.100"}
        mock_all_ipv6.return_value = {"eth0": "2001:db8::1"}

        mock_active.return_value = "eth0"
        mock_egress.return_value = EgressInfo(
            external_ip="1.2.3.4",
            external_ipv6="2001:db8::100",
            isp="Test ISP",
            country="US"
        )

        with patch('orchestrator.get_route_info', return_value=("192.168.1.1", "100")):
            result = collect_network_data(parallel=False)

        # Verify all fields populated
        interface = result[0]
        assert interface.name == "eth0"
        assert interface.interface_type == InterfaceType.ETHERNET
        assert interface.device == "Test Device"
        assert interface.internal_ipv4 == "192.168.1.100"
        assert interface.internal_ipv6 == "2001:db8::1"
        assert interface.dns_servers == ["8.8.8.8"]
        assert interface.current_dns == "8.8.8.8"
        assert interface.default_gateway == "192.168.1.1"
        assert interface.metric == "100"
        assert interface.external_ipv4 == "1.2.3.4"
        assert interface.external_ipv6 == "2001:db8::100"
        assert interface.egress_isp == "Test ISP"
        assert interface.egress_country == "US"

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    @patch('network.configuration.get_all_ipv6_addresses')
    @patch('network.configuration.get_all_ipv4_addresses')
    def test_dns_servers_list_format(
        self,
        mock_all_ipv4: MagicMock,
        mock_all_ipv6: MagicMock,
        mock_get_list: MagicMock,
        mock_detect_type: MagicMock,
        mock_device_name: MagicMock,
        mock_dns: MagicMock,
        mock_active: MagicMock,
        mock_egress: MagicMock,
        mock_dns_leaks: MagicMock,
        mock_vpn_underlay: MagicMock
    ) -> None:
        """Test that DNS servers are stored as a list."""
        # Setup mocks
        mock_get_list.return_value = ["eth0"]
        mock_detect_type.return_value = InterfaceType.ETHERNET
        mock_device_name.return_value = "Test Device"

        # Multiple DNS servers
        mock_dns.return_value = (["8.8.8.8", "8.8.4.4", "1.1.1.1"], "8.8.8.8")

        mock_all_ipv4.return_value = {"eth0": "192.168.1.100"}
        mock_all_ipv6.return_value = {}

        mock_active.return_value = None
        mock_egress.return_value = EgressInfo.create_error()

        with patch('orchestrator.get_route_info', return_value=("192.168.1.1", "100")):
            result = collect_network_data(parallel=False)

        # Verify DNS servers list format
        interface = result[0]
        assert isinstance(interface.dns_servers, list)
        assert len(interface.dns_servers) == 3
        assert interface.dns_servers == ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        assert interface.current_dns == "8.8.8.8"
