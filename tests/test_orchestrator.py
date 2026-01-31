"""Comprehensive tests for orchestrator.py - network detection coordination."""

from typing import List
from unittest.mock import Mock, patch
import pytest

from models import InterfaceInfo, EgressInfo
from enums import InterfaceType, DnsLeakStatus, DataMarker


class TestCheckDependencies:
    """Test dependency checking."""

    @patch('orchestrator.shutil.which')
    def test_all_dependencies_present(self, mock_which: Mock) -> None:
        """Test when all dependencies are present."""
        from orchestrator import check_dependencies
        
        mock_which.return_value = "/usr/bin/cmd"
        
        result = check_dependencies()
        
        assert result is True

    @patch('orchestrator.shutil.which')
    def test_missing_dependency(self, mock_which: Mock) -> None:
        """Test when a dependency is missing."""
        from orchestrator import check_dependencies
        
        # First call returns None (missing), rest return paths
        mock_which.side_effect = [None, "/usr/bin/cmd", "/usr/bin/cmd", "/usr/bin/cmd", "/usr/bin/cmd", "/usr/bin/cmd"]
        
        result = check_dependencies()
        
        assert result is False


class TestCollectNetworkData:
    """Test main network data collection function."""

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_route_metric')
    @patch('orchestrator.get_default_gateway')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_internal_ipv6')
    @patch('orchestrator.get_internal_ipv4')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    def test_collect_single_interface(
        self,
        mock_get_interfaces: Mock,
        mock_detect_type: Mock,
        mock_get_device: Mock,
        mock_get_ipv4: Mock,
        mock_get_ipv6: Mock,
        mock_get_dns: Mock,
        mock_get_gateway: Mock,
        mock_get_metric: Mock,
        mock_get_active: Mock,
        mock_get_egress: Mock,
        mock_check_leaks: Mock,
        mock_detect_vpn: Mock,
    ) -> None:
        """Test collecting info for a single interface."""
        from orchestrator import collect_network_data
        
        # Setup mocks
        mock_get_interfaces.return_value = ["eth0"]
        mock_detect_type.return_value = str(InterfaceType.ETHERNET)
        mock_get_device.return_value = "Intel I219-V"
        mock_get_ipv4.return_value = "192.168.1.100"
        mock_get_ipv6.return_value = "N/A"
        mock_get_dns.return_value = (["192.168.1.1"], "192.168.1.1")
        mock_get_gateway.return_value = "192.168.1.1"
        mock_get_metric.return_value = "100"
        mock_get_active.return_value = "eth0"
        mock_get_egress.return_value = EgressInfo(
            external_ip="203.0.113.1",
            external_ipv6="--",
            isp="Example ISP",
            country="US"
        )
        
        result = collect_network_data()
        
        assert len(result) == 1
        assert result[0].name == "eth0"
        assert result[0].interface_type == str(InterfaceType.ETHERNET)
        assert result[0].external_ipv4 == "203.0.113.1"

    @patch('orchestrator.get_interface_list')
    def test_collect_no_interfaces(self, mock_get_interfaces: Mock) -> None:
        """Test collection when no interfaces are found."""
        from orchestrator import collect_network_data
        
        mock_get_interfaces.return_value = []
        
        result = collect_network_data()
        
        assert result == []

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_route_metric')
    @patch('orchestrator.get_default_gateway')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_internal_ipv6')
    @patch('orchestrator.get_internal_ipv4')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    def test_collect_multiple_interfaces(
        self,
        mock_get_interfaces: Mock,
        mock_detect_type: Mock,
        mock_get_device: Mock,
        mock_get_ipv4: Mock,
        mock_get_ipv6: Mock,
        mock_get_dns: Mock,
        mock_get_gateway: Mock,
        mock_get_metric: Mock,
        mock_get_active: Mock,
        mock_get_egress: Mock,
        mock_check_leaks: Mock,
        mock_detect_vpn: Mock,
    ) -> None:
        """Test collecting info for multiple interfaces."""
        from orchestrator import collect_network_data
        
        mock_get_interfaces.return_value = ["lo", "eth0"]
        
        def type_side_effect(iface: str) -> str:
            return str(InterfaceType.LOOPBACK) if iface == "lo" else str(InterfaceType.ETHERNET)
        
        mock_detect_type.side_effect = type_side_effect
        mock_get_device.return_value = "N/A"
        mock_get_ipv4.return_value = "127.0.0.1"
        mock_get_ipv6.return_value = "::1"
        mock_get_dns.return_value = ([], None)
        mock_get_gateway.return_value = "NONE"
        mock_get_metric.return_value = "NONE"
        mock_get_active.return_value = None
        mock_get_egress.return_value = None
        
        result = collect_network_data()
        
        assert len(result) == 2
        assert any(i.name == "lo" for i in result)
        assert any(i.name == "eth0" for i in result)

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_route_metric')
    @patch('orchestrator.get_default_gateway')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_internal_ipv6')
    @patch('orchestrator.get_internal_ipv4')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    def test_egress_info_attached_to_active_interface(
        self,
        mock_get_interfaces: Mock,
        mock_detect_type: Mock,
        mock_get_device: Mock,
        mock_get_ipv4: Mock,
        mock_get_ipv6: Mock,
        mock_get_dns: Mock,
        mock_get_gateway: Mock,
        mock_get_metric: Mock,
        mock_get_active: Mock,
        mock_get_egress: Mock,
        mock_check_leaks: Mock,
        mock_detect_vpn: Mock,
    ) -> None:
        """Test that egress info is attached only to active interface."""
        from orchestrator import collect_network_data
        
        mock_get_interfaces.return_value = ["eth0", "wlan0"]
        mock_detect_type.return_value = str(InterfaceType.ETHERNET)
        mock_get_device.return_value = "Test Device"
        mock_get_ipv4.return_value = "192.168.1.100"
        mock_get_ipv6.return_value = "N/A"
        mock_get_dns.return_value = ([], None)
        mock_get_gateway.return_value = "192.168.1.1"
        mock_get_metric.return_value = "100"
        mock_get_active.return_value = "eth0"  # Only eth0 is active
        mock_get_egress.return_value = EgressInfo(
            external_ip="203.0.113.1",
            external_ipv6="--",
            isp="Example ISP",
            country="US"
        )
        
        result = collect_network_data()
        
        # Find eth0 and wlan0
        eth0 = next(i for i in result if i.name == "eth0")
        wlan0 = next(i for i in result if i.name == "wlan0")
        
        # Only eth0 should have egress info
        assert eth0.external_ipv4 == "203.0.113.1"
        assert wlan0.external_ipv4 == str(DataMarker.NOT_APPLICABLE)

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_route_metric')
    @patch('orchestrator.get_default_gateway')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_internal_ipv6')
    @patch('orchestrator.get_internal_ipv4')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    def test_dns_leak_check_called(
        self,
        mock_get_interfaces: Mock,
        mock_detect_type: Mock,
        mock_get_device: Mock,
        mock_get_ipv4: Mock,
        mock_get_ipv6: Mock,
        mock_get_dns: Mock,
        mock_get_gateway: Mock,
        mock_get_metric: Mock,
        mock_get_active: Mock,
        mock_get_egress: Mock,
        mock_check_leaks: Mock,
        mock_detect_vpn: Mock,
    ) -> None:
        """Test that DNS leak check is called."""
        from orchestrator import collect_network_data
        
        mock_get_interfaces.return_value = ["eth0"]
        mock_detect_type.return_value = str(InterfaceType.ETHERNET)
        mock_get_device.return_value = "Test"
        mock_get_ipv4.return_value = "192.168.1.100"
        mock_get_ipv6.return_value = "N/A"
        mock_get_dns.return_value = ([], None)
        mock_get_gateway.return_value = "NONE"
        mock_get_metric.return_value = "NONE"
        mock_get_active.return_value = None
        
        collect_network_data()
        
        mock_check_leaks.assert_called_once()

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_route_metric')
    @patch('orchestrator.get_default_gateway')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_internal_ipv6')
    @patch('orchestrator.get_internal_ipv4')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    def test_vpn_underlay_detection_called(
        self,
        mock_get_interfaces: Mock,
        mock_detect_type: Mock,
        mock_get_device: Mock,
        mock_get_ipv4: Mock,
        mock_get_ipv6: Mock,
        mock_get_dns: Mock,
        mock_get_gateway: Mock,
        mock_get_metric: Mock,
        mock_get_active: Mock,
        mock_get_egress: Mock,
        mock_check_leaks: Mock,
        mock_detect_vpn: Mock,
    ) -> None:
        """Test that VPN underlay detection is called."""
        from orchestrator import collect_network_data
        
        mock_get_interfaces.return_value = ["eth0"]
        mock_detect_type.return_value = str(InterfaceType.ETHERNET)
        mock_get_device.return_value = "Test"
        mock_get_ipv4.return_value = "192.168.1.100"
        mock_get_ipv6.return_value = "N/A"
        mock_get_dns.return_value = ([], None)
        mock_get_gateway.return_value = "NONE"
        mock_get_metric.return_value = "NONE"
        mock_get_active.return_value = None
        
        collect_network_data()
        
        mock_detect_vpn.assert_called_once()


class TestDataIntegrity:
    """Test data integrity and consistency."""

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_route_metric')
    @patch('orchestrator.get_default_gateway')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_internal_ipv6')
    @patch('orchestrator.get_internal_ipv4')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    def test_interface_data_completeness(
        self,
        mock_get_interfaces: Mock,
        mock_detect_type: Mock,
        mock_get_device: Mock,
        mock_get_ipv4: Mock,
        mock_get_ipv6: Mock,
        mock_get_dns: Mock,
        mock_get_gateway: Mock,
        mock_get_metric: Mock,
        mock_get_active: Mock,
        mock_get_egress: Mock,
        mock_check_leaks: Mock,
        mock_detect_vpn: Mock,
    ) -> None:
        """Test that collected data has all required fields."""
        from orchestrator import collect_network_data
        
        mock_get_interfaces.return_value = ["eth0"]
        mock_detect_type.return_value = str(InterfaceType.ETHERNET)
        mock_get_device.return_value = "Intel I219-V"
        mock_get_ipv4.return_value = "192.168.1.100"
        mock_get_ipv6.return_value = "fe80::1"
        mock_get_dns.return_value = (["192.168.1.1"], "192.168.1.1")
        mock_get_gateway.return_value = "192.168.1.1"
        mock_get_metric.return_value = "100"
        mock_get_active.return_value = "eth0"
        mock_get_egress.return_value = EgressInfo(
            external_ip="203.0.113.1",
            external_ipv6="2001:db8::1",
            isp="Example ISP",
            country="US",
        )
        
        result = collect_network_data()
        
        # Verify structure
        assert len(result) == 1
        interface = result[0]
        
        # Check all required fields exist
        assert hasattr(interface, 'name')
        assert hasattr(interface, 'interface_type')
        assert hasattr(interface, 'device')
        assert hasattr(interface, 'internal_ipv4')
        assert hasattr(interface, 'internal_ipv6')
        assert hasattr(interface, 'dns_servers')
        assert hasattr(interface, 'current_dns')
        assert hasattr(interface, 'external_ipv4')
        assert hasattr(interface, 'external_ipv6')
        assert hasattr(interface, 'egress_isp')
        assert hasattr(interface, 'egress_country')
        assert hasattr(interface, 'default_gateway')
        assert hasattr(interface, 'metric')
        
        # Check values
        assert interface.name == "eth0"
        assert interface.device == "Intel I219-V"
        assert interface.internal_ipv4 == "192.168.1.100"
        assert interface.external_ipv4 == "203.0.113.1"

    @patch('orchestrator.detect_vpn_underlay')
    @patch('orchestrator.check_dns_leaks_all_interfaces')
    @patch('orchestrator.get_egress_info')
    @patch('orchestrator.get_active_interface')
    @patch('orchestrator.get_route_metric')
    @patch('orchestrator.get_default_gateway')
    @patch('orchestrator.get_interface_dns')
    @patch('orchestrator.get_internal_ipv6')
    @patch('orchestrator.get_internal_ipv4')
    @patch('orchestrator.get_device_name')
    @patch('orchestrator.detect_interface_type')
    @patch('orchestrator.get_interface_list')
    def test_dns_servers_list_format(
        self,
        mock_get_interfaces: Mock,
        mock_detect_type: Mock,
        mock_get_device: Mock,
        mock_get_ipv4: Mock,
        mock_get_ipv6: Mock,
        mock_get_dns: Mock,
        mock_get_gateway: Mock,
        mock_get_metric: Mock,
        mock_get_active: Mock,
        mock_get_egress: Mock,
        mock_check_leaks: Mock,
        mock_detect_vpn: Mock,
    ) -> None:
        """Test that DNS servers are stored as list."""
        from orchestrator import collect_network_data
        
        mock_get_interfaces.return_value = ["eth0"]
        mock_detect_type.return_value = str(InterfaceType.ETHERNET)
        mock_get_device.return_value = "Test"
        mock_get_ipv4.return_value = "192.168.1.100"
        mock_get_ipv6.return_value = "N/A"
        mock_get_dns.return_value = (["8.8.8.8", "8.8.4.4"], "8.8.8.8")
        mock_get_gateway.return_value = "NONE"
        mock_get_metric.return_value = "NONE"
        mock_get_active.return_value = None
        
        result = collect_network_data()
        
        interface = result[0]
        assert isinstance(interface.dns_servers, list)
        assert interface.dns_servers == ["8.8.8.8", "8.8.4.4"]
        assert interface.current_dns == "8.8.8.8"
