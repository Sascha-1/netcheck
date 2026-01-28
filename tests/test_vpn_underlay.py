"""
Tests for network.vpn_underlay module.

Tests VPN server endpoint detection and physical interface underlay detection.
"""

import pytest
from unittest.mock import patch, Mock
from network.vpn_underlay import (
    get_vpn_connection_endpoint,
    get_vpn_server_endpoint,
    find_physical_interface_for_vpn,
    detect_vpn_underlay
)
from models import InterfaceInfo



class TestGetVpnConnectionEndpoint:
    """Test generic VPN connection endpoint detection."""
    
    @patch('network.vpn_underlay.subprocess.run')
    def test_successful_connection_detection(self, mock_run):
        """Test finding VPN server from active connection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Netid State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
udp   ESTAB      0      0      10.2.0.2:54321       159.26.108.89:51820"""
        mock_run.return_value = mock_result
        
        result = get_vpn_connection_endpoint("tun0", "10.2.0.2")
        
        assert result == "159.26.108.89"
    
    @patch('network.vpn_underlay.subprocess.run')
    def test_ignores_dns_connections(self, mock_run):
        """Test that DNS connections are ignored."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Netid State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
udp   ESTAB      0      0      10.2.0.2:54321       10.2.0.1:53
udp   ESTAB      0      0      10.2.0.2:54322       159.26.108.89:51820"""
        mock_run.return_value = mock_result
        
        result = get_vpn_connection_endpoint("tun0", "10.2.0.2")
        
        # Should find non-DNS connection
        assert result == "159.26.108.89"
    
    @patch('network.vpn_underlay.subprocess.run')
    def test_ipv6_connection(self, mock_run):
        """Test IPv6 VPN connection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Netid State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
udp   ESTAB      0      0      [2a07:b944::2:2]:54321  [2001:db8::1]:51820"""
        mock_run.return_value = mock_result
        
        result = get_vpn_connection_endpoint("tun0", "2a07:b944::2:2")
        
        assert result == "2001:db8::1"
    
    @patch('network.vpn_underlay.subprocess.run')
    def test_no_matching_connection(self, mock_run):
        """Test when no connection matches VPN interface."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Netid State  Local Address:Port  Peer Address:Port
udp   ESTAB  192.168.1.100:54321  8.8.8.8:53"""
        mock_run.return_value = mock_result
        
        result = get_vpn_connection_endpoint("tun0", "10.2.0.2")
        
        assert result is None
    
    @patch('network.vpn_underlay.subprocess.run')
    def test_command_failure(self, mock_run):
        """Test ss command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result
        
        result = get_vpn_connection_endpoint("tun0", "10.2.0.2")
        
        assert result is None


class TestGetVpnServerEndpoint:
    """Test VPN server endpoint detection (connection-based)."""
    
    @patch('network.vpn_underlay.get_vpn_connection_endpoint')
    def test_successful_detection(self, mock_conn):
        """Test that connection detection works."""
        mock_conn.return_value = "159.26.108.89"
        
        result = get_vpn_server_endpoint("tun0", "vpn", "10.2.0.2")
        
        assert result == "159.26.108.89"
        mock_conn.assert_called_once()
    
    def test_non_vpn_interface(self):
        """Test that non-VPN interfaces return None."""
        result = get_vpn_server_endpoint("eth0", "ethernet", "192.168.1.100")
        
        assert result is None
    
    def test_no_local_ip(self):
        """Test when interface has no local IP."""
        result = get_vpn_server_endpoint("tun0", "vpn", "N/A")
        
        assert result is None


class TestFindPhysicalInterfaceForVpn:
    """Test physical interface detection for VPN."""
    
    def test_successful_detection(self):
        """Test finding physical interface from gateway method."""
        from models import InterfaceInfo
        
        # Mock interfaces list
        interfaces = [
            InterfaceInfo.create_empty("eth0"),
            InterfaceInfo.create_empty("tun0")
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[0].default_gateway = "192.168.1.1"
        interfaces[0].metric = "100"
        interfaces[1].interface_type = "vpn"
        interfaces[1].default_gateway = "NONE"
        
        result = find_physical_interface_for_vpn("159.26.108.89", interfaces)
        
        assert result == "eth0"
    
    @patch('network.vpn_underlay.run_command')
    def test_direct_route(self, mock_run):
        """Test direct route without via gateway."""
        from models import InterfaceInfo
        
        mock_run.return_value = "159.26.108.89 dev wlan0 src 192.168.1.101"
        
        interfaces = [
            InterfaceInfo.create_empty("wlan0"),
        ]
        interfaces[0].interface_type = "wireless"
        interfaces[0].default_gateway = "192.168.1.1"
        
        result = find_physical_interface_for_vpn("159.26.108.89", interfaces)
        
        assert result == "wlan0"
    
    @patch('network.vpn_underlay.run_command')
    def test_command_failure(self, mock_run):
        """Test when route command fails - uses fallback method."""
        from models import InterfaceInfo
        
        mock_run.return_value = None
        
        # Fallback should find eth0 as it has a default gateway
        interfaces = [
            InterfaceInfo.create_empty("eth0"),
            InterfaceInfo.create_empty("tun0")
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[0].default_gateway = "192.168.1.1"
        interfaces[0].metric = "100"
        interfaces[1].interface_type = "vpn"
        
        result = find_physical_interface_for_vpn("159.26.108.89", interfaces)
        
        assert result == "eth0"  # Fallback finds physical interface with gateway
    
    @patch('network.vpn_underlay.run_command')
    def test_malformed_output(self, mock_run):
        """Test malformed route output - uses fallback."""
        from models import InterfaceInfo
        
        mock_run.return_value = "malformed output without dev"
        
        interfaces = [
            InterfaceInfo.create_empty("eth0"),
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[0].default_gateway = "192.168.1.1"
        interfaces[0].metric = "100"
        
        result = find_physical_interface_for_vpn("159.26.108.89", interfaces)
        
        assert result == "eth0"  # Fallback finds physical interface
    
    def test_ipv6_route(self):
        """Test IPv6 VPN server with physical interface."""
        from models import InterfaceInfo
        
        interfaces = [
            InterfaceInfo.create_empty("eth0"),
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[0].default_gateway = "fe80::1"
        interfaces[0].metric = "100"
        
        result = find_physical_interface_for_vpn("2001:db8::1", interfaces)
        
        assert result == "eth0"
    
    @patch('network.vpn_underlay.run_command')
    def test_protonvpn_routing_table(self, mock_run):
        """Test ProtonVPN case where ip route get returns VPN interface."""
        from models import InterfaceInfo
        
        # ProtonVPN returns the VPN interface itself due to custom routing tables
        mock_run.return_value = "185.70.42.41 dev proton0 table 106088063 src 10.2.0.2"
        
        interfaces = [
            InterfaceInfo.create_empty("eno2"),
            InterfaceInfo.create_empty("proton0")
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[0].default_gateway = "192.168.8.1"
        interfaces[0].metric = "100"
        interfaces[1].interface_type = "vpn"
        
        result = find_physical_interface_for_vpn("185.70.42.41", interfaces)
        
        # Should detect proton0 is a VPN interface and use fallback
        assert result == "eno2"
    
    @patch('network.vpn_underlay.run_command')
    def test_no_physical_interface(self, mock_run):
        """Test when no physical interfaces have default gateway."""
        from models import InterfaceInfo
        
        mock_run.return_value = None
        
        # Only VPN interfaces, no physical ones with gateway
        interfaces = [
            InterfaceInfo.create_empty("tun0"),
        ]
        interfaces[0].interface_type = "vpn"
        
        result = find_physical_interface_for_vpn("159.26.108.89", interfaces)
        
        assert result is None


class TestDetectVpnUnderlay:
    """Test complete VPN underlay detection."""
    
    @patch('network.vpn_underlay.find_physical_interface_for_vpn')
    @patch('network.vpn_underlay.get_vpn_server_endpoint')
    def test_single_vpn_detection(self, mock_get_endpoint, mock_find_physical):
        """Test detecting underlay for single VPN."""
        mock_get_endpoint.return_value = "159.26.108.89"
        mock_find_physical.return_value = "eth0"
        
        interfaces = [
            InterfaceInfo(
                name="eth0",
                interface_type="ethernet",
                device="Intel I219",
                internal_ipv4="192.168.1.100",
                internal_ipv6="N/A",
                dns_servers=[],
                current_dns=None,
                dns_leak_status="--",
                external_ipv4="--",
                external_ipv6="--",
                egress_isp="--",
                egress_country="--",
                default_gateway="192.168.1.1",
                metric="100"
            ),
            InterfaceInfo(
                name="tun0",
                interface_type="vpn",
                device="N/A",
                internal_ipv4="10.2.0.2",
                internal_ipv6="N/A",
                dns_servers=["10.2.0.1"],
                current_dns="10.2.0.1",
                dns_leak_status="OK",
                external_ipv4="159.26.108.89",
                external_ipv6="2a07:b944::2:2",
                egress_isp="Proton AG",
                egress_country="SE",
                default_gateway="NONE",
                metric="98"
            )
        ]
        
        detect_vpn_underlay(interfaces)
        
        # Check VPN interface has server IP
        vpn_if = [i for i in interfaces if i.name == "tun0"][0]
        assert vpn_if.vpn_server_ip == "159.26.108.89"
        
        # Check physical interface is marked
        eth_if = [i for i in interfaces if i.name == "eth0"][0]
        assert eth_if.carries_vpn is True
    
    @patch('network.vpn_underlay.find_physical_interface_for_vpn')
    @patch('network.vpn_underlay.get_vpn_server_endpoint')
    def test_multiple_vpn_same_physical(self, mock_get_endpoint, mock_find_physical):
        """Test multiple VPNs using same physical interface."""
        mock_get_endpoint.side_effect = ["159.26.108.89", "159.26.108.90"]
        mock_find_physical.return_value = "eth0"
        
        interfaces = [
            InterfaceInfo.create_empty("eth0"),
            InterfaceInfo.create_empty("tun0"),
            InterfaceInfo.create_empty("tun1")
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[0].internal_ipv4 = "192.168.1.100"
        interfaces[1].interface_type = "vpn"
        interfaces[1].internal_ipv4 = "10.2.0.2"
        interfaces[2].interface_type = "vpn"
        interfaces[2].internal_ipv4 = "10.3.0.2"
        
        detect_vpn_underlay(interfaces)
        
        # Both VPNs should have their server IPs
        assert interfaces[1].vpn_server_ip == "159.26.108.89"
        assert interfaces[2].vpn_server_ip == "159.26.108.90"
        
        # Physical interface should be marked
        assert interfaces[0].carries_vpn is True
    
    @patch('network.vpn_underlay.find_physical_interface_for_vpn')
    @patch('network.vpn_underlay.get_vpn_server_endpoint')
    def test_vpn_endpoint_not_found(self, mock_get_endpoint, mock_find_physical):
        """Test when VPN endpoint cannot be determined."""
        mock_get_endpoint.return_value = None
        
        interfaces = [
            InterfaceInfo.create_empty("eth0"),
            InterfaceInfo.create_empty("tun0")
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[1].interface_type = "vpn"
        interfaces[1].internal_ipv4 = "10.2.0.2"
        
        detect_vpn_underlay(interfaces)
        
        # VPN should not have server IP
        assert interfaces[1].vpn_server_ip is None
        
        # Physical interface should not be marked
        assert interfaces[0].carries_vpn is False
        
        # find_physical should not be called
        mock_find_physical.assert_not_called()
    
    @patch('network.vpn_underlay.find_physical_interface_for_vpn')
    @patch('network.vpn_underlay.get_vpn_server_endpoint')
    def test_no_vpn_interfaces(self, mock_get_endpoint, mock_find_physical):
        """Test when no VPN interfaces exist."""
        interfaces = [
            InterfaceInfo.create_empty("eth0"),
            InterfaceInfo.create_empty("wlan0")
        ]
        interfaces[0].interface_type = "ethernet"
        interfaces[1].interface_type = "wireless"
        
        detect_vpn_underlay(interfaces)
        
        # Nothing should be marked
        assert interfaces[0].carries_vpn is False
        assert interfaces[1].carries_vpn is False
        
        # Detection should not be called
        mock_get_endpoint.assert_not_called()
        mock_find_physical.assert_not_called()
