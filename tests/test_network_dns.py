"""
Tests for network.dns module.

Tests DNS configuration detection and DNS leak monitoring.
"""

import pytest
from unittest.mock import patch, Mock, MagicMock

from models import InterfaceInfo, EgressInfo
from network.dns import (
    get_interface_dns,
    get_system_dns,
    detect_dns_leak,
    collect_dns_servers_by_category,
    check_dns_leaks_all_interfaces
)


class TestGetInterfaceDns:
    """Test DNS server retrieval for interface."""

    @patch('network.dns.subprocess.run')
    def test_basic_dns_servers(self, mock_run: MagicMock) -> None:

        """Test retrieving basic DNS configuration."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Link 2 (eth0)
    Current Scopes: DNS
     DefaultRoute setting: yes
  Current DNS Server: 8.8.8.8
         DNS Servers: 8.8.8.8
                      8.8.4.4
          DNS Domain: ~."""
        mock_run.return_value = mock_result

        dns_list, current_dns = get_interface_dns("eth0")

        assert len(dns_list) == 2
        assert "8.8.8.8" in dns_list
        assert "8.8.4.4" in dns_list
        assert current_dns == "8.8.8.8"

    @patch('network.dns.subprocess.run')
    def test_current_dns_not_in_list(self, mock_run: MagicMock) -> None:

        """Test when current DNS is added to list."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Link 2 (eth0)
  Current DNS Server: 1.1.1.1
         DNS Servers: 8.8.8.8
                      8.8.4.4"""
        mock_run.return_value = mock_result

        dns_list, current_dns = get_interface_dns("eth0")

        assert "1.1.1.1" in dns_list
        assert current_dns == "1.1.1.1"
        # Current DNS should be first
        assert dns_list[0] == "1.1.1.1"

    @patch('network.dns.subprocess.run')
    def test_no_dns_configured(self, mock_run: MagicMock) -> None:

        """Test interface without DNS configuration."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Link 2 (eth0)
    Current Scopes: none"""
        mock_run.return_value = mock_result

        dns_list, current_dns = get_interface_dns("eth0")

        assert dns_list == []
        assert current_dns is None

    @patch('network.dns.subprocess.run')
    def test_resolvectl_failure(self, mock_run: MagicMock) -> None:

        """Test handling of resolvectl command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        dns_list, current_dns = get_interface_dns("eth0")

        assert dns_list == []
        assert current_dns is None

    @patch('network.dns.subprocess.run')
    def test_ipv6_dns_servers(self, mock_run: MagicMock) -> None:

        """Test IPv6 DNS servers."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Link 4 (tun0)
  Current DNS Server: 2001:db8::1
         DNS Servers: 2001:db8::1
                      2001:db8::2"""
        mock_run.return_value = mock_result

        dns_list, current_dns = get_interface_dns("tun0")

        assert len(dns_list) == 2
        assert "2001:db8::1" in dns_list
        assert current_dns == "2001:db8::1"

    @patch('network.dns.subprocess.run')
    def test_vpn_dns_server(self, mock_run: MagicMock) -> None:

        """Test VPN DNS configuration."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Link 4 (tun0)
  Current DNS Server: 10.2.0.1
         DNS Servers: 10.2.0.1"""
        mock_run.return_value = mock_result

        dns_list, current_dns = get_interface_dns("tun0")

        assert dns_list == ["10.2.0.1"]
        assert current_dns == "10.2.0.1"

    @patch('network.dns.subprocess.run')
    def test_timeout(self, mock_run: MagicMock) -> None:

        """Test handling of timeout."""
        mock_run.side_effect = Exception("timeout")

        dns_list, current_dns = get_interface_dns("eth0")

        assert dns_list == []
        assert current_dns is None


class TestGetSystemDns:
    """Test system-wide DNS retrieval."""

    @patch('network.dns.subprocess.run')
    def test_global_dns_servers(self, mock_run: MagicMock) -> None:

        """Test retrieving global DNS configuration."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Global
         Protocols: +LLMNR +mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub
       DNS Servers: 8.8.8.8
                    8.8.4.4

Link 2 (eth0)
    Current Scopes: DNS"""
        mock_run.return_value = mock_result

        dns_list = get_system_dns()

        assert len(dns_list) == 2
        assert "8.8.8.8" in dns_list
        assert "8.8.4.4" in dns_list

    @patch('network.dns.subprocess.run')
    def test_no_global_dns(self, mock_run: MagicMock) -> None:

        """Test when no global DNS is configured."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Global
         Protocols: +LLMNR +mDNS
  resolv.conf mode: stub

Link 2 (eth0)"""
        mock_run.return_value = mock_result

        dns_list = get_system_dns()

        assert dns_list == []

    @patch('network.dns.subprocess.run')
    def test_command_failure(self, mock_run: MagicMock) -> None:

        """Test handling of command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        dns_list = get_system_dns()

        assert dns_list == []




class TestDetectDnsLeak:
    """Test DNS leak detection logic (deterministic, configuration-based)."""

    def test_no_vpn_active(self) -> None:

        """Test when no VPN is active."""
        result = detect_dns_leak(
            interface_name="eth0",
            interface_ip="192.168.1.100",
            configured_dns=["192.168.1.1"],
            is_vpn=False,
            vpn_dns=[],
            isp_dns=["192.168.1.1"]
        )

        assert result == "--"

    def test_leak_via_isp_dns(self) -> None:

        """Test leak detected when using ISP DNS."""
        result = detect_dns_leak(
            interface_name="eth0",
            interface_ip="192.168.1.100",
            configured_dns=["192.168.1.1"],
            is_vpn=False,
            vpn_dns=["10.2.0.1"],
            isp_dns=["192.168.1.1"]
        )

        assert result == "LEAK"

    def test_ok_via_vpn_dns(self) -> None:

        """Test OK status when using VPN DNS."""
        result = detect_dns_leak(
            interface_name="tun0",
            interface_ip="10.2.0.2",
            configured_dns=["10.2.0.1"],
            is_vpn=True,
            vpn_dns=["10.2.0.1"],
            isp_dns=["192.168.1.1"]
        )

        assert result == "OK"

    def test_ok_via_public_dns(self) -> None:

        """Test OK status when using public DNS (Cloudflare)."""
        result = detect_dns_leak(
            interface_name="eth0",
            interface_ip="192.168.1.100",
            configured_dns=["1.1.1.1"],
            is_vpn=False,
            vpn_dns=["10.2.0.1"],
            isp_dns=["192.168.1.1"]
        )

        assert result == "OK"

    def test_ok_via_google_dns(self) -> None:

        """Test OK status when using Google DNS."""
        result = detect_dns_leak(
            interface_name="eth0",
            interface_ip="192.168.1.100",
            configured_dns=["8.8.8.8"],
            is_vpn=False,
            vpn_dns=["10.2.0.1"],
            isp_dns=["192.168.1.1"]
        )

        assert result == "OK"

    def test_warn_unknown_dns(self) -> None:

        """Test warning for unknown DNS server."""
        result = detect_dns_leak(
            interface_name="eth0",
            interface_ip="192.168.1.100",
            configured_dns=["9.9.9.10"],  # Not in public DNS list
            is_vpn=False,
            vpn_dns=["10.2.0.1"],
            isp_dns=["192.168.1.1"]
        )

        assert result == "WARN"

    def test_no_configured_dns(self) -> None:

        """Test when no DNS configured."""
        result = detect_dns_leak(
            interface_name="eth0",
            interface_ip="192.168.1.100",
            configured_dns=[],
            is_vpn=False,
            vpn_dns=["10.2.0.1"],
            isp_dns=["192.168.1.1"]
        )

        assert result == "--"


class TestCollectDnsServersByCategory:
    """Test DNS server categorization."""

    def test_categorize_vpn_and_isp(self, sample_interface_list: list[InterfaceInfo]) -> None:

        """Test categorizing VPN and ISP DNS servers."""
        vpn_dns, isp_dns = collect_dns_servers_by_category(sample_interface_list)

        assert len(vpn_dns) > 0
        assert len(isp_dns) > 0

    def test_no_duplicates(self) -> None:

        """Test that duplicates are removed."""
        from models import InterfaceInfo

        interfaces = [
            InterfaceInfo(
                name="eth0",
                interface_type="ethernet",
                device="N/A",
                internal_ipv4="192.168.1.100",
                internal_ipv6="N/A",
                dns_servers=["8.8.8.8"],
                current_dns="8.8.8.8",
                dns_leak_status="--",
                external_ipv4="--",
                external_ipv6="--",
                egress_isp="--",
                egress_country="--",
                default_gateway="192.168.1.1",
                metric="100"
            ),
            InterfaceInfo(
                name="wlan0",
                interface_type="wireless",
                device="N/A",
                internal_ipv4="192.168.1.101",
                internal_ipv6="N/A",
                dns_servers=["8.8.8.8"],  # Same DNS
                current_dns="8.8.8.8",
                dns_leak_status="--",
                external_ipv4="--",
                external_ipv6="--",
                egress_isp="--",
                egress_country="--",
                default_gateway="192.168.1.1",
                metric="100"
            )
        ]

        vpn_dns, isp_dns = collect_dns_servers_by_category(interfaces)

        # Should only have one instance of 8.8.8.8
        assert isp_dns.count("8.8.8.8") == 1


class TestCheckDnsLeaksAllInterfaces:
    """Test complete DNS leak checking."""

    def test_update_interface_status(self, sample_interface_list: list[InterfaceInfo]) -> None:

        """Test that interface status is updated."""
        # Initially all should be "--"
        check_dns_leaks_all_interfaces(sample_interface_list)

        # Status should be updated
        for interface in sample_interface_list:
            # dns_leak_status should be set to something
            assert interface.dns_leak_status in ["OK", "LEAK", "WARN", "--"]

    def test_interfaces_without_ipv4(self) -> None:

        """Test that interfaces without IPv4 get '--' status."""
        from models import InterfaceInfo

        interfaces = [
            InterfaceInfo.create_empty("eth0")
        ]

        check_dns_leaks_all_interfaces(interfaces)

        assert interfaces[0].dns_leak_status == "--"
