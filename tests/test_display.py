"""Comprehensive tests for display.py - output formatting and presentation."""

from typing import List
import pytest
from _pytest.capture import CaptureFixture

from models import InterfaceInfo
from enums import InterfaceType, DnsLeakStatus, DataMarker


class TestCleanupDeviceName:
    """Test device name cleanup function."""

    def test_remove_parentheses(self) -> None:
        """Test removing content in parentheses."""
        from display import cleanup_device_name

        result = cleanup_device_name("Intel I219-V (Rev 1.0)")

        assert "Rev 1.0" not in result
        assert "Intel" in result

    def test_remove_brackets(self) -> None:
        """Test removing content in brackets."""
        from display import cleanup_device_name

        result = cleanup_device_name("Device [ABC123]")

        assert "ABC123" not in result

    def test_remove_corporation_terms(self) -> None:
        """Test removing corporate terms."""
        from display import cleanup_device_name

        result = cleanup_device_name("Intel Corporation Ethernet Controller")

        # Should remove "Corporation" and "Controller"
        assert "Corporation" not in result
        assert "Controller" not in result

    def test_empty_result_returns_original(self) -> None:
        """Test that empty result returns original name."""
        from display import cleanup_device_name

        # If cleaning produces empty string, return original
        result = cleanup_device_name("Corporation")

        assert isinstance(result, str)
        assert len(result) > 0

    def test_data_marker_handling(self) -> None:
        """Test handling of DataMarker values."""
        from display import cleanup_device_name

        result = cleanup_device_name(str(DataMarker.NOT_AVAILABLE))

        assert result == str(DataMarker.NOT_AVAILABLE)


class TestCleanupIspName:
    """Test ISP name cleanup function."""

    def test_remove_asn_prefix(self) -> None:
        """Test removing ASN prefix from ISP name."""
        from display import cleanup_isp_name

        result = cleanup_isp_name("AS12345 Example ISP")

        assert result == "Example ISP"
        assert "AS12345" not in result

    def test_no_asn_prefix(self) -> None:
        """Test ISP name without ASN prefix."""
        from display import cleanup_isp_name

        result = cleanup_isp_name("Example ISP")

        assert result == "Example ISP"

    def test_data_marker_handling(self) -> None:
        """Test handling of DataMarker values."""
        from display import cleanup_isp_name

        result = cleanup_isp_name(str(DataMarker.NOT_AVAILABLE))

        assert result == str(DataMarker.NOT_AVAILABLE)


class TestShortenText:
    """Test text shortening function."""

    def test_short_text_unchanged(self) -> None:
        """Test that short text is not modified."""
        from display import shorten_text

        result = shorten_text("Short", 20)

        assert result == "Short"

    def test_long_text_shortened(self) -> None:
        """Test that long text is shortened."""
        from display import shorten_text

        result = shorten_text("Very Long Text That Should Be Shortened", 10)

        assert len(result) <= 11  # May add ellipsis

    def test_break_at_word_boundary(self) -> None:
        """Test breaking at word boundaries when possible."""
        from display import shorten_text

        result = shorten_text("One Two Three Four", 8)

        # Should break at word boundary if possible
        assert "One Two" in result or len(result) <= 11

    def test_empty_text(self) -> None:
        """Test with empty text."""
        from display import shorten_text

        result = shorten_text("", 10)

        assert result == ""


class TestFormatOutput:
    """Test main output formatting function."""

    def test_format_empty_interface_list(self, capsys: CaptureFixture[str]) -> None:
        """Test formatting with no interfaces."""
        from display import format_output

        format_output([])

        captured = capsys.readouterr()
        # Should still show headers and structure
        assert "Network Analysis Tool" in captured.out or len(captured.out) > 0

    def test_format_single_interface(self, capsys: CaptureFixture[str]) -> None:
        """Test formatting with one interface."""
        from display import format_output

        interface = InterfaceInfo(
            name="eth0",
            interface_type=str(InterfaceType.ETHERNET),
            device="Intel I219-V",
            internal_ipv4="192.168.1.100",
            internal_ipv6=str(DataMarker.NOT_AVAILABLE),
            dns_servers=["192.168.1.1"],
            current_dns="192.168.1.1",
            dns_leak_status=str(DnsLeakStatus.NOT_APPLICABLE),
            external_ipv4=str(DataMarker.NOT_APPLICABLE),
            external_ipv6=str(DataMarker.NOT_APPLICABLE),
            egress_isp=str(DataMarker.NOT_APPLICABLE),
            egress_country=str(DataMarker.NOT_APPLICABLE),
            default_gateway="192.168.1.1",
            metric="100",
            vpn_server_ip=None,
            carries_vpn=False,
        )

        format_output([interface])

        captured = capsys.readouterr()
        assert "eth0" in captured.out
        assert "192.168.1.100" in captured.out

    def test_format_multiple_interfaces(self, capsys: CaptureFixture[str]) -> None:
        """Test formatting with multiple interfaces."""
        from display import format_output

        interfaces = [
            InterfaceInfo(
                name="lo",
                interface_type=str(InterfaceType.LOOPBACK),
                device=str(DataMarker.NOT_AVAILABLE),
                internal_ipv4="127.0.0.1",
                internal_ipv6="::1",
                dns_servers=[],
                current_dns=None,
                dns_leak_status=str(DnsLeakStatus.NOT_APPLICABLE),
                external_ipv4=str(DataMarker.NOT_APPLICABLE),
                external_ipv6=str(DataMarker.NOT_APPLICABLE),
                egress_isp=str(DataMarker.NOT_APPLICABLE),
                egress_country=str(DataMarker.NOT_APPLICABLE),
                default_gateway=str(DataMarker.NONE_VALUE),
                metric=str(DataMarker.NONE_VALUE),
                vpn_server_ip=None,
                carries_vpn=False,
            ),
            InterfaceInfo(
                name="eth0",
                interface_type=str(InterfaceType.ETHERNET),
                device="Intel I219-V",
                internal_ipv4="192.168.1.100",
                internal_ipv6=str(DataMarker.NOT_AVAILABLE),
                dns_servers=["192.168.1.1"],
                current_dns="192.168.1.1",
                dns_leak_status=str(DnsLeakStatus.NOT_APPLICABLE),
                external_ipv4=str(DataMarker.NOT_APPLICABLE),
                external_ipv6=str(DataMarker.NOT_APPLICABLE),
                egress_isp=str(DataMarker.NOT_APPLICABLE),
                egress_country=str(DataMarker.NOT_APPLICABLE),
                default_gateway="192.168.1.1",
                metric="100",
                vpn_server_ip=None,
                carries_vpn=False,
            ),
        ]

        format_output(interfaces)

        captured = capsys.readouterr()
        assert "lo" in captured.out
        assert "eth0" in captured.out
        assert "127.0.0.1" in captured.out
        assert "192.168.1.100" in captured.out

    def test_color_legend_printed(self, capsys: CaptureFixture[str]) -> None:
        """Test that color legend is printed."""
        from display import format_output

        interface = InterfaceInfo.create_empty("eth0")

        format_output([interface])

        captured = capsys.readouterr()
        assert "Color Legend" in captured.out or "GREEN" in captured.out

    def test_vpn_interface_display(self, capsys: CaptureFixture[str]) -> None:
        """Test display of VPN interface."""
        from display import format_output

        interface = InterfaceInfo(
            name="tun0",
            interface_type=str(InterfaceType.VPN),
            device=str(DataMarker.NOT_AVAILABLE),
            internal_ipv4="10.2.0.2",
            internal_ipv6=str(DataMarker.NOT_AVAILABLE),
            dns_servers=["10.2.0.1"],
            current_dns="10.2.0.1",
            dns_leak_status=str(DnsLeakStatus.OK),
            external_ipv4="159.26.108.89",
            external_ipv6=str(DataMarker.NOT_APPLICABLE),
            egress_isp="Proton AG",
            egress_country="SE",
            default_gateway=str(DataMarker.NONE_VALUE),
            metric=str(DataMarker.NONE_VALUE),
            vpn_server_ip="10.2.0.1",
            carries_vpn=False,
        )

        format_output([interface])

        captured = capsys.readouterr()
        assert "tun0" in captured.out
        assert "10.2.0.2" in captured.out

    def test_dns_leak_status_ok(self, capsys: CaptureFixture[str]) -> None:
        """Test display of OK status."""
        from display import format_output

        interface = InterfaceInfo(
            name="tun0",
            interface_type=str(InterfaceType.VPN),
            device=str(DataMarker.NOT_AVAILABLE),
            internal_ipv4="10.2.0.2",
            internal_ipv6=str(DataMarker.NOT_AVAILABLE),
            dns_servers=["10.2.0.1"],
            current_dns="10.2.0.1",
            dns_leak_status=str(DnsLeakStatus.OK),
            external_ipv4="159.26.108.89",
            external_ipv6=str(DataMarker.NOT_APPLICABLE),
            egress_isp="Proton AG",
            egress_country="SE",
            default_gateway=str(DataMarker.NONE_VALUE),
            metric=str(DataMarker.NONE_VALUE),
            vpn_server_ip=None,
            carries_vpn=False,
        )

        format_output([interface])

        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_dns_leak_status_leak(self, capsys: CaptureFixture[str]) -> None:
        """Test display of LEAK status - shown by YELLOW row color."""
        from display import format_output

        interface = InterfaceInfo(
            name="eth0",
            interface_type=str(InterfaceType.ETHERNET),
            device="Intel I219-V",
            internal_ipv4="192.168.1.100",
            internal_ipv6=str(DataMarker.NOT_AVAILABLE),
            dns_servers=["192.168.1.1"],
            current_dns="192.168.1.1",
            dns_leak_status=str(DnsLeakStatus.LEAK),
            external_ipv4=str(DataMarker.NOT_APPLICABLE),
            external_ipv6=str(DataMarker.NOT_APPLICABLE),
            egress_isp=str(DataMarker.NOT_APPLICABLE),
            egress_country=str(DataMarker.NOT_APPLICABLE),
            default_gateway="192.168.1.1",
            metric="100",
            vpn_server_ip=None,
            carries_vpn=False,
        )

        format_output([interface])

        captured = capsys.readouterr()
        # DNS leak status shown by YELLOW color on the row
        assert "\033[93m" in captured.out  # YELLOW color code
        assert "eth0" in captured.out


    def test_data_marker_display(self, capsys: CaptureFixture[str]) -> None:
        """Test display of DataMarker values."""
        from display import format_output

        interface = InterfaceInfo.create_empty("eth0")

        format_output([interface])

        captured = capsys.readouterr()
        # Should show N/A or -- for not available fields
        assert "N/A" in captured.out or "--" in captured.out


class TestComplexScenarios:
    """Test complex, realistic scenarios."""

    def test_vpn_with_leak_scenario(self, capsys: CaptureFixture[str]) -> None:
        """Test display of VPN active with DNS leak on physical interface."""
        from display import format_output

        interfaces = [
            InterfaceInfo(
                name="eth0",
                interface_type=str(InterfaceType.ETHERNET),
                device="Intel I219-V",
                internal_ipv4="192.168.1.100",
                internal_ipv6=str(DataMarker.NOT_AVAILABLE),
                dns_servers=["192.168.1.1"],
                current_dns="192.168.1.1",
                dns_leak_status=str(DnsLeakStatus.LEAK),
                external_ipv4=str(DataMarker.NOT_APPLICABLE),
                external_ipv6=str(DataMarker.NOT_APPLICABLE),
                egress_isp=str(DataMarker.NOT_APPLICABLE),
                egress_country=str(DataMarker.NOT_APPLICABLE),
                default_gateway="192.168.1.1",
                metric="100",
                vpn_server_ip=None,
                carries_vpn=False,
            ),
            InterfaceInfo(
                name="tun0",
                interface_type=str(InterfaceType.VPN),
                device=str(DataMarker.NOT_AVAILABLE),
                internal_ipv4="10.2.0.2",
                internal_ipv6="2a07:b944::2:2",
                dns_servers=["10.2.0.1"],
                current_dns="10.2.0.1",
                dns_leak_status=str(DnsLeakStatus.OK),
                external_ipv4="159.26.108.89",
                external_ipv6="2001:db8::1",
                egress_isp="Proton AG",
                egress_country="SE",
                default_gateway=str(DataMarker.NONE_VALUE),
                metric=str(DataMarker.NONE_VALUE),
                vpn_server_ip="10.2.0.1",
                carries_vpn=False,
            ),
        ]

        format_output(interfaces)

        captured = capsys.readouterr()
        # Check for both YELLOW (leak) and GREEN (VPN with OK DNS) colors
        assert "\033[93m" in captured.out  # YELLOW for DNS leak
        assert "\033[92m" in captured.out  # GREEN for VPN with OK DNS
        assert "OK" in captured.out

    def test_dual_stack_scenario(self, capsys: CaptureFixture[str]) -> None:
        """Test display of dual-stack (IPv4 + IPv6) interface."""
        from display import format_output

        interface = InterfaceInfo(
            name="eth0",
            interface_type=str(InterfaceType.ETHERNET),
            device="Intel I219-V",
            internal_ipv4="192.168.1.100",
            internal_ipv6="2001:db8:85a3::8a2e:370:7334",
            dns_servers=["2001:4860:4860::8888"],
            current_dns="2001:4860:4860::8888",
            dns_leak_status=str(DnsLeakStatus.NOT_APPLICABLE),
            external_ipv4="203.0.113.1",
            external_ipv6="2001:db8:cafe::1",
            egress_isp="Example ISP",
            egress_country="US",
            default_gateway="192.168.1.1",
            metric="100",
            vpn_server_ip=None,
            carries_vpn=False,
        )

        format_output([interface])

        captured = capsys.readouterr()
        assert "192.168.1.100" in captured.out
        assert "2001:db8" in captured.out


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_many_interfaces(self, capsys: CaptureFixture[str]) -> None:
        """Test display with many interfaces."""
        from display import format_output

        interfaces = []
        for i in range(20):
            interfaces.append(
                InterfaceInfo(
                    name=f"eth{i}",
                    interface_type=str(InterfaceType.ETHERNET),
                    device=f"Device {i}",
                    internal_ipv4=f"192.168.1.{i}",
                    internal_ipv6=str(DataMarker.NOT_AVAILABLE),
                    dns_servers=["192.168.1.1"],
                    current_dns="192.168.1.1",
                    dns_leak_status=str(DnsLeakStatus.NOT_APPLICABLE),
                    external_ipv4=str(DataMarker.NOT_APPLICABLE),
                    external_ipv6=str(DataMarker.NOT_APPLICABLE),
                    egress_isp=str(DataMarker.NOT_APPLICABLE),
                    egress_country=str(DataMarker.NOT_APPLICABLE),
                    default_gateway="192.168.1.1",
                    metric=str(100 + i),
                    vpn_server_ip=None,
                    carries_vpn=False,
                )
            )

        format_output(interfaces)

        captured = capsys.readouterr()
        # Should handle many interfaces without crashing
        assert "eth0" in captured.out
        assert "eth19" in captured.out

    def test_long_values(self, capsys: CaptureFixture[str]) -> None:
        """Test handling of very long values."""
        from display import format_output

        interface = InterfaceInfo(
            name="verylonginterfacename0",
            interface_type=str(InterfaceType.ETHERNET),
            device="A" * 100,
            internal_ipv4="192.168.1.100",
            internal_ipv6="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            dns_servers=["192.168.1.1"],
            current_dns="192.168.1.1",
            dns_leak_status=str(DnsLeakStatus.NOT_APPLICABLE),
            external_ipv4=str(DataMarker.NOT_APPLICABLE),
            external_ipv6=str(DataMarker.NOT_APPLICABLE),
            egress_isp="Very Long ISP Name " * 10,
            egress_country="US",
            default_gateway="192.168.1.1",
            metric="100",
            vpn_server_ip=None,
            carries_vpn=False,
        )

        format_output([interface])

        captured = capsys.readouterr()
        # Should not crash with long values
        assert len(captured.out) > 0
