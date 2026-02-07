"""
Tests for data models.

Verifies InterfaceInfo and EgressInfo data structures work correctly.
"""

import pytest
from models import InterfaceInfo, EgressInfo
from enums import DataMarker, DnsLeakStatus


class TestInterfaceInfo:
    """Test InterfaceInfo model."""

    def test_create_empty(self) -> None:
        """Test creating empty interface info with default values."""
        info = InterfaceInfo.create_empty("eth0")

        assert info.name == "eth0"
        assert info.interface_type == str(DataMarker.NOT_AVAILABLE)
        assert info.device == str(DataMarker.NOT_AVAILABLE)
        assert info.internal_ipv4 == str(DataMarker.NOT_AVAILABLE)
        assert info.dns_servers == []
        assert info.current_dns is None
        assert info.dns_leak_status == str(DnsLeakStatus.NOT_APPLICABLE)

    def test_with_all_fields(self, sample_interface_info: InterfaceInfo) -> None:
        """Test interface info with all fields populated."""
        info = sample_interface_info

        assert info.name == "eth0"
        assert info.interface_type == "ethernet"
        assert info.device == "Intel Corporation I219-V"
        assert info.internal_ipv4 == "192.168.1.100"
        assert info.internal_ipv6 == "2001:db8::1"
        assert len(info.dns_servers) == 2
        assert info.current_dns == "8.8.8.8"
        assert info.external_ipv4 == "1.2.3.4"

    def test_dataclass_immutability(self) -> None:
        """Test that we can modify InterfaceInfo fields."""
        info = InterfaceInfo.create_empty("eth0")

        # Should be able to modify fields
        info.internal_ipv4 = "192.168.1.1"
        assert info.internal_ipv4 == "192.168.1.1"


class TestEgressInfo:
    """Test EgressInfo model."""

    def test_create_normal(self) -> None:
        """Test creating normal egress info."""
        info = EgressInfo(
            external_ip="1.2.3.4",
            external_ipv6="2001:db8::1",
            isp="Example ISP",
            country="US"
        )

        assert info.external_ip == "1.2.3.4"
        assert info.external_ipv6 == "2001:db8::1"
        assert info.isp == "Example ISP"
        assert info.country == "US"

    def test_create_error(self) -> None:
        """Test creating error egress info."""
        info = EgressInfo.create_error()

        assert info.external_ip == str(DataMarker.ERROR)
        assert info.external_ipv6 == str(DataMarker.ERROR)
        assert info.isp == str(DataMarker.ERROR)
        assert info.country == str(DataMarker.ERROR)
