"""
Tests for enumeration types.

Verifies that enums provide correct values and string conversions.
"""

import pytest
from enums import InterfaceType, DnsLeakStatus, DataMarker


class TestInterfaceType:
    """Test InterfaceType enum."""
    
    def test_values(self):
        """Test that enum values are correct."""
        assert InterfaceType.LOOPBACK.value == "loopback"
        assert InterfaceType.ETHERNET.value == "ethernet"
        assert InterfaceType.WIRELESS.value == "wireless"
        assert InterfaceType.VPN.value == "vpn"
    
    def test_string_conversion(self):
        """Test that enum converts to string correctly."""
        assert str(InterfaceType.ETHERNET) == "ethernet"
        assert str(InterfaceType.VPN) == "vpn"
    
    def test_all_types_present(self):
        """Test that all expected types are defined."""
        expected = {
            "loopback", "ethernet", "wireless", "vpn",
            "tether", "virtual", "bridge", "unknown"
        }
        actual = {t.value for t in InterfaceType}
        assert actual == expected


class TestDnsLeakStatus:
    """Test DnsLeakStatus enum."""
    
    def test_values(self):
        """Test that status values are correct."""
        assert DnsLeakStatus.OK.value == "OK"
        assert DnsLeakStatus.LEAK.value == "LEAK"
        assert DnsLeakStatus.WARN.value == "WARN"
        assert DnsLeakStatus.NOT_APPLICABLE.value == "--"
    
    def test_string_conversion(self):
        """Test string conversion."""
        assert str(DnsLeakStatus.OK) == "OK"
        assert str(DnsLeakStatus.LEAK) == "LEAK"


class TestDataMarker:
    """Test DataMarker enum."""
    
    def test_values(self):
        """Test marker values."""
        assert DataMarker.NOT_APPLICABLE.value == "--"
        assert DataMarker.NOT_AVAILABLE.value == "N/A"
        assert DataMarker.NONE_VALUE.value == "NONE"
        assert DataMarker.DEFAULT.value == "DEFAULT"
        assert DataMarker.ERROR.value == "ERR"
    
    def test_string_conversion(self):
        """Test string conversion."""
        assert str(DataMarker.NOT_AVAILABLE) == "N/A"
        assert str(DataMarker.ERROR) == "ERR"
