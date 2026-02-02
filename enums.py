"""
Enumeration types for netcheck.

Provides type-safe constants for interface types, DNS leak status, and data markers.
"""

from enum import Enum


class InterfaceType(str, Enum):
    """Network interface type classifications."""
    
    LOOPBACK = "loopback"
    ETHERNET = "ethernet"
    WIRELESS = "wireless"
    VPN = "vpn"
    TETHER = "tether"
    VIRTUAL = "virtual"
    BRIDGE = "bridge"
    UNKNOWN = "unknown"
    
    def __str__(self) -> str:
        """Return the value for string operations."""
        return self.value


class DnsLeakStatus(str, Enum):
    """
    DNS leak detection status values.
    
    Indicates whether DNS queries are leaking to ISP servers when VPN is active.
    """
    
    OK = "OK"
    LEAK = "LEAK"
    WARN = "WARN"
    NOT_APPLICABLE = "--"
    
    def __str__(self) -> str:
        """Return the value for string operations."""
        return self.value


class DataMarker(str, Enum):
    """
    Special markers for data states.
    
    Used consistently throughout the application to indicate various
    states of unavailable or inapplicable data.
    """
    
    NOT_APPLICABLE = "--"
    NOT_AVAILABLE = "N/A"
    NONE_VALUE = "NONE"
    DEFAULT = "DEFAULT"
    ERROR = "ERR"
    
    def __str__(self) -> str:
        """Return the value for string operations."""
        return self.value
