"""Core domain models and enumerations for netcheck.

This package defines the immutable data structures and categorical types that
form the shared vocabulary of the entire application.  No other package in
netcheck should define its own data types for network interface information.

Exported names
--------------
From ``enums``:
    ``DataStatus``     -- Status of a data field (OK / NOT_APPLICABLE /
                         UNAVAILABLE / ERROR).
    ``DnsLeakStatus``  -- DNS leak analysis result.
    ``EgressStatus``   -- Outcome of the egress API query.
    ``InterfaceType``  -- Interface classification.

From ``models``:
    ``DeviceInfo``     -- Hardware device name with explicit collection status.
    ``DNSConfig``      -- DNS server list, query status, and leak status.
    ``EgressInfo``     -- Public IP, ISP, and country.
    ``IPConfig``       -- IPv4 and IPv6 addresses.
    ``InterfaceInfo``  -- Top-level interface record.
    ``ModemInfo``      -- Cellular modem state.
    ``RoutingInfo``    -- Gateway, metric, and query status.
    ``VPNInfo``        -- VPN endpoint and underlay flag.
"""

from netcheck.core.enums import DataStatus, DnsLeakStatus, EgressStatus, InterfaceType
from netcheck.core.models import (
    DNSConfig,
    DeviceInfo,
    EgressInfo,
    IPConfig,
    InterfaceInfo,
    ModemInfo,
    RoutingInfo,
    VPNInfo,
)

__all__ = [
    # enums
    "DataStatus",
    "DnsLeakStatus",
    "EgressStatus",
    "InterfaceType",
    # models
    "DeviceInfo",
    "DNSConfig",
    "EgressInfo",
    "IPConfig",
    "InterfaceInfo",
    "ModemInfo",
    "RoutingInfo",
    "VPNInfo",
]
