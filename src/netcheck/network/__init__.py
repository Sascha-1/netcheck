"""Network data collection for netcheck.

Provides interface discovery, IP addressing, routing, DNS, egress, and VPN
analysis.  All functions accept injectable protocol instances (``CommandRunner``,
``SysfsReader``, ``HttpClient``) so the network layer is fully testable without
spawning subprocesses or making network requests.

Exported names
--------------
From ``interfaces``:
    ``get_interface_list``    -- All interface names from ``ip -o link show``.
    ``detect_interface_type`` -- Classify one interface into ``InterfaceType``.
    ``get_device_name``       -- Hardware description string or ``None``.

From ``addressing``:
    ``get_all_ipv4_addresses`` -- Batch IPv4 address query (all interfaces).
    ``get_all_ipv6_addresses`` -- Batch IPv6 address query (global scope only).

From ``routing``:
    ``get_metric_sort_key``   -- Pure sort key for route metric values.
    ``get_route_info``        -- Default gateway and metric for one interface.
    ``get_active_interface``  -- Interface with the lowest-metric default route.

From ``dns``:
    ``get_interface_dns``     -- DNS configuration for one interface.
    ``check_dns_leaks``       -- Return updated interface list with leak status.

From ``egress``:
    ``get_egress_info``       -- Public IP, ISP, and country from ipinfo.io.

From ``vpn``:
    ``get_vpn_server_endpoint`` -- VPN server IP from static host routes in the
                                   kernel routing table.
    ``find_vpn_carrier``        -- Physical interface carrying VPN tunnel traffic.
"""

from netcheck.network.addressing import get_all_ipv4_addresses, get_all_ipv6_addresses
from netcheck.network.dns import check_dns_leaks, get_interface_dns
from netcheck.network.egress import get_egress_info
from netcheck.network.interfaces import detect_interface_type, get_device_name, get_interface_list
from netcheck.network.routing import get_active_interface, get_metric_sort_key, get_route_info
from netcheck.network.vpn import find_vpn_carrier, get_vpn_server_endpoint

__all__ = [
    # Interfaces
    "get_interface_list",
    "detect_interface_type",
    "get_device_name",
    # Addressing
    "get_all_ipv4_addresses",
    "get_all_ipv6_addresses",
    # Routing
    "get_metric_sort_key",
    "get_route_info",
    "get_active_interface",
    # DNS
    "get_interface_dns",
    "check_dns_leaks",
    # Egress
    "get_egress_info",
    # VPN
    "get_vpn_server_endpoint",
    "find_vpn_carrier",
]
