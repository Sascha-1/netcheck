"""VPN tunnel analysis for netcheck.

Provides:
- ``get_vpn_server_endpoint`` -- find the VPN server IP from static host routes.
- ``find_vpn_carrier``        -- identify which physical interface carries VPN traffic.

``get_vpn_server_endpoint`` performs I/O (reads the routing table via
``ip route show``).  ``find_vpn_carrier`` is pure computation -- it needs
only the collected interface list.  The two functions are separated because
pure functions are simpler to test and reason about.

VPN server detection
--------------------
Parses ``ip route show`` looking for static host routes to public IP
addresses.  VPN clients (WireGuard, OpenVPN) must inject a bypass host
route for the VPN server so that server-bound traffic does not recurse
through the tunnel itself.  These routes have the following
characteristics:

- Destination is a single host (no prefix length, or explicit ``/32``).
- ``proto static`` -- added by the VPN client, not by DHCP or the kernel.
- Destination is a public (non-private, non-CGNAT) IP address.

This approach is protocol-agnostic and unprivileged.  WireGuard runs as a
kernel module and is invisible to socket inspection via ``ss``.  Its
userspace tool ``wg show`` requires root and does not cross network
namespace boundaries (ProtonVPN isolates ``proton0`` in a separate
namespace).  The bypass host route is always present in the global routing
table and is readable without elevated privileges.

Known limitation -- multiple simultaneous VPNs
---------------------------------------------
Bypass routes are injected on the physical carrier interface, not on the
VPN tunnel interface.  ``ip route show`` returns a global view; no
unprivileged kernel API links a specific route to the tunnel that caused
it.  When two independent VPN tunnels with *different* servers are active
simultaneously, both receive the server IP whose route appears first in the
table.  Per-interface attribution would require root (``wg show``, network
namespace entry) or a VPN-client-specific sidecar -- neither is compatible
with the no-root guarantee.

Single-VPN configurations are handled correctly, including multi-interface
architectures such as ProtonVPN's kill-switch pair (``pvpnksintrf0`` and
``proton0``), where both interfaces legitimately share one server and
receiving the same IP is the accurate result.

Known limitation -- network namespace isolation
-----------------------------------------------
Some VPN clients isolate their tunnel interface in a dedicated network
namespace at the OS level.  ProtonVPN is a documented example: ``proton0``
lives in a private namespace while ``pvpnksintrf0`` (the kill-switch) lives
in the global namespace alongside all other interfaces.

Direct inspection of the tunnel is not possible without root in this
configuration.  ``wg show`` requires elevated privileges and, critically,
cannot cross namespace boundaries even when run as root in the global
namespace.  ``ip -d link show`` can identify that an interface is of type
wireguard, but only if the interface is visible in the current namespace.

netcheck is deliberately immune to namespace isolation for VPN *detection*:
the bypass host route for the VPN server is always injected in the global
routing table (the VPN client must do this so that server-bound packets are
not re-routed through the tunnel itself).  ``ip route show``, which reads
the global table without elevated privileges, is sufficient to find the
server endpoint regardless of which namespace the tunnel interface occupies.

The limitation that remains is that netcheck cannot verify the tunnel's
internal WireGuard state (peer handshakes, bytes transferred, allowed IPs)
without entering the namespace.  This is acceptable for the tool's purpose:
the combination of a confirmed bypass host route, active DNS on the tunnel
interface, and correct egress IP is a reliable proxy for a live tunnel.

VPN carrier detection
---------------------
The carrier is the physical interface (ethernet, wireless, cellular, or
tether) with the lowest route metric that has a default gateway configured.
The lowest metric matches the kernel's own preference for outbound traffic.
"""

import ipaddress
import logging
import re

# Explicit private IPv4 ranges for VPN endpoint filtering.
#
# We do NOT use ``ipaddress.IPv4Address.is_private`` because it does not
# cover the CGNAT range (100.64.0.0/10, RFC 6598).  CGNAT addresses are
# assigned by carrier-grade NAT devices between the ISP and the subscriber
# and are not publicly reachable, so they must never be returned as a VPN
# server endpoint.  The standard library only added CGNAT to ``is_private``
# in Python 3.11, but even then only via ``is_global`` (the complement);
# relying on that would tie correctness to a specific Python version.
# Defining the ranges explicitly makes the policy unambiguous regardless of
# Python version.
#
# IPv4Network/IPv6Network constructors are used instead of ip_network() to
# give mypy the precise return type without a cast.
_PRIVATE_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)
_CGNAT_V4: ipaddress.IPv4Network = ipaddress.IPv4Network("100.64.0.0/10")
_PRIVATE_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
)

# Matches a bare IPv4 host route destination (no prefix, or explicit /32).
_HOST_ROUTE_RE: re.Pattern[str] = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})(?:/32)?$"
)

from netcheck.core.enums import DataStatus, InterfaceType
from netcheck.core.models import InterfaceInfo
from netcheck.network.routing import get_metric_sort_key
from netcheck.utils.command import CommandRunner

logger = logging.getLogger(__name__)


def get_vpn_server_endpoint(
    runner: CommandRunner,
) -> tuple[str | None, DataStatus]:
    """Return the VPN server IP and query status from static host routes.

    Runs ``ip route show`` and looks for host routes (single-IP destinations,
    no prefix length or explicit ``/32``) with ``proto static`` to public IP
    addresses.  VPN clients inject these routes to ensure server-bound traffic
    bypasses the tunnel -- they are the authoritative, protocol-agnostic signal
    for the VPN server endpoint.

    Works for WireGuard (kernel module, invisible to socket inspection) and
    OpenVPN alike.  When multiple redundant routes to the same server exist
    (e.g. one per physical interface), only the first match (lowest metric)
    is returned.

    Args:
        runner: Command runner.

    Returns:
        A ``(server_ip, status)`` tuple where:

        - ``status`` is ``DataStatus.ERROR`` if ``ip route show`` produced
          no output (runner returned ``None``).
        - ``status`` is ``DataStatus.UNAVAILABLE`` if the command ran but
          no qualifying static host route to a public address was found.
        - ``status`` is ``DataStatus.OK`` and ``server_ip`` is the VPN
          server IP string when a qualifying route is found.
    """
    output = runner.run(["ip", "route", "show"])
    if output is None:
        return None, DataStatus.ERROR

    for line in output.splitlines():
        parts = line.split()
        if not parts or parts[0] == "default":
            continue

        match = _HOST_ROUTE_RE.match(parts[0])
        if not match:
            continue

        if "proto" not in parts:
            continue
        proto_idx = parts.index("proto")
        if proto_idx + 1 >= len(parts) or parts[proto_idx + 1] != "static":
            continue

        destination = match.group(1)
        if is_private_or_cgnat(destination):
            continue

        logger.debug("Found static host route to VPN server: %s", destination)
        return destination, DataStatus.OK

    return None, DataStatus.UNAVAILABLE


def find_vpn_carrier(
    interfaces: list[InterfaceInfo],
) -> str | None:
    """Return the name of the physical interface that carries VPN traffic.

    Selects the physical interface (ethernet, wireless, cellular, or tether)
    with the lowest route metric among those that have a default gateway.
    This matches the kernel's routing decision for outbound packets.

    Args:
        interfaces: All collected interfaces.

    Returns:
        Interface name string, or ``None`` if no suitable carrier is found.
    """
    candidates: list[tuple[str, int | None]] = []

    for iface in interfaces:
        if iface.interface_type not in (
            InterfaceType.ETHERNET,
            InterfaceType.WIRELESS,
            InterfaceType.CELLULAR,
            InterfaceType.TETHER,
        ):
            continue
        if iface.routing.gateway is None:
            continue
        candidates.append((iface.name, iface.routing.metric))

    if not candidates:
        return None

    candidates.sort(key=lambda c: get_metric_sort_key(c[1]))
    return candidates[0][0]


def is_private_or_cgnat(ip_str: str) -> bool:
    """Return ``True`` if ``ip_str`` is in a private or CGNAT range.

    Uses explicit network definitions rather than ``ipaddress.is_private``
    because the standard library does not consistently cover the CGNAT range
    (100.64.0.0/10, RFC 6598) across Python versions.  CGNAT addresses are
    assigned by carrier-grade NAT and are not publicly reachable VPN endpoints.

    Excluded ranges (IPv4):
        - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16  (RFC 1918)
        - 127.0.0.0/8                                  (loopback)
        - 169.254.0.0/16                               (link-local)
        - 100.64.0.0/10                                (CGNAT, RFC 6598)

    Excluded ranges (IPv6):
        - ::1/128   (loopback)
        - fc00::/7  (ULA)
        - fe80::/10 (link-local)

    Args:
        ip_str: IP address string to check.

    Returns:
        ``True`` if in a private or CGNAT range, or if ``ip_str`` cannot
        be parsed (conservative fail-safe).  ``False`` for public addresses.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if isinstance(addr, ipaddress.IPv4Address):
        return addr in _CGNAT_V4 or any(addr in net for net in _PRIVATE_V4)
    return any(addr in net for net in _PRIVATE_V6)
