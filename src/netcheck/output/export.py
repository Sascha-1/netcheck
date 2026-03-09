"""JSON export for netcheck.

Serialises a ``list[InterfaceInfo]`` to a JSON string that includes a
metadata block and a flat-field representation of each interface.

Nested dataclass attributes (``IPConfig``, ``DNSConfig``, etc.) are
flattened into a single dictionary per interface for easy consumption by
downstream tools.  ``None`` values are preserved as JSON ``null``.

``DataStatus`` fields (``device_status``, ``dns_query_status``,
``routing_query_status``, ``ipv4_status``, ``ipv6_status``,
``vpn_server_ip_status``) are included so that consumers can distinguish
between "not applicable", "unavailable", and "error" without inspecting
the associated value field for ``None``.

Metric is emitted as a JSON number when present, or ``null`` when the
interface has no default route.

Version
-------
The version string is imported directly from ``netcheck.config.VERSION``.
No ``importlib.metadata`` lookup is performed; the version is a compile-time
constant that does not require a dist-info directory to be present.

TypedDicts
----------
``_SummaryRecord``, ``MetadataRecord``, and ``InterfaceRecord`` are
``TypedDict`` subclasses that let mypy verify the exact keys and value
types returned by the internal builder functions.  They are not part of
the public API.

VPN active signal
-----------------
``summary.vpn_active`` is ``True`` when at least one VPN interface has a
confirmed server endpoint (``vpn.server_ip_status == DataStatus.OK``) or is the active
egress path (``egress.status == OK``).  The ``server_ip`` signal is
authoritative: it is set by the orchestrator only when a static host route
to the VPN server is present in the global routing table, which is the same
criterion used by the table renderer to color a row GREEN.  Using the
presence of an IP address on the VPN interface would be incorrect because
an interface retains its address even after the tunnel drops.
"""

import json
from datetime import datetime, timezone
from typing import Final, TypedDict

from netcheck.config import VERSION
from netcheck.core.enums import DataStatus, DnsLeakStatus, EgressStatus, InterfaceType
from netcheck.core.models import InterfaceInfo

_TOOL_NAME: Final[str] = "netcheck"


# ---------------------------------------------------------------------------
# TypedDicts for internal builder return types (PEP 589)
# ---------------------------------------------------------------------------

class _SummaryRecord(TypedDict):
    vpn_active: bool
    vpn_interface_count: int
    dns_leak_detected: bool


class MetadataRecord(TypedDict):
    """Metadata block emitted at the top of every JSON export."""

    timestamp: str
    tool: str
    version: str
    interface_count: int
    summary: _SummaryRecord


class InterfaceRecord(TypedDict):
    """Flat representation of one ``InterfaceInfo`` for JSON export."""

    # Identity
    name: str
    type: str
    # Hardware device
    device: str | None
    device_status: str
    # IP configuration
    ipv4: str | None
    ipv4_status: str
    ipv6: str | None
    ipv6_status: str
    # DNS configuration
    dns_servers: list[str] | None
    current_dns: str | None
    dns_query_status: str
    dns_leak_status: str
    # Egress information
    egress_status: str
    external_ipv4: str | None
    external_ipv6: str | None
    isp: str | None
    country: str | None
    # Routing
    routing_query_status: str
    gateway: str | None
    metric: int | None
    # VPN
    vpn_server_ip: str | None
    vpn_server_ip_status: str
    carries_vpn: bool
    # Modem (cellular interfaces only)
    modem_state: str | None
    modem_state_reason: str | None


class _JsonPayload(TypedDict):
    metadata: MetadataRecord
    interfaces: list[InterfaceRecord]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def format_json(interfaces: list[InterfaceInfo], indent: int = 2) -> str:
    """Serialise *interfaces* to a JSON string with metadata.

    The output structure is::

        {
          "metadata": { ... },
          "interfaces": [ { ... }, ... ]
        }

    Args:
        interfaces: Interface records to serialise.
        indent: JSON indentation level (default 2).

    Returns:
        Formatted JSON string.
    """
    payload: _JsonPayload = {
        "metadata": _build_metadata(interfaces),
        "interfaces": [_interface_to_dict(i) for i in interfaces],
    }
    return json.dumps(payload, indent=indent)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_metadata(interfaces: list[InterfaceInfo]) -> MetadataRecord:
    """Build the metadata block for the JSON output.

    ``vpn_active`` is ``True`` when at least one VPN interface has a confirmed
    server endpoint (``vpn.server_ip_status == DataStatus.OK``) or is the active egress
    path (``egress.status == OK``).  See module docstring for rationale.
    """
    vpn_ifaces = [i for i in interfaces if i.interface_type == InterfaceType.VPN]
    vpn_active = any(
        i.egress.status == EgressStatus.OK or i.vpn.server_ip_status == DataStatus.OK
        for i in vpn_ifaces
    )
    dns_leak = any(i.dns.leak_status == DnsLeakStatus.LEAK for i in interfaces)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": _TOOL_NAME,
        "version": VERSION,
        "interface_count": len(interfaces),
        "summary": {
            "vpn_active": vpn_active,
            "vpn_interface_count": len(vpn_ifaces),
            "dns_leak_detected": dns_leak,
        },
    }


def _interface_to_dict(iface: InterfaceInfo) -> InterfaceRecord:
    """Flatten *iface* into a JSON-serialisable ``InterfaceRecord``.

    ``device_status``, ``dns_query_status``, and ``routing_query_status``
    allow consumers to distinguish "not applicable", "unavailable", and
    "error" without checking whether the associated value is ``None``.
    """
    modem_state: str | None = None
    modem_state_reason: str | None = None
    if iface.modem is not None:
        modem_state = iface.modem.state
        modem_state_reason = iface.modem.state_reason

    return {
        "name": iface.name,
        "type": iface.interface_type.value,
        "device": iface.device.name,
        "device_status": iface.device.status.value,
        "ipv4": iface.ip.ipv4,
        "ipv4_status": iface.ip.ipv4_status.value,
        "ipv6": iface.ip.ipv6,
        "ipv6_status": iface.ip.ipv6_status.value,
        "dns_servers": (
            list(iface.dns.servers)
            if iface.dns.query_status == DataStatus.OK
            else None
        ),
        "current_dns": iface.dns.current_server,
        "dns_query_status": iface.dns.query_status.value,
        "dns_leak_status": iface.dns.leak_status.value,
        "egress_status": iface.egress.status.value,
        "external_ipv4": iface.egress.external_ip,
        "external_ipv6": iface.egress.external_ipv6,
        "isp": iface.egress.isp,
        "country": iface.egress.country,
        "routing_query_status": iface.routing.query_status.value,
        "gateway": iface.routing.gateway,
        "metric": iface.routing.metric,
        "vpn_server_ip": iface.vpn.server_ip,
        "vpn_server_ip_status": iface.vpn.server_ip_status.value,
        "carries_vpn": iface.vpn.carries_vpn,
        "modem_state": modem_state,
        "modem_state_reason": modem_state_reason,
    }
