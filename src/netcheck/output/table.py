"""Table renderer for network interface data.

Renders ``InterfaceInfo`` records as a colour-coded fixed-width text table.

Column layout
-------------
Each column has a fixed width (including padding).  The ``_COLUMNS`` constant
defines header names and widths.  The ``_SEP`` constant defines the separator
between columns.  ``_WIDTH`` is the total line width.

Row data convention
-------------------
- ``NOT_APPLICABLE`` -> ``"N/A"`` -- field does not apply to this interface
                                     type (e.g. DEVICE for a VPN interface has
                                     no hardware).
- ``UNAVAILABLE``    -> ``"--"``  -- field applies but data is not available
                                     (e.g. no default route configured,
                                     sysfs returned no device data).
- ``ERROR``          -> ``"ERR"`` -- query was attempted and failed.
- ``OK``             -> the field's actual value; ``"--"`` when the value
                                     is absent within a successful query (e.g.
                                     a directly-connected route has no gateway).

The same convention applies to egress sub-fields and bare ``str | None``
fields (INT IPv4, INT IPv6): ``None`` renders as ``"--"`` (data absent).

DNS column convention
---------------------
The DNS column distinguishes four states for the server address:

- ``"10.8.0.1"``      -- ``current_server`` is set; interface is actively
                          resolving through this address.
- ``"(192.168.1.1)"`` -- ``current_server`` is None but ``servers`` is
                          non-empty; interface is dormant (VPN shifted the
                          active designation elsewhere).  The parentheses
                          signal "configured but not currently in use."
- ``"--"``            -- no DNS servers configured (data unavailable).
- ``"ERR"``           -- ``resolvectl`` query failed.
"""

import sys
from typing import Final, TextIO

from netcheck.core.enums import DataStatus, DnsLeakStatus, EgressStatus, InterfaceType
from netcheck.core.models import (
    DeviceInfo,
    DNSConfig,
    EgressInfo,
    InterfaceInfo,
    RoutingInfo,
)
from netcheck.output.formatters import clean_device, clean_isp, truncate

# ---------------------------------------------------------------------------
# ANSI color codes (optimised for dark terminal backgrounds)
# ---------------------------------------------------------------------------
_RESET: Final[str] = "\033[0m"
_GREEN: Final[str] = "\033[92m"
_CYAN: Final[str] = "\033[96m"
_RED: Final[str] = "\033[91m"
_YELLOW: Final[str] = "\033[93m"
_MAGENTA: Final[str] = "\033[95m"

# ---------------------------------------------------------------------------
# Table column specification: (header, width_including_padding)
# ---------------------------------------------------------------------------
_COLUMNS: Final[tuple[tuple[str, int], ...]] = (
    ("INTERFACE", 15),
    ("TYPE", 10),
    ("DEVICE", 22),
    ("INT IPv4", 16),
    ("INT IPv6", 28),
    ("DNS", 20),
    ("EXT IPv4", 16),
    ("EXT IPv6", 28),
    ("ISP", 18),
    ("COUNTRY", 8),
    ("GATEWAY", 16),
    ("METRIC", 8),
)

_SEP: Final[str] = "   "  # 3-space column separator
_WIDTH: Final[int] = sum(w for _, w in _COLUMNS) + len(_SEP) * (len(_COLUMNS) - 1)

# Interface types for which RED coloring is meaningful.
# RED means "this interface is a direct, unencrypted internet path".
# Applying RED to a VPN, bridge, or virtual interface would be misleading:
# a VPN interface being the active egress means the VPN is working, not that
# traffic is unprotected.
#
# UNKNOWN is included because an unclassified interface is most likely
# unidentified physical hardware.  If it carries active egress traffic the
# conservative assumption is that the connection is unprotected; showing RED
# is preferable to silently omitting the warning.
_PHYSICAL_TYPES: Final[frozenset[InterfaceType]] = frozenset({
    InterfaceType.ETHERNET,
    InterfaceType.WIRELESS,
    InterfaceType.CELLULAR,
    InterfaceType.TETHER,
    InterfaceType.UNKNOWN,
})

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_table(interfaces: list[InterfaceInfo]) -> str:
    """Return the complete color-coded table as a single string.

    Pure function: no I/O, no side-effects.  The returned string ends with a
    trailing newline so that callers using ``out.write(render_table(interfaces))``
    receive a complete, self-contained block of text without needing to add one.

    Args:
        interfaces: Interface records to render.

    Returns:
        Complete table string including header, data rows, dividers, and legend.
    """
    divider = "=" * _WIDTH
    lines: list[str] = []
    lines.append(divider)
    lines.append("Network Interface Analysis")
    lines.append(divider)

    header_parts = [name.ljust(width) for name, width in _COLUMNS]
    lines.append(_SEP.join(header_parts))
    lines.append(divider)

    for iface in interfaces:
        row = _build_row(iface)
        color = _row_color(iface)
        lines.append(f"{color}{row}{_RESET}" if color else row)

    lines.append(divider)
    lines.extend(_legend_lines())

    return "\n".join(lines) + "\n"


def format_table(
    interfaces: list[InterfaceInfo],
    file: TextIO | None = None,
) -> None:
    """Write the color-coded interface table to *file* (default: stdout).

    Thin wrapper around ``render_table``: renders to a string then writes it.
    Prefer ``render_table`` when the string is needed without I/O.

    Args:
        interfaces: Interface records to render.
        file: Destination file handle.  Defaults to ``sys.stdout``.
    """
    out = file if file is not None else sys.stdout
    out.write(render_table(interfaces))


def _build_row(iface: InterfaceInfo) -> str:
    """Format one interface as a padded, separator-joined row string."""
    cells = [
        iface.name,
        iface.interface_type.value,
        _render_device(iface.device),
        _render_ipv4(iface),
        _render_ipv6(iface),
        _render_dns_server(iface.dns),
        _egress_ipv4(iface.egress),
        _egress_ipv6(iface.egress),
        _egress_isp(iface.egress),
        _egress_country(iface.egress),
        _render_gateway(iface.routing),
        _render_metric(iface.routing),
    ]
    parts = []
    for (_, width), value in zip(_COLUMNS, cells):
        parts.append(truncate(str(value), width).ljust(width))
    return _SEP.join(parts)


def _row_color(iface: InterfaceInfo) -> str:
    """Return the ANSI color code for *iface*, or empty string for no color."""
    leak = iface.dns.leak_status
    itype = iface.interface_type
    egress_ok = iface.egress.status == EgressStatus.OK

    if leak == DnsLeakStatus.LEAK:
        return _MAGENTA
    if leak in (DnsLeakStatus.WARN, DnsLeakStatus.PUBLIC):
        return _YELLOW
    if itype == InterfaceType.VPN and iface.vpn.server_ip_status == DataStatus.OK:
        # Color GREEN only when this VPN interface is the active encrypted
        # tunnel -- confirmed by the VPN provider's DNS being active on it.
        #
        # ``dns_leak_status == OK`` is the only reliable signal: it means
        # systemd-resolved is routing queries through this interface's VPN
        # DNS server, which confirms both the tunnel and DNS isolation are
        # working.
        #
        # The egress-OK fallback (for DNS managed outside systemd-resolved)
        # is intentionally absent.  Any VPN interface without an active
        # ``current_server`` -- whether a kill-switch or one using an
        # external resolver -- receives ``dns_leak_status=NOT_APPLICABLE``
        # from the ``_DNS_PROVIDER_TYPES`` guard in ``check_dns_leaks``.
        # These two scenarios are indistinguishable at the ``leak_status``
        # level, so the conservative choice is to require DNS OK for GREEN.
        if leak == DnsLeakStatus.OK:
            return _GREEN
    if iface.vpn.carries_vpn:
        return _CYAN
    if egress_ok and itype in _PHYSICAL_TYPES:
        # RED signals an unprotected internet-facing physical interface.
        return _RED
    return ""


def _render_device(device: DeviceInfo) -> str:
    """Render a ``DeviceInfo`` to a display string."""
    if device.status == DataStatus.NOT_APPLICABLE:
        return "N/A"
    if device.status == DataStatus.ERROR:
        return "ERR"
    if device.status == DataStatus.UNAVAILABLE:
        return "--"
    # OK: name is guaranteed non-None by DeviceInfo.__post_init__
    return clean_device(device.name)


def _render_ipv4(iface: InterfaceInfo) -> str:
    """Render the internal IPv4 address from ``iface.ip``.

    Follows the ``DataStatus`` convention:
    ``NOT_APPLICABLE`` is excluded from ``IPConfig`` by design, so only
    ``OK``, ``UNAVAILABLE``, and ``ERROR`` are handled.
    """
    if iface.ip.ipv4_status == DataStatus.ERROR:
        return "ERR"
    if iface.ip.ipv4_status == DataStatus.UNAVAILABLE:
        return "--"
    # OK: ipv4 is guaranteed non-None by IPConfig.__post_init__
    return iface.ip.ipv4  # type: ignore[return-value]


def _render_ipv6(iface: InterfaceInfo) -> str:
    """Render the internal IPv6 address from ``iface.ip``.

    Follows the ``DataStatus`` convention:
    ``NOT_APPLICABLE`` is excluded from ``IPConfig`` by design, so only
    ``OK``, ``UNAVAILABLE``, and ``ERROR`` are handled.
    """
    if iface.ip.ipv6_status == DataStatus.ERROR:
        return "ERR"
    if iface.ip.ipv6_status == DataStatus.UNAVAILABLE:
        return "--"
    # OK: ipv6 is guaranteed non-None by IPConfig.__post_init__
    return iface.ip.ipv6  # type: ignore[return-value]


def _render_dns_server(dns: DNSConfig) -> str:
    """Render the active or dormant DNS server address for *dns*.

    Returns the ``current_server`` directly when the interface is actively
    resolving.  When the interface is dormant (VPN shifted the active
    designation elsewhere), the first configured server is shown in
    parentheses to indicate "configured but not currently in use."
    """
    if dns.query_status == DataStatus.ERROR:
        return "ERR"
    if dns.current_server is not None:
        return dns.current_server
    if dns.servers:
        return f"({dns.servers[0]})"
    return "--"


def _render_gateway(routing: RoutingInfo) -> str:
    """Render the default gateway address from *routing*."""
    if routing.query_status == DataStatus.NOT_APPLICABLE:
        return "N/A"
    if routing.query_status == DataStatus.ERROR:
        return "ERR"
    if routing.query_status == DataStatus.UNAVAILABLE:
        return "--"
    return routing.gateway if routing.gateway is not None else "--"


def _render_metric(routing: RoutingInfo) -> str:
    """Render the route metric from *routing*.

    When ``query_status`` is ``OK`` and ``metric`` is ``None``, the kernel
    implicitly used metric 0 (the ``metric`` keyword was absent from the route
    entry).  Display ``"0"`` rather than ``"--"`` to distinguish this from a
    genuinely unavailable metric.
    """
    if routing.query_status == DataStatus.NOT_APPLICABLE:
        return "N/A"
    if routing.query_status == DataStatus.ERROR:
        return "ERR"
    if routing.query_status == DataStatus.UNAVAILABLE:
        return "--"
    return str(routing.metric) if routing.metric is not None else "0"


def _egress_ipv4(egress: EgressInfo) -> str:
    """Render the external IPv4 address from *egress*."""
    if egress.status == EgressStatus.FAILED:
        return "ERR"
    if egress.status == EgressStatus.UNAVAILABLE:
        return "--"
    return egress.external_ip if egress.external_ip is not None else "--"


def _egress_ipv6(egress: EgressInfo) -> str:
    """Render the external IPv6 address from *egress*."""
    if egress.status == EgressStatus.FAILED:
        return "ERR"
    if egress.status == EgressStatus.UNAVAILABLE:
        return "--"
    return egress.external_ipv6 if egress.external_ipv6 is not None else "--"


def _egress_isp(egress: EgressInfo) -> str:
    """Render the ISP string from *egress*, with AS number stripped."""
    if egress.status == EgressStatus.FAILED:
        return "ERR"
    if egress.status == EgressStatus.UNAVAILABLE:
        return "--"
    return clean_isp(egress.isp)


def _egress_country(egress: EgressInfo) -> str:
    """Render the country code from *egress*."""
    if egress.status == EgressStatus.FAILED:
        return "ERR"
    if egress.status == EgressStatus.UNAVAILABLE:
        return "--"
    return egress.country if egress.country is not None else "--"


def _legend_lines() -> list[str]:
    """Return the legend block as a list of strings for ``render_table``.

    Used by ``render_table`` to build the complete table string.  The first
    element is an empty string so that the legend is visually separated from
    the closing divider by a blank line when joined with ``"\\n"``.
    """
    return [
        "",
        "Legend:",
        f"  {_GREEN}GREEN  {_RESET}  (dns:ok)              VPN tunnel -- DNS via VPN provider",
        f"  {_CYAN}CYAN   {_RESET}                        Physical interface carrying VPN traffic",
        f"  {_RED}RED    {_RESET}                        Direct internet -- no VPN active",
        f"  {_MAGENTA}MAGENTA{_RESET}  (dns:leak)            DNS leak -- ISP sees your queries",
        f"  {_YELLOW}YELLOW {_RESET}  (dns:public)          Public resolver -- no ISP leak",
        f"  {_YELLOW}YELLOW {_RESET}  (dns:warn)            Unrecognised resolver -- investigate",
        "           (dns:dormant)          VPN active; interface stepped aside, not routing DNS",
        "           (dns:not_applicable)   Interface type does not participate in DNS routing",
        "",
        "Missing data:",
        "  N/A  Field does not apply to this interface type by design",
        "  --   Field applies but data is currently unavailable",
        "  ERR  Query was attempted and failed",
        "  (..) DNS configured but dormant -- not currently routing queries",
        "",
    ]
