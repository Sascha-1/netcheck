"""DNS configuration and leak detection for netcheck.

Provides:
- ``get_interface_dns`` -- parse DNS configuration for one interface.
- ``check_dns_leaks``   -- compute leak status for all interfaces.

Key distinction: configured vs. active
---------------------------------------
``DNSConfig`` holds two related but distinct pieces of information:

- ``servers``        -- every DNS server address that systemd-resolved has
                        *configured* for this interface (from the
                        "DNS Servers:" line in ``resolvectl status``).
- ``current_server`` -- the single server that systemd-resolved is
                        *actively using right now* (from the
                        "Current DNS Server:" line).

When a VPN is active, systemd-resolved shifts the ``current_server``
designation to the VPN interface.  Physical interfaces that were previously
resolving via their DHCP-assigned servers become dormant: ``current_server``
becomes ``None`` even though ``servers`` is still populated.  A dormant
interface is not resolving any queries and therefore cannot be leaking DNS.

Leak detection algorithm
------------------------
``check_dns_leaks`` takes the full interface list because accurate
classification requires a system-wide view.

**Reference-set collection** (unchanged by VPN state):
    - ``vpn_dns``  -- all addresses from ``servers`` of VPN interfaces.
    - ``isp_dns``  -- all addresses from ``servers`` of physical interfaces
                      (ethernet, wireless, cellular, tether).
    These sets represent *known* VPN and ISP DNS addresses respectively,
    regardless of whether those interfaces are currently active.

**Per-interface classification** (uses ``current_server`` only):
    1. If no VPN is active (``vpn_dns`` is empty): ``NOT_APPLICABLE``.
    2. If ``current_server`` is ``None``: ``DORMANT`` -- the VPN is active
       and this interface has correctly stepped aside; systemd-resolved is
       not routing queries through it.  This is a positive security signal:
       it confirms the VPN's DNS isolation is working.
    3. If ``current_server`` is in ``isp_dns``: ``LEAK`` -- active queries
       go to the ISP resolver while a VPN is running.
    4. If ``current_server`` is in ``vpn_dns``: ``OK`` -- queries go through
       the VPN provider's resolver.
    5. If ``current_server`` is in ``PUBLIC_DNS_SERVERS``: ``PUBLIC`` --
       using a public resolver (Cloudflare/Google/Quad9); not an ISP leak
       but not optimal.
    6. Otherwise: ``WARN`` -- unknown resolver; investigate.

``query_status`` semantics
--------------------------
- ``DataStatus.ERROR``       -- ``resolvectl status <iface>`` produced no
                               output or exited with a non-zero code.
- ``DataStatus.UNAVAILABLE`` -- command succeeded but reported no DNS servers
                               for this interface.
- ``DataStatus.OK``          -- at least one DNS server was found.

Immutability
------------
``InterfaceInfo`` uses ``frozen=True``.  ``check_dns_leaks`` returns a
**new list** of ``InterfaceInfo`` objects with updated ``dns.leak_status``
fields.  The original list is not modified.  ``dataclasses.replace()`` is
used throughout.
"""

import dataclasses
import logging
import re

from netcheck.config import PUBLIC_DNS_SERVERS
from netcheck.core.enums import DataStatus, DnsLeakStatus, InterfaceType
from netcheck.core.models import DNSConfig, InterfaceInfo
from netcheck.utils.command import CommandRunner

logger = logging.getLogger(__name__)

# Interface types that participate as DNS providers and can be DORMANT.
# Only these types receive their DNS servers from DHCP or static
# configuration and hand off to the VPN interface when a tunnel is active.
# All other types (loopback, VPN, bridge, virtual, unknown) receive
# NOT_APPLICABLE unconditionally -- they never act as DNS providers and
# cannot meaningfully step aside for a VPN.
_DNS_PROVIDER_TYPES: frozenset[InterfaceType] = frozenset({
    InterfaceType.ETHERNET,
    InterfaceType.WIRELESS,
    InterfaceType.CELLULAR,
    InterfaceType.TETHER,
})


def get_interface_dns(iface_name: str, runner: CommandRunner) -> DNSConfig:
    """Return the DNS configuration for ``iface_name``.

    Runs ``resolvectl status <iface>`` and parses the ``DNS Servers`` and
    ``Current DNS Server`` fields.  Sets ``leak_status`` to
    ``NOT_APPLICABLE`` as a placeholder; the real value is computed by
    ``check_dns_leaks`` once all interfaces are collected.

    ``query_status`` reflects the outcome of the command:

    - ``DataStatus.ERROR``       -- command produced no output.
    - ``DataStatus.UNAVAILABLE`` -- command succeeded; no DNS servers found.
    - ``DataStatus.OK``          -- at least one DNS server found.

    Args:
        iface_name: Interface name.
        runner: Command runner.

    Returns:
        ``DNSConfig`` with servers, current_server, query_status, and a
        placeholder ``leak_status`` of ``NOT_APPLICABLE``.
    """
    output = runner.run(["resolvectl", "status", iface_name])
    if not output:
        logger.debug("%s: resolvectl returned no output (status=ERROR)", iface_name)
        return DNSConfig(
            query_status=DataStatus.ERROR,
            servers=(),
            current_server=None,
            leak_status=DnsLeakStatus.NOT_APPLICABLE,
        )

    lines = output.splitlines()
    servers = tuple(_parse_dns_servers(lines))
    current = _parse_current_dns(lines)
    query_status = DataStatus.OK if servers else DataStatus.UNAVAILABLE

    logger.debug(
        "%s: servers=%s current_server=%s status=%s",
        iface_name, servers, current, query_status.value,
    )

    return DNSConfig(
        query_status=query_status,
        servers=servers,
        current_server=current,
        leak_status=DnsLeakStatus.NOT_APPLICABLE,
    )


def check_dns_leaks(interfaces: list[InterfaceInfo]) -> list[InterfaceInfo]:
    """Return a new list of interfaces with ``dns.leak_status`` populated.

    Takes a system-wide view to classify DNS servers, then assigns each
    interface a ``DnsLeakStatus`` using the algorithm documented in the
    module docstring.

    ``InterfaceInfo`` objects are frozen; this function uses
    ``dataclasses.replace()`` to construct updated copies.  The input list
    is not modified.

    Args:
        interfaces: All collected interfaces.

    Returns:
        New list of ``InterfaceInfo`` objects with ``dns.leak_status`` set.
    """
    vpn_dns, isp_dns = _collect_dns_by_category(interfaces)
    return [_with_leak_status(iface, vpn_dns, isp_dns) for iface in interfaces]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------
def _parse_dns_servers(lines: list[str]) -> list[str]:
    """Extract all DNS server addresses from resolvectl output lines.

    Args:
        lines: Lines from ``resolvectl status <iface>``.

    Returns:
        List of DNS server IP address strings.
    """
    servers: list[str] = []
    in_section = False

    for line in lines:
        if "DNS Servers:" in line:
            in_section = True
            _, _, rest = line.partition(":")
            servers.extend(_extract_ips(rest))
        elif in_section:
            if line.startswith(" "):
                servers.extend(_extract_ips(line))
            else:
                break

    return servers


def _parse_current_dns(lines: list[str]) -> str | None:
    """Extract the current DNS server address from resolvectl output lines.

    Args:
        lines: Lines from ``resolvectl status <iface>``.

    Returns:
        Current DNS server IP string or ``None``.
    """
    for line in lines:
        if "Current DNS Server:" in line:
            _, _, rest = line.partition(":")
            ips = _extract_ips(rest)
            if ips:
                return ips[0]
    return None


def _extract_ips(text: str) -> list[str]:
    """Extract IPv4 and IPv6 address strings from ``text``.

    Args:
        text: Arbitrary text that may contain IP addresses.

    Returns:
        List of IP address strings found in ``text``.
    """
    ipv4 = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    ipv6 = re.findall(
        r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b",
        text,
        re.IGNORECASE,
    )
    return ipv4 + ipv6


def _collect_dns_by_category(
    interfaces: list[InterfaceInfo],
) -> tuple[frozenset[str], frozenset[str]]:
    """Categorise DNS servers across all interfaces as VPN or ISP.

    Args:
        interfaces: All collected interfaces.

    Returns:
        ``(vpn_dns, isp_dns)`` as frozensets of IP address strings.
    """
    vpn_dns: set[str] = set()
    isp_dns: set[str] = set()

    for iface in interfaces:
        if iface.interface_type == InterfaceType.VPN:
            vpn_dns.update(iface.dns.servers)
        elif iface.interface_type in (
            InterfaceType.ETHERNET,
            InterfaceType.WIRELESS,
            InterfaceType.CELLULAR,
            InterfaceType.TETHER,
        ):
            isp_dns.update(iface.dns.servers)

    return (frozenset(vpn_dns), frozenset(isp_dns))


def _compute_leak_status(
    dns_config: DNSConfig,
    vpn_dns: frozenset[str],
    isp_dns: frozenset[str],
) -> DnsLeakStatus:
    """Compute the leak status for a single interface's DNS configuration.

    Classification is based on ``current_server`` -- the address that
    systemd-resolved is *actively* using for this interface.

    When a VPN is active and ``current_server`` is ``None``, the interface
    is dormant: systemd-resolved has shifted the active DNS designation to
    the VPN interface.  This is a positive security signal -- the VPN's DNS
    isolation is working -- and is represented as ``DORMANT`` rather than
    ``NOT_APPLICABLE``.  The two are semantically distinct: ``NOT_APPLICABLE``
    means the VPN precondition is not met; ``DORMANT`` means the precondition
    is met and this interface correctly stepped aside.

    Args:
        dns_config: The interface's DNS configuration.
        vpn_dns: All DNS server addresses from VPN interfaces system-wide.
        isp_dns: All DNS server addresses from physical interfaces system-wide.

    Returns:
        The computed ``DnsLeakStatus``.
    """
    if not vpn_dns:
        return DnsLeakStatus.NOT_APPLICABLE

    active = dns_config.current_server
    if active is None:
        # VPN is active but this interface has no current DNS activity.
        # systemd-resolved correctly shifted the active designation to the
        # VPN interface.  DORMANT is a positive security signal -- it means
        # DNS isolation is working; this interface cannot be leaking.
        logger.debug("leak_status=DORMANT: current_server is None (stepped aside for VPN)")
        return DnsLeakStatus.DORMANT

    active_set = frozenset({active})

    if active_set & isp_dns:
        logger.debug(
            "leak_status=LEAK: active server %s is in isp_dns", active,
        )
        return DnsLeakStatus.LEAK
    if active_set & vpn_dns:
        logger.debug(
            "leak_status=OK: active server %s is in vpn_dns", active,
        )
        return DnsLeakStatus.OK
    if active_set & PUBLIC_DNS_SERVERS:
        logger.debug(
            "leak_status=PUBLIC: active server %s is a public resolver", active,
        )
        return DnsLeakStatus.PUBLIC
    logger.debug("leak_status=WARN: active server %s is unknown", active)
    return DnsLeakStatus.WARN


def _with_leak_status(
    iface: InterfaceInfo,
    vpn_dns: frozenset[str],
    isp_dns: frozenset[str],
) -> InterfaceInfo:
    """Return a copy of ``iface`` with ``dns.leak_status`` computed.

    Only ``_DNS_PROVIDER_TYPES`` (ethernet, wireless, cellular, tether) can
    be ``DORMANT``.  These are the interfaces that receive DNS from DHCP or
    static configuration and hand off to the VPN interface when a tunnel is
    active.

    All other interface types -- loopback, VPN, bridge, virtual, unknown --
    are assigned ``NOT_APPLICABLE`` when ``current_server`` is ``None``,
    because the DORMANT/LEAK distinction is meaningless for them.  A VPN
    interface whose ``current_server`` is populated (e.g. ``proton0``) is
    not short-circuited by this guard and proceeds to ``_compute_leak_status``
    normally, where it receives ``OK`` if its server is in ``vpn_dns``.

    Additionally, any interface whose DNS query status is not ``OK`` and has
    no ``current_server`` -- regardless of type -- receives ``NOT_APPLICABLE``.
    This covers interfaces that are structurally a DNS-provider type but have
    never provided DNS and cannot in their current state (e.g. a cellular modem
    with no SIM, ``modem_state=failed``).  Labelling such an interface
    ``DORMANT`` would misrepresent it as having stepped aside for a VPN,
    implying prior DNS activity that never occurred.

    Args:
        iface: The interface to update.
        vpn_dns: All VPN DNS servers system-wide.
        isp_dns: All ISP DNS servers system-wide.

    Returns:
        New ``InterfaceInfo`` with updated ``dns.leak_status``.
    """
    if (
        iface.interface_type not in _DNS_PROVIDER_TYPES
        and iface.dns.current_server is None
    ):
        new_dns = dataclasses.replace(iface.dns, leak_status=DnsLeakStatus.NOT_APPLICABLE)
        return dataclasses.replace(iface, dns=new_dns)
    if (
        iface.dns.query_status != DataStatus.OK
        and iface.dns.current_server is None
    ):
        new_dns = dataclasses.replace(iface.dns, leak_status=DnsLeakStatus.NOT_APPLICABLE)
        return dataclasses.replace(iface, dns=new_dns)
    status = _compute_leak_status(iface.dns, vpn_dns, isp_dns)
    new_dns = dataclasses.replace(iface.dns, leak_status=status)
    return dataclasses.replace(iface, dns=new_dns)
