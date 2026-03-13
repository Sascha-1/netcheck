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
    1. If no VPN is active (``vpn_dns`` is empty): ``NO_VPN``.
    2. If ``current_server`` is ``None`` and ``servers`` is non-empty:
       ``DORMANT`` -- the VPN is active and this interface has correctly
       stepped aside from its configured DNS role; systemd-resolved is not
       routing queries through it.  This is a positive security signal.
    3. If ``current_server`` is ``None`` and ``servers`` is empty:
       ``ISOLATED`` -- the VPN is active and this interface has no DNS
       server configuration at all.  The tool cannot determine whether the
       VPN client removed the servers (e.g. ProtonVPN) or the interface
       never had DNS in its current operational state (e.g. a cellular modem
       with no SIM).  Both produce the same observable state; both are
       positive security signals: the interface is not resolving any queries.
    4. If ``current_server`` is in ``isp_dns``: ``LEAK`` -- active queries
       go to the ISP resolver while a VPN is running.
    5. If ``current_server`` is in ``vpn_dns``: ``OK`` -- queries go through
       the VPN provider's resolver.
    6. If ``current_server`` is in ``PUBLIC_DNS_SERVERS``: ``PUBLIC`` --
       using a public resolver (Cloudflare/Google/Quad9); not an ISP leak
       but not optimal.
    7. Otherwise: ``WARN`` -- unknown resolver; investigate.

``query_status`` semantics
--------------------------
- ``DataStatus.ERROR``       -- runner returned ``None`` (``resolvectl``
                               subprocess failed or timed out).
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

    - ``DataStatus.ERROR``       -- runner returned ``None`` (subprocess
                                   failed or timed out).
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
    if output is None:
        logger.debug("%s: resolvectl runner returned None (status=ERROR)", iface_name)
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

    When a VPN is active and ``current_server`` is ``None``, the result
    depends on whether ``servers`` is populated:

    - Non-empty ``servers``: ``DORMANT`` -- the interface was a DNS provider
      that has correctly stepped aside for the VPN.  A positive security
      signal confirming DNS isolation is working.
    - Empty ``servers``: ``ISOLATED`` -- the VPN is active and this interface
      has no DNS configuration at all.  The cause is unknowable from
      observable state (VPN client stripped the servers, or the interface
      never had DNS in its current state); both are represented as
      ``ISOLATED``.

    Args:
        dns_config: The interface's DNS configuration.
        vpn_dns: All DNS server addresses from VPN interfaces system-wide.
        isp_dns: All DNS server addresses from physical interfaces system-wide.

    Returns:
        The computed ``DnsLeakStatus``.
    """
    if not vpn_dns:
        return DnsLeakStatus.NO_VPN

    active = dns_config.current_server
    if active is None:
        if dns_config.servers:
            # VPN is active; this interface has configured servers but none
            # is currently active -- systemd-resolved shifted the active
            # designation to the VPN interface.  DORMANT is a positive
            # security signal: this interface cannot be leaking.
            logger.debug(
                "leak_status=DORMANT: current_server is None, servers=%s"
                " (stepped aside for VPN)",
                dns_config.servers,
            )
            return DnsLeakStatus.DORMANT
        # VPN is active; this interface has no servers and no current_server.
        # The tool cannot distinguish whether the VPN client stripped the
        # servers (e.g. ProtonVPN) or the interface never had DNS in its
        # current state (e.g. no-SIM modem).  Both are observationally
        # identical and both are positive security signals: the interface is
        # not routing any DNS queries.
        logger.debug(
            "leak_status=ISOLATED: current_server is None, servers empty"
            " (VPN active, no DNS configuration present)",
        )
        return DnsLeakStatus.ISOLATED

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


def _should_skip_leak_detection(
    iface: InterfaceInfo,
    vpn_dns: frozenset[str],
) -> bool:
    """Return ``True`` when ``_with_leak_status`` must assign ``NOT_APPLICABLE``.

    Two independent conditions mandate ``NOT_APPLICABLE``; this helper
    encapsulates them so that the action (assigning ``NOT_APPLICABLE``) is
    written exactly once in ``_with_leak_status``.

    **Condition 1 -- structural exclusion.**
    The interface type is not in ``_DNS_PROVIDER_TYPES`` (loopback, VPN,
    bridge, virtual, unknown) *and* ``current_server`` is ``None``.
    These types cannot step aside for a VPN: they never act as DNS providers
    to begin with, so ``DORMANT`` and ``ISOLATED`` are semantically incorrect
    for them.
    A non-DNS-provider type with an active ``current_server`` is not
    short-circuited here; it proceeds to ``_compute_leak_status`` normally,
    where it may receive ``OK`` (e.g. a VPN interface whose resolver is in
    ``vpn_dns``).

    **Condition 2 -- state-based exclusion (no VPN active only).**
    The interface is a DNS-provider type *but* its DNS query status is not
    ``OK``, it has no ``current_server``, **and no VPN is active on the
    system** (``vpn_dns`` is empty).  When no VPN is active there is no
    tunnel to compare DNS servers against, so classification is not
    meaningful for an interface with no DNS activity.
    When a VPN *is* active and the same state is observed (no servers, no
    current_server), the interface is not skipped: it proceeds to
    ``_compute_leak_status``, which returns ``ISOLATED`` -- a truthful
    signal that the interface is not routing DNS while the VPN is running.

    Both conditions share the ``current_server is None`` sub-condition.
    When ``current_server`` is set, neither condition can fire and the
    function returns ``False`` immediately.

    Args:
        iface: The interface under evaluation.
        vpn_dns: All DNS server addresses from VPN interfaces system-wide.
                 Non-empty when at least one VPN interface is active.

    Returns:
        ``True`` if ``NOT_APPLICABLE`` must be assigned; ``False`` if
        ``_compute_leak_status`` should be called instead.
    """
    if iface.dns.current_server is not None:
        return False
    if iface.interface_type not in _DNS_PROVIDER_TYPES:
        return True  # Condition 1: structural exclusion
    if iface.dns.query_status != DataStatus.OK and not vpn_dns:
        return True  # Condition 2: no DNS activity and no VPN active
    return False


def _with_leak_status(
    iface: InterfaceInfo,
    vpn_dns: frozenset[str],
    isp_dns: frozenset[str],
) -> InterfaceInfo:
    """Return a copy of ``iface`` with ``dns.leak_status`` computed.

    Delegates the skip decision to ``_should_skip_leak_detection``, which
    encapsulates the two independent conditions that mandate ``NOT_APPLICABLE``
    (structural exclusion by interface type, and state-based exclusion for
    DNS-provider types with no DNS activity when no VPN is active).
    See ``_should_skip_leak_detection`` for the full rationale.

    When neither skip condition applies, delegates to
    ``_compute_leak_status`` for the full
    DORMANT/ISOLATED/LEAK/OK/PUBLIC/WARN classification.

    Args:
        iface: The interface to update.
        vpn_dns: All VPN DNS servers system-wide.
        isp_dns: All ISP DNS servers system-wide.

    Returns:
        New ``InterfaceInfo`` with updated ``dns.leak_status``.
    """
    if _should_skip_leak_detection(iface, vpn_dns):
        new_dns = dataclasses.replace(iface.dns, leak_status=DnsLeakStatus.NOT_APPLICABLE)
        return dataclasses.replace(iface, dns=new_dns)
    status = _compute_leak_status(iface.dns, vpn_dns, isp_dns)
    new_dns = dataclasses.replace(iface.dns, leak_status=status)
    return dataclasses.replace(iface, dns=new_dns)
