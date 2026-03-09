"""Orchestrator for netcheck.

Coordinates all hardware and network modules to produce a complete
``list[InterfaceInfo]``.  All external dependencies are injected; the
orchestrator contains no direct system calls.

Collection sequence
-------------------
1.  Fetch all modem data from ModemManager (one batch call).
2.  Derive the set of cellular interface names from modem records.
3.  Determine the active egress interface (lowest-metric default route).
4.  Query the ipinfo.io API for the egress interface only.
5.  Batch-query all IPv4 and IPv6 addresses in two ``ip addr show`` calls.
6.  Enumerate all network interfaces.
7.  For each interface, build an ``InterfaceInfo`` (type, device, IP, DNS,
    routing, egress, VPN placeholder, modem if cellular).
8.  Run DNS leak detection over the completed list -- returns a new list
    (immutable pattern; original list discarded).
9.  Detect VPN underlay: resolve the VPN server endpoint and physical carrier
    interface once (both are system-wide properties); update the carrier with
    ``vpn.carries_vpn = True``, then update every VPN interface with the
    server IP.  All updates use ``dataclasses.replace`` (immutable pattern).

Failure handling
----------------
If an individual interface cannot be processed, it is skipped with a
warning log.  Processing of remaining interfaces continues.

If the egress query fails, ``EgressInfo.create_failed()`` is attached to
the active interface.  All other interfaces receive
``EgressInfo.create_unavailable()``.

Egress status semantics
-----------------------
``EgressStatus.UNAVAILABLE`` is used for two distinct conditions:

- The interface is not the active egress path (the common case).
- No default route exists on the system at all, so no interface is the
  active egress path.

The display layer renders both as ``--``.  The distinction is not currently
surfaced to the user; it is noted here for future reference.
"""

import dataclasses
import logging

from netcheck.core.enums import DataStatus, InterfaceType
from netcheck.core.models import (
    EgressInfo,
    IPConfig,
    InterfaceInfo,
    ModemInfo,
    RoutingInfo,
    VPNInfo,
)
from netcheck.hardware.modem import (
    ModemRecord,
    build_modem_info,
    get_all_modem_data,
    get_modem_interfaces,
)
from netcheck.network.addressing import get_all_ipv4_addresses, get_all_ipv6_addresses
from netcheck.network.dns import check_dns_leaks, get_interface_dns
from netcheck.network.egress import get_egress_info
from netcheck.network.interfaces import detect_interface_type, get_device_name, get_interface_list
from netcheck.network.routing import get_active_interface, get_route_info
from netcheck.network.vpn import find_vpn_carrier, get_vpn_server_endpoint
from netcheck.utils.command import CommandRunner
from netcheck.utils.http import HttpClient
from netcheck.utils.sysfs import SysfsReader

logger = logging.getLogger(__name__)


def collect_network_data(
    runner: CommandRunner,
    reader: SysfsReader,
    client: HttpClient,
) -> list[InterfaceInfo]:
    """Collect complete network information for all interfaces.

    Args:
        runner: Command runner for system calls (``ip``, ``mmcli``, etc.).
        reader: Sysfs reader for hardware detection.
        client: HTTP client for the ipinfo.io API.

    Returns:
        Ordered list of ``InterfaceInfo`` objects (one per interface),
        with DNS leak status and VPN underlay information populated.
        Returns an empty list if no interfaces are found.
    """
    # Step 1--2: Modem data
    logger.debug("Querying ModemManager...")
    modem_records = get_all_modem_data(runner)
    modem_ifaces = get_modem_interfaces(modem_records)
    logger.debug("Cellular interfaces: %s", modem_ifaces)

    # Step 3: Active interface
    active = get_active_interface(runner)
    logger.debug("Active egress interface: %s", active)

    # Step 4: External IP (egress interface only)
    egress = _fetch_egress(active, client)

    # Step 5: Batch IP queries
    logger.debug("Batch-querying IP addresses...")
    all_ipv4 = get_all_ipv4_addresses(runner)
    all_ipv6 = get_all_ipv6_addresses(runner)

    # Step 6: Interface list
    names = get_interface_list(runner)
    if not names:
        logger.warning("No network interfaces found")
        return []
    logger.debug("Found %d interfaces", len(names))

    # Step 7: Build per-interface records
    ctx = _SharedRunData(
        active=active,
        egress=egress,
        all_ipv4=all_ipv4,
        all_ipv6=all_ipv6,
        modem_ifaces=modem_ifaces,
        modem_records=modem_records,
    )
    interfaces: list[InterfaceInfo] = []
    for name in names:
        try:
            iface = _build_interface(name, ctx, runner, reader)
            interfaces.append(iface)
        except (OSError, ValueError, RuntimeError) as exc:
            logger.warning("Skipping %s: %s", name, exc)

    # Step 8: DNS leak detection (returns new list)
    logger.debug("Running DNS leak detection...")
    interfaces = check_dns_leaks(interfaces)

    # Step 9: VPN underlay detection (returns new list)
    logger.debug("Detecting VPN underlay...")
    interfaces = _apply_vpn_underlay(interfaces, runner)

    logger.info("Collected data for %d interfaces", len(interfaces))
    return interfaces


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class _SharedRunData:
    """Data fetched once per run and shared across every per-interface query.

    Bundles the collection-wide results (active interface, egress info,
    IP address maps, modem records) so that ``_build_interface`` receives a
    single structured argument rather than a long positional list.
    """

    active: str | None
    egress: EgressInfo
    all_ipv4: tuple[dict[str, str], DataStatus]
    all_ipv6: tuple[dict[str, str], DataStatus]
    modem_ifaces: frozenset[str]
    modem_records: list[ModemRecord]


def _fetch_egress(active: str | None, client: HttpClient) -> EgressInfo:
    """Query the egress API when an active interface is known.

    Returns ``create_unavailable()`` if there is no active interface.
    """
    if active is None:
        return EgressInfo.create_unavailable()
    logger.debug("Querying egress info for %s...", active)
    return get_egress_info(client)


def _build_interface(
    name: str,
    ctx: _SharedRunData,
    runner: CommandRunner,
    reader: SysfsReader,
) -> InterfaceInfo:
    """Build a single ``InterfaceInfo`` for *name* using collection context.

    Each sub-query (DNS, routing, device) returns a domain object that
    carries its own ``DataStatus``, so the orchestrator does not need to
    reconstruct those objects from raw tuples.

    Routing is not queried for loopback interfaces: the loopback has only
    kernel-internal routes that are never visible to ``ip route show dev``,
    so any result would always be ``ERROR``.  ``RoutingInfo`` is constructed
    directly with ``DataStatus.NOT_APPLICABLE`` instead.
    """
    itype = detect_interface_type(name, ctx.modem_ifaces, reader)
    device = get_device_name(name, itype, reader, runner)
    dns_config = get_interface_dns(name, runner)
    routing = (
        RoutingInfo(query_status=DataStatus.NOT_APPLICABLE, gateway=None, metric=None)
        if itype == InterfaceType.LOOPBACK
        else get_route_info(name, runner)
    )
    egress_for_iface = ctx.egress if name == ctx.active else EgressInfo.create_unavailable()
    modem: ModemInfo | None = None
    if itype == InterfaceType.CELLULAR:
        modem = build_modem_info(name, ctx.modem_records)

    return InterfaceInfo(
        name=name,
        interface_type=itype,
        device=device,
        ip=_build_ip_config(name, ctx),
        dns=dns_config,
        egress=egress_for_iface,
        routing=routing,
        vpn=VPNInfo.not_applicable() if itype != InterfaceType.VPN else VPNInfo.unavailable(),
        modem=modem,
    )


def _build_ip_config(name: str, ctx: _SharedRunData) -> IPConfig:
    """Derive ``IPConfig`` for *name* from the batch address query results.

    Translates the batch-command status into per-interface ``DataStatus``:
    if the command failed (``ERROR``), every interface inherits ``ERROR``;
    if the command succeeded but the interface is absent from the dict, the
    status is ``UNAVAILABLE``.

    Args:
        name: Interface name.
        ctx: Shared run data containing the batch address query results.

    Returns:
        ``IPConfig`` with independent status fields for IPv4 and IPv6.
    """
    ipv4_dict, ipv4_cmd_status = ctx.all_ipv4
    ipv6_dict, ipv6_cmd_status = ctx.all_ipv6
    ipv4 = ipv4_dict.get(name)
    ipv6 = ipv6_dict.get(name)
    ipv4_status = (
        DataStatus.OK if ipv4 is not None else
        DataStatus.ERROR if ipv4_cmd_status == DataStatus.ERROR else
        DataStatus.UNAVAILABLE
    )
    ipv6_status = (
        DataStatus.OK if ipv6 is not None else
        DataStatus.ERROR if ipv6_cmd_status == DataStatus.ERROR else
        DataStatus.UNAVAILABLE
    )
    logger.debug(
        "%s: ipv4=%s (%s) ipv6=%s (%s)",
        name,
        ipv4 if ipv4 is not None else "--",
        ipv4_status.value,
        ipv6 if ipv6 is not None else "--",
        ipv6_status.value,
    )
    return IPConfig(
        ipv4=ipv4, ipv4_status=ipv4_status,
        ipv6=ipv6, ipv6_status=ipv6_status,
    )


def _apply_vpn_underlay(
    interfaces: list[InterfaceInfo],
    runner: CommandRunner,
) -> list[InterfaceInfo]:
    """Populate VPN server IPs and carrier flags using ``dataclasses.replace``.

    Execution sequence:
    1.  Determine the VPN server endpoint from static host routes (one call).
    2.  Find the physical underlay carrier by metric priority (one call).
    3.  Set ``vpn.carries_vpn = True`` on the carrier interface (if found).
    4.  Update every VPN interface with the server endpoint result:

        - If ``server_ip`` is found: call ``VPNInfo.ok(server_ip)`` on every
          VPN interface, setting ``server_ip_status = DataStatus.OK``.
        - If ``server_ip`` is ``None``: propagate the ``ERROR`` or
          ``UNAVAILABLE`` status via
          ``dataclasses.replace(iface.vpn, server_ip_status=status)``,
          leaving ``server_ip=None`` intact (invariant satisfied).

    Both the server endpoint and the carrier are system-wide properties that
    do not depend on which VPN interface is being processed.  They are
    therefore resolved once, before the per-interface update loop, rather
    than once per VPN interface.

    ``find_vpn_carrier`` is safe to call before the server_ip loop because it
    reads only ``interface_type``, ``routing.gateway``, and ``routing.metric``
    -- none of which are modified by this function.  The carrier is always a
    physical interface (ethernet, wireless, cellular, or tether); VPN
    interfaces are excluded from carrier selection by design.

    All modifications use ``dataclasses.replace`` -- the input list and its
    ``InterfaceInfo`` objects are never mutated.

    Args:
        interfaces: Post-DNS-leak-check interface list.
        runner: Command runner for ``ip route show``.

    Returns:
        New list with VPN server IPs and carrier flags populated.
    """
    result = list(interfaces)
    idx: dict[str, int] = {iface.name: i for i, iface in enumerate(result)}

    vpn_indices = [i for i, iface in enumerate(result)
                   if iface.interface_type == InterfaceType.VPN]
    if not vpn_indices:
        return result

    server_ip, server_ip_status = get_vpn_server_endpoint(runner)
    if server_ip is None:
        logger.debug(
            "No VPN server endpoint found in routing table (status=%s)", server_ip_status
        )
        # Propagate ERROR or UNAVAILABLE status onto every VPN interface.
        for i in vpn_indices:
            iface = result[i]
            new_vpn = dataclasses.replace(iface.vpn, server_ip_status=server_ip_status)
            result[i] = dataclasses.replace(iface, vpn=new_vpn)
        return result

    logger.debug("VPN server endpoint: %s", server_ip)
    # Carrier is a system-wide property: the lowest-metric physical interface
    # with a default gateway.  Resolve it once here; it does not change
    # between VPN interface iterations.
    carrier_name = find_vpn_carrier(result)
    if carrier_name is not None:
        logger.debug("VPN underlay carrier: %s", carrier_name)
        j = idx[carrier_name]
        carrier = result[j]
        new_carrier_vpn = dataclasses.replace(carrier.vpn, carries_vpn=True)
        result[j] = dataclasses.replace(carrier, vpn=new_carrier_vpn)
    else:
        logger.debug("No VPN carrier found in interface list")

    for i in vpn_indices:
        iface = result[i]
        logger.debug("Updating VPN interface %s with server_ip=%s", iface.name, server_ip)
        new_vpn = VPNInfo.ok(server_ip, carries_vpn=iface.vpn.carries_vpn)
        result[i] = dataclasses.replace(iface, vpn=new_vpn)

    return result
