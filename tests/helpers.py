"""Shared test helpers for constructing model objects.

Single source of truth for ``InterfaceInfo`` boilerplate.  Each test module
has its own thin wrapper that exposes only the parameters relevant to that
module's concerns; they all delegate to ``make_iface`` here so the actual
``InterfaceInfo(...)`` construction code exists in exactly one place.

Factory functions
-----------------
``make_iface(spec: IfaceSpec) -> InterfaceInfo``
    Full-scope factory used by all test modules.  Accepts an ``IfaceSpec``
    bundle so the function itself has a single argument, satisfying the
    ``max-args`` pylint limit without suppression.

``make_output_iface(spec: IfaceSpec) -> InterfaceInfo``
    Thin delegation to ``make_iface`` for output-layer tests (``test_table``
    and ``test_export``).  The distinct name signals scope: supply an
    ``IfaceSpec`` configured for whatever the output test needs.  For
    domain-layer tests, use ``make_iface`` directly.

``IfaceSpec``
    Frozen, keyword-only dataclass whose fields mirror the parameters of the
    old positional factory API.  All fields have defaults so call sites supply
    only the fields relevant to the test.
"""

import dataclasses

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


@dataclasses.dataclass(frozen=True, kw_only=True)
class IfaceSpec:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """Frozen, keyword-only configuration bundle for InterfaceInfo test factories.

    All fields carry sensible defaults so call sites supply only what is
    relevant to the test being written.  The field names mirror the
    ``InterfaceInfo`` domain model groups (IP, DNS, routing, VPN) without
    the strict domain invariants that ``__post_init__`` would impose on
    the model itself.

    This class is the single parameter accepted by both ``make_iface`` and
    ``make_output_iface``, which keeps both factory functions within the
    project ``max-args = 6`` limit and makes the configuration explicit at
    each call site.

    ``frozen=True`` is applied for the same reason production domain objects
    are frozen: a spec that is silently mutated between construction and use
    in a test is indistinguishable from a correct spec, making the mutation
    invisible.  Freezing catches such bugs at construction time.

    The ``too-many-instance-attributes`` suppressor is intentional.  The
    fourteen fields mirror the fourteen configurable aspects of
    ``InterfaceInfo`` that tests need to vary.  Reducing the field count
    would force per-module spec subclasses, fragmenting the single-source-
    of-truth design.  The suppressor is localised to this class and does
    not hide a design smell; it documents a deliberate trade-off.

    Fields
    ------
    name:
        Interface name string.
    interface_type:
        Classification of the interface.
    device:
        Explicit ``DeviceInfo``; defaults to ``DeviceInfo.unavailable()``.
    ipv4:
        Internal IPv4 address, or ``None``.
    dns_servers:
        Configured DNS server addresses (``servers`` tuple).
    current_server:
        Actively-used DNS server address, or ``None`` when dormant.
    leak:
        DNS leak classification sentinel.
    gateway:
        Default route gateway address, or ``None`` when no route exists.
    metric:
        Route metric integer, or ``None``.
    egress:
        Explicit ``EgressInfo``; overrides ``egress_status`` when provided.
    egress_status:
        Used to synthesise ``EgressInfo`` when ``egress`` is ``None``.
    carries_vpn:
        Whether this interface is the physical underlay for a VPN tunnel.
    server_ip:
        VPN server IP detected from static host routes.
    modem:
        ``ModemInfo`` for cellular interfaces; ``None`` otherwise.
    """

    name: str = "eth0"
    interface_type: InterfaceType = InterfaceType.ETHERNET
    device: DeviceInfo | None = None
    ipv4: str | None = None
    dns_servers: tuple[str, ...] = ()
    current_server: str | None = None
    leak: DnsLeakStatus = DnsLeakStatus.NOT_APPLICABLE
    gateway: str | None = None
    metric: int | None = None
    egress: EgressInfo | None = None
    egress_status: EgressStatus = EgressStatus.UNAVAILABLE
    carries_vpn: bool = False
    server_ip: str | None = None
    modem: ModemInfo | None = None


def make_iface(spec: IfaceSpec) -> InterfaceInfo:
    """Build a minimal ``InterfaceInfo`` from *spec*.

    This is the canonical ``InterfaceInfo`` factory for the test suite.
    Every test module uses ``make_iface`` (directly or via a thin
    module-local wrapper) rather than constructing ``InterfaceInfo`` inline,
    so the dataclass construction code lives in exactly one place.

    Derived fields
    --------------
    ``dns.query_status`` is ``OK`` when ``spec.dns_servers`` is non-empty,
    ``UNAVAILABLE`` otherwise.  ``routing.query_status`` is ``OK`` when
    ``spec.gateway`` is non-``None``, ``UNAVAILABLE`` otherwise.  When
    ``spec.egress`` is ``None``, a synthetic ``EgressInfo`` is built from
    ``spec.egress_status``; ``OK`` status populates placeholder fields.

    Args:
        spec: Configuration bundle.  Supply only the fields relevant to the
              test; everything else defaults to the simplest valid value.

    Returns:
        A fully-constructed, frozen ``InterfaceInfo`` instance.
    """
    dns_status = DataStatus.OK if spec.dns_servers else DataStatus.UNAVAILABLE
    routing_status = DataStatus.OK if spec.gateway is not None else DataStatus.UNAVAILABLE

    egress = spec.egress
    if egress is None:
        egress = EgressInfo(
            status=spec.egress_status,
            external_ip="1.2.3.4" if spec.egress_status == EgressStatus.OK else None,
            external_ipv6=None,
            isp="AS1 ISP" if spec.egress_status == EgressStatus.OK else None,
            country="DE" if spec.egress_status == EgressStatus.OK else None,
        )

    return InterfaceInfo(
        name=spec.name,
        interface_type=spec.interface_type,
        device=spec.device if spec.device is not None else DeviceInfo.unavailable(),
        ip=IPConfig.ok(spec.ipv4, None) if spec.ipv4 is not None else IPConfig.unavailable(),
        dns=DNSConfig(
            query_status=dns_status,
            servers=spec.dns_servers,
            current_server=spec.current_server,
            leak_status=spec.leak,
        ),
        egress=egress,
        routing=RoutingInfo(
            query_status=routing_status,
            gateway=spec.gateway,
            metric=spec.metric,
        ),
        vpn=(
            VPNInfo.ok(spec.server_ip, carries_vpn=spec.carries_vpn)
            if spec.server_ip is not None
            else VPNInfo.not_applicable(carries_vpn=spec.carries_vpn)
            if spec.interface_type != InterfaceType.VPN
            else VPNInfo.unavailable(carries_vpn=spec.carries_vpn)
        ),
        modem=spec.modem,
    )


def make_output_iface(spec: IfaceSpec) -> InterfaceInfo:
    """Factory for output-layer tests (``test_table``, ``test_export``).

    A thin delegation to ``make_iface`` with a distinct name that signals
    scope: this factory is for tests that exercise table rendering and JSON
    export.  It covers the union of parameters needed by both output test
    modules.

    For domain-layer tests (``test_dns``, ``test_vpn``, ``test_orchestrator``
    etc.), use ``make_iface`` directly with a module-local wrapper that
    exposes only the parameters relevant to that module.

    Args:
        spec: Configuration bundle.  See ``IfaceSpec`` for field descriptions.

    Returns:
        A fully-constructed, frozen ``InterfaceInfo`` instance.
    """
    return make_iface(spec)
