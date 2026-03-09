"""Smoke tests for netcheck.core.models.

Verifies the structural contracts of the domain model:

- All dataclasses are frozen (mutation raises ``FrozenInstanceError``).
- ``DeviceInfo`` factory methods produce the correct ``DataStatus`` and
  ``name`` values; the ``OK`` factory enforces that ``name`` is non-None
  via ``__post_init__``.
- ``DNSConfig`` and ``RoutingInfo`` carry a ``query_status`` field so
  callers can distinguish "data absent" from "query failed" without
  inspecting sentinel strings.
- No sentinel strings (``"N/A"``, ``"--"``, etc.) appear in domain objects;
  those are a display-layer concern handled in ``netcheck/output/``.
"""

from dataclasses import FrozenInstanceError

import pytest

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
from tests.helpers import IfaceSpec, make_iface

_SENTINEL_STRINGS = frozenset({"N/A", "--", "NONE", "DEFAULT", "QUERY FAILED"})


def _make_interface(
    name: str = "eth0",
    interface_type: InterfaceType = InterfaceType.ETHERNET,
    modem: ModemInfo | None = None,
) -> InterfaceInfo:
    """Build a minimal InterfaceInfo for model-layer structural tests."""
    return make_iface(IfaceSpec(name=name, interface_type=interface_type, modem=modem))


class TestDeviceInfo:
    """DeviceInfo uses factory class-methods to encode query outcome in the type.

    Each factory sets ``status`` to the appropriate ``DataStatus`` value and
    leaves ``name`` as ``None`` except for ``ok()``, which requires a non-None
    string (enforced by ``__post_init__``).  This makes it impossible to
    construct an ``OK`` record with a missing name.
    """

    def test_not_applicable_factory(self) -> None:
        d = DeviceInfo.not_applicable()
        assert d.status == DataStatus.NOT_APPLICABLE
        assert d.name is None

    def test_unavailable_factory(self) -> None:
        d = DeviceInfo.unavailable()
        assert d.status == DataStatus.UNAVAILABLE
        assert d.name is None

    def test_error_factory(self) -> None:
        d = DeviceInfo.error()
        assert d.status == DataStatus.ERROR
        assert d.name is None

    def test_ok_factory(self) -> None:
        d = DeviceInfo.ok("Intel I219-V")
        assert d.status == DataStatus.OK
        assert d.name == "Intel I219-V"

    def test_frozen(self) -> None:
        d = DeviceInfo.ok("test")
        with pytest.raises(FrozenInstanceError):
            d.name = "other"  # type: ignore[misc]

    def test_ok_with_none_name_raises(self) -> None:
        """Constructing DeviceInfo(OK, None) must raise ValueError.

        ``OK`` status promises a name is present.  Accepting ``None`` would
        violate the invariant that callers rely on to avoid ``None``-checks
        after status gating.  The ``__post_init__`` guard exists precisely
        for call sites that bypass the factory methods.
        """
        with pytest.raises(ValueError, match="invariant"):
            DeviceInfo(status=DataStatus.OK, name=None)

    def test_non_ok_with_name_raises(self) -> None:
        """Constructing DeviceInfo(NOT_APPLICABLE, name) must raise ValueError.

        A non-``OK`` status means the lookup was not attempted or failed.
        Carrying a name alongside such a status is internally inconsistent
        and would mislead callers that gate on status before reading the name.
        All three non-OK statuses are covered by the same invariant check;
        ``NOT_APPLICABLE`` is used here as the representative case.
        """
        with pytest.raises(ValueError, match="invariant"):
            DeviceInfo(status=DataStatus.NOT_APPLICABLE, name="Intel I219-V")


class TestDNSConfig:
    """DNSConfig now requires query_status."""

    def test_construction_with_query_status(self) -> None:
        cfg = DNSConfig(
            query_status=DataStatus.OK,
            servers=("1.1.1.1",),
            current_server="1.1.1.1",
            leak_status=DnsLeakStatus.OK,
        )
        assert cfg.query_status == DataStatus.OK
        assert cfg.servers == ("1.1.1.1",)

    def test_error_status_construction(self) -> None:
        cfg = DNSConfig(
            query_status=DataStatus.ERROR,
            servers=(),
            current_server=None,
            leak_status=DnsLeakStatus.NOT_APPLICABLE,
        )
        assert cfg.query_status == DataStatus.ERROR

    def test_frozen(self) -> None:
        cfg = DNSConfig(
            query_status=DataStatus.OK,
            servers=("1.1.1.1",),
            current_server="1.1.1.1",
            leak_status=DnsLeakStatus.OK,
        )
        with pytest.raises(FrozenInstanceError):
            cfg.current_server = "8.8.8.8"  # type: ignore[misc]


class TestRoutingInfo:
    """RoutingInfo now requires query_status."""

    def test_ok_status_with_route(self) -> None:
        info = RoutingInfo(
            query_status=DataStatus.OK,
            gateway="192.168.1.1",
            metric=100,
        )
        assert info.query_status == DataStatus.OK
        assert info.gateway == "192.168.1.1"
        assert info.metric == 100

    def test_unavailable_status_no_route(self) -> None:
        info = RoutingInfo(
            query_status=DataStatus.UNAVAILABLE,
            gateway=None,
            metric=None,
        )
        assert info.query_status == DataStatus.UNAVAILABLE
        assert info.gateway is None

    def test_metric_zero_is_valid(self) -> None:
        info = RoutingInfo(query_status=DataStatus.OK, gateway="10.0.0.1", metric=0)
        assert info.metric == 0
        assert info.metric is not None

    def test_frozen(self) -> None:
        info = RoutingInfo(
            query_status=DataStatus.OK, gateway="192.168.1.1", metric=100
        )
        with pytest.raises(FrozenInstanceError):
            info.metric = 200  # type: ignore[misc]


class TestInterfaceInfo:
    """InterfaceInfo.device is now DeviceInfo (not str | None)."""

    def test_construction_with_device_info(self) -> None:
        iface = _make_interface()
        assert isinstance(iface.device, DeviceInfo)

    def test_frozen_top_level(self) -> None:
        iface = _make_interface()
        with pytest.raises(FrozenInstanceError):
            iface.name = "eth1"  # type: ignore[misc]

    def test_frozen_nested(self) -> None:
        iface = _make_interface()
        with pytest.raises(FrozenInstanceError):
            iface.routing.metric = 50  # type: ignore[misc]

    def test_equality(self) -> None:
        assert _make_interface() == _make_interface()

    def test_inequality_on_name(self) -> None:
        assert _make_interface("eth0") != _make_interface("eth1")

    def test_modem_none_for_non_cellular(self) -> None:
        iface = _make_interface(interface_type=InterfaceType.ETHERNET)
        assert iface.modem is None

    def test_cellular_carries_modem_info(self) -> None:
        modem = ModemInfo(state="connected", state_reason=None)
        iface = _make_interface(
            name="wwp0",
            interface_type=InterfaceType.CELLULAR,
            modem=modem,
        )
        assert iface.modem is not None
        assert iface.modem.state == "connected"

    def test_no_sentinel_strings_in_none_fields(self) -> None:
        """The model layer must never store display sentinel strings."""
        iface = _make_interface()
        nullable: list[str | None] = [
            iface.device.name,
            iface.ip.ipv4,
            iface.ip.ipv6,
            iface.dns.current_server,
            iface.egress.external_ip,
            iface.routing.gateway,
            iface.vpn.server_ip,
        ]
        for v in nullable:
            assert v not in _SENTINEL_STRINGS


class TestEgressInfo:
    """EgressInfo factory methods and frozen contract."""

    def test_create_unavailable(self) -> None:
        info = EgressInfo.create_unavailable()
        assert info.status == EgressStatus.UNAVAILABLE
        assert info.external_ip is None

    def test_create_failed(self) -> None:
        info = EgressInfo.create_failed()
        assert info.status == EgressStatus.FAILED
        assert info.external_ip is None

    def test_unavailable_and_failed_are_distinct(self) -> None:
        assert (
            EgressInfo.create_unavailable().status != EgressInfo.create_failed().status
        )

    def test_frozen(self) -> None:
        info = EgressInfo.create_unavailable()
        with pytest.raises(FrozenInstanceError):
            info.country = "US"  # type: ignore[misc]


class TestIPConfig:
    """IPConfig factory methods, invariants, and frozen contract."""

    def test_unavailable_factory(self) -> None:
        ip = IPConfig.unavailable()
        assert ip.ipv4 is None
        assert ip.ipv4_status == DataStatus.UNAVAILABLE
        assert ip.ipv6 is None
        assert ip.ipv6_status == DataStatus.UNAVAILABLE

    def test_error_factory(self) -> None:
        ip = IPConfig.error()
        assert ip.ipv4_status == DataStatus.ERROR
        assert ip.ipv6_status == DataStatus.ERROR

    def test_ok_factory_ipv4_only(self) -> None:
        ip = IPConfig.ok("192.168.1.1", None)
        assert ip.ipv4 == "192.168.1.1"
        assert ip.ipv4_status == DataStatus.OK
        assert ip.ipv6 is None
        assert ip.ipv6_status == DataStatus.UNAVAILABLE

    def test_ok_factory_dual_stack(self) -> None:
        ip = IPConfig.ok("192.168.1.1", "2001:db8::1", ipv6_status=DataStatus.OK)
        assert ip.ipv4_status == DataStatus.OK
        assert ip.ipv6 == "2001:db8::1"
        assert ip.ipv6_status == DataStatus.OK

    def test_ok_with_none_ipv4_raises(self) -> None:
        """IPConfig invariant: status OK requires a non-None address."""
        with pytest.raises(ValueError, match="invariant"):
            IPConfig(ipv4=None, ipv4_status=DataStatus.OK,
                     ipv6=None, ipv6_status=DataStatus.UNAVAILABLE)

    def test_non_ok_with_ipv4_raises(self) -> None:
        """IPConfig invariant: non-OK status requires address to be None."""
        with pytest.raises(ValueError, match="invariant"):
            IPConfig(ipv4="1.2.3.4", ipv4_status=DataStatus.UNAVAILABLE,
                     ipv6=None, ipv6_status=DataStatus.UNAVAILABLE)

    def test_frozen(self) -> None:
        ip = IPConfig.ok("1.2.3.4", None)
        with pytest.raises(FrozenInstanceError):
            ip.ipv4 = "5.6.7.8"  # type: ignore[misc]


class TestVPNInfo:
    """VPNInfo factory methods, invariants, and frozen contract."""

    def test_not_applicable_factory(self) -> None:
        v = VPNInfo.not_applicable()
        assert v.server_ip is None
        assert v.server_ip_status == DataStatus.NOT_APPLICABLE
        assert v.carries_vpn is False

    def test_unavailable_factory(self) -> None:
        v = VPNInfo.unavailable()
        assert v.server_ip is None
        assert v.server_ip_status == DataStatus.UNAVAILABLE
        assert v.carries_vpn is False

    def test_error_factory(self) -> None:
        v = VPNInfo.error()
        assert v.server_ip is None
        assert v.server_ip_status == DataStatus.ERROR

    def test_error_factory_with_carries_vpn(self) -> None:
        v = VPNInfo.error(carries_vpn=True)
        assert v.carries_vpn is True

    def test_ok_factory(self) -> None:
        v = VPNInfo.ok("5.253.204.194")
        assert v.server_ip == "5.253.204.194"
        assert v.server_ip_status == DataStatus.OK
        assert v.carries_vpn is False

    def test_ok_factory_with_carries_vpn(self) -> None:
        v = VPNInfo.ok("5.253.204.194", carries_vpn=True)
        assert v.carries_vpn is True

    def test_ok_with_none_server_ip_raises(self) -> None:
        """VPNInfo invariant: status OK requires a non-None server_ip."""
        with pytest.raises(ValueError, match="invariant"):
            VPNInfo(server_ip=None, server_ip_status=DataStatus.OK, carries_vpn=False)

    def test_non_ok_with_server_ip_raises(self) -> None:
        """VPNInfo invariant: non-OK status requires server_ip to be None."""
        with pytest.raises(ValueError, match="invariant"):
            VPNInfo(server_ip="1.2.3.4", server_ip_status=DataStatus.UNAVAILABLE,
                    carries_vpn=False)

    def test_frozen(self) -> None:
        v = VPNInfo.unavailable()
        with pytest.raises(FrozenInstanceError):
            v.carries_vpn = True  # type: ignore[misc]
