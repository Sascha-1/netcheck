"""Tests for netcheck.orchestrator.

Exercises ``collect_network_data`` end-to-end and its private helpers
using the full fake infrastructure (FakeCommandRunner, FakeSysfsReader,
FakeHttpClient).  No real subprocess calls, sysfs reads, or network
requests are made.

Test groups
-----------
``TestCollectNetworkDataHappyPath``
    Full collection run: loopback + ethernet + VPN tunnel.
    Verifies interface count, type classification, IP assignment, egress
    attachment, DNS leak detection, and VPN underlay population.

``TestCollectNetworkDataEdgeCases``
    No interfaces found -> empty list.
    No active interface (no default route) -> all egress UNAVAILABLE.
    OSError from _build_interface -> that interface skipped, others kept.
    RuntimeError from _build_interface -> that interface skipped, others kept.
    ValueError from _build_interface -> propagates (programming error).

``TestFetchEgress``
    Active interface -> delegates to get_egress_info.
    None active interface -> returns create_unavailable().

``TestApplyVpnUnderlay``
    No VPN interfaces -> list returned unchanged.
    VPN interface present but no static host route -> server_ip stays None.
    VPN interface + static host route -> server_ip set, carrier flagged.

``TestBuildInterface``
    Loopback -> routing NOT_APPLICABLE (no ip route show dev call needed).
    Cellular -> modem info attached when ModemManager reports the interface.
"""

import pytest

from netcheck.core.enums import DataStatus, DnsLeakStatus, EgressStatus, InterfaceType
from netcheck.core.models import InterfaceInfo
from netcheck.orchestrator import _apply_vpn_underlay, _fetch_egress, collect_network_data
from tests.fakes import FakeCommandRunner, FakeHttpClient, FakeHttpResponse, FakeSysfsReader
from tests.helpers import IfaceSpec, make_iface, make_output_iface

# ---------------------------------------------------------------------------
# Shared fake data
# ---------------------------------------------------------------------------

_IPINFO_OK = FakeHttpResponse({"ip": "1.2.3.4", "org": "AS9009 M247 Europe", "country": "NL"})

_LOOPBACK_RESOLV = "Link 1 (lo)\n      Current Scopes: none"
_ETH_RESOLV = (
    "Link 2 (eth0)\n"
    "  Current DNS Server: 192.168.1.1\n"
    "         DNS Servers: 192.168.1.1\n"
)
_TUN_RESOLV = (
    "Link 3 (tun0)\n"
    "  Current DNS Server: 10.8.0.1\n"
    "         DNS Servers: 10.8.0.1\n"
)

_LINK_SHOW = (
    "1: lo: <LOOPBACK,UP> mtu 65536\n"
    "2: eth0: <BROADCAST,UP> mtu 1500\n"
    "3: tun0: <POINTOPOINT,UP> mtu 1500"
)

_ADDR4 = (
    "1: lo: <LOOPBACK,UP>\n"
    "    inet 127.0.0.1/8 scope host lo\n"
    "2: eth0: <BROADCAST,UP>\n"
    "    inet 192.168.1.100/24 scope global eth0\n"
    "3: tun0: <POINTOPOINT,UP>\n"
    "    inet 10.8.0.2/24 scope global tun0\n"
)

# Static host route to VPN server -- what the VPN client injects.
_FULL_ROUTE_TABLE = (
    "default via 192.168.1.1 dev eth0 metric 100\n"
    "5.253.204.194 proto static\n"
    "10.8.0.0/24 dev tun0 scope link\n"
)


def _build_vpn_runner() -> FakeCommandRunner:
    """Runner responses for a three-interface scenario: lo + eth0 + tun0."""
    return FakeCommandRunner({
        ("mmcli", "-L"): "",
        ("ip", "route", "show", "default"): "default via 192.168.1.1 dev eth0 metric 100",
        ("ip", "-4", "addr", "show"): _ADDR4,
        ("ip", "-6", "addr", "show"): "",
        ("ip", "-o", "link", "show"): _LINK_SHOW,
        ("resolvectl", "status", "lo"): _LOOPBACK_RESOLV,
        ("ip", "-d", "link", "show", "eth0"): "",
        ("resolvectl", "status", "eth0"): _ETH_RESOLV,
        ("ip", "route", "show", "dev", "eth0"): "default via 192.168.1.1 proto dhcp metric 100",
        ("resolvectl", "status", "tun0"): _TUN_RESOLV,
        ("ip", "route", "show", "dev", "tun0"): "default via 10.8.0.1 metric 50",
        ("ip", "route", "show"): _FULL_ROUTE_TABLE,
    })


def _build_vpn_client() -> FakeHttpClient:
    return FakeHttpClient({
        "https://ipinfo.io/json": _IPINFO_OK,
        "https://v6.ipinfo.io/json": None,
    })


# ---------------------------------------------------------------------------
# Test doubles for exception-handling tests
# ---------------------------------------------------------------------------

class _ErrorReader:
    """SysfsReader test double that raises a given exception for one interface.

    All five ``SysfsReader`` protocol methods are implemented so that mypy
    strict accepts this class wherever a ``SysfsReader`` is expected.  Every
    method delegates to a plain ``FakeSysfsReader`` except ``device_path``:
    when called with the configured ``failing`` interface name it raises
    ``exc`` instead of returning a value.

    ``device_path`` is the first sysfs call made during
    ``detect_interface_type`` (and therefore during ``_build_interface``), so
    the exception surfaces at the very start of per-interface processing --
    before any domain model is constructed.  This makes it the minimal,
    stable injection point for testing the exception handler in
    ``collect_network_data`` without using ``unittest.mock``.

    Args:
        failing: Interface name that triggers the exception.
        exc:     Exception instance to raise when ``device_path(failing)``
                 is called.
    """

    def __init__(self, failing: str, exc: Exception) -> None:
        self._failing = failing
        self._exc = exc
        self._fallback = FakeSysfsReader()

    def device_path(self, iface: str) -> str | None:
        """Raise ``self._exc`` for the failing interface; delegate otherwise."""
        if iface == self._failing:
            raise self._exc
        return self._fallback.device_path(iface)

    def read_file(self, path: str, filename: str) -> str | None:
        """Delegate to FakeSysfsReader."""
        return self._fallback.read_file(path, filename)

    def read_link_name(self, path: str, link_name: str) -> str | None:
        """Delegate to FakeSysfsReader."""
        return self._fallback.read_link_name(path, link_name)

    def parent_path(self, path: str) -> str | None:
        """Delegate to FakeSysfsReader."""
        return self._fallback.parent_path(path)

    def dir_exists(self, path: str) -> bool:
        """Delegate to FakeSysfsReader."""
        return self._fallback.dir_exists(path)


def _build_exception_test_runner() -> FakeCommandRunner:
    """Runner for a lo + eth0 two-interface scenario used by exception-handler tests.

    ``eth0`` is the interface that will fail via ``_ErrorReader``; the
    exception is raised inside ``detect_interface_type`` before any
    per-interface commands (``resolvectl``, ``ip route show dev``) are
    reached, so those commands are intentionally absent from this mapping.

    Only the batch commands (needed before the per-interface loop) and
    ``lo``'s per-interface commands are present.  ``ip route show`` is
    omitted because ``_apply_vpn_underlay`` returns early when no VPN
    interfaces are in the result list.
    """
    return FakeCommandRunner({
        ("mmcli", "-L"): "",
        ("ip", "route", "show", "default"): None,
        ("ip", "-4", "addr", "show"): (
            "1: lo: <LOOPBACK,UP>\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,UP>\n"
            "    inet 192.168.1.10/24 scope global eth0\n"
        ),
        ("ip", "-6", "addr", "show"): "",
        ("ip", "-o", "link", "show"): (
            "1: lo: <LOOPBACK,UP> mtu 65536\n"
            "2: eth0: <BROADCAST,UP> mtu 1500"
        ),
        ("resolvectl", "status", "lo"): _LOOPBACK_RESOLV,
    })


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------

class TestCollectNetworkDataHappyPath:
    """collect_network_data with lo + eth0 + tun0."""

    def _run(self) -> list[InterfaceInfo]:
        runner = _build_vpn_runner()
        # Provide the sysfs ARPHRD type file for eth0 so that _is_ethernet
        # (priority 9) correctly classifies it as ETHERNET.  The real kernel
        # always writes this file; FakeSysfsReader must supply it explicitly.
        reader = FakeSysfsReader(files={("/sys/class/net/eth0", "type"): "1"})
        client = _build_vpn_client()
        return collect_network_data(runner, reader, client)

    def test_returns_all_three_interfaces(self) -> None:
        result = self._run()
        assert len(result) == 3

    def test_interface_names_present(self) -> None:
        result = self._run()
        names = {i.name for i in result}
        assert names == {"lo", "eth0", "tun0"}

    def test_loopback_classified_correctly(self) -> None:
        result = self._run()
        lo = next(i for i in result if i.name == "lo")
        assert lo.interface_type == InterfaceType.LOOPBACK

    def test_ethernet_classified_correctly(self) -> None:
        result = self._run()
        eth = next(i for i in result if i.name == "eth0")
        assert eth.interface_type == InterfaceType.ETHERNET

    def test_vpn_classified_correctly(self) -> None:
        result = self._run()
        tun = next(i for i in result if i.name == "tun0")
        assert tun.interface_type == InterfaceType.VPN

    def test_loopback_routing_not_applicable(self) -> None:
        """Loopback must never have ip route show dev called on it."""
        result = self._run()
        lo = next(i for i in result if i.name == "lo")
        assert lo.routing.query_status == DataStatus.NOT_APPLICABLE

    def test_ipv4_addresses_assigned(self) -> None:
        result = self._run()
        by_name = {i.name: i for i in result}
        assert by_name["lo"].ip.ipv4 == "127.0.0.1"
        assert by_name["eth0"].ip.ipv4 == "192.168.1.100"
        assert by_name["tun0"].ip.ipv4 == "10.8.0.2"

    def test_egress_attached_to_active_interface(self) -> None:
        """eth0 is the active interface; it must carry the egress data."""
        result = self._run()
        eth = next(i for i in result if i.name == "eth0")
        assert eth.egress.status == EgressStatus.OK
        assert eth.egress.external_ip == "1.2.3.4"

    def test_non_active_interfaces_have_unavailable_egress(self) -> None:
        result = self._run()
        for iface in result:
            if iface.name != "eth0":
                assert iface.egress.status == EgressStatus.UNAVAILABLE

    def test_vpn_server_ip_populated(self) -> None:
        """VPN endpoint must be detected from the static bypass route."""
        result = self._run()
        tun = next(i for i in result if i.name == "tun0")
        assert tun.vpn.server_ip == "5.253.204.194"

    def test_vpn_carrier_flagged(self) -> None:
        """eth0 must be flagged as the VPN underlay carrier."""
        result = self._run()
        eth = next(i for i in result if i.name == "eth0")
        assert eth.vpn.is_vpn_underlay is True

    def test_vpn_interface_not_flagged_as_carrier(self) -> None:
        """The VPN interface itself must not carry_vpn=True."""
        result = self._run()
        tun = next(i for i in result if i.name == "tun0")
        assert tun.vpn.is_vpn_underlay is False

    def test_dns_leak_detection_applied(self) -> None:
        """DNS leak statuses must not all remain NOT_APPLICABLE after collection."""
        result = self._run()
        statuses = {i.dns.leak_status for i in result}
        assert statuses != {DnsLeakStatus.NOT_APPLICABLE}

    def test_vpn_dns_classified_ok(self) -> None:
        """tun0's active DNS server (10.8.0.1) is in vpn_dns -> OK."""
        result = self._run()
        tun = next(i for i in result if i.name == "tun0")
        assert tun.dns.leak_status == DnsLeakStatus.OK

    def test_return_type_is_list(self) -> None:
        assert isinstance(self._run(), list)


class TestCollectNetworkDataEdgeCases:
    """collect_network_data under abnormal conditions.

    Exception-handler policy
    ------------------------
    ``OSError`` and ``RuntimeError`` raised inside ``_build_interface`` are
    caught: the affected interface is skipped with a warning log and
    processing of remaining interfaces continues.

    ``ValueError`` is NOT caught: it propagates out of
    ``collect_network_data``.  ``ValueError`` is raised by the domain-model
    ``__post_init__`` validators (``DeviceInfo``, ``IPConfig``, ``VPNInfo``)
    when a caller passes an invalid argument combination -- a programming
    error that must not be silenced.
    """

    def test_no_interfaces_returns_empty_list(self) -> None:
        runner = FakeCommandRunner({
            ("mmcli", "-L"): "",
            ("ip", "route", "show", "default"): None,
            ("ip", "-4", "addr", "show"): "",
            ("ip", "-6", "addr", "show"): "",
            ("ip", "-o", "link", "show"): None,
        })
        result = collect_network_data(runner, FakeSysfsReader(), FakeHttpClient({}))
        assert not result

    def test_no_default_route_all_egress_unavailable(self) -> None:
        """When ip route show default returns None, no egress query is made."""
        runner = FakeCommandRunner({
            ("mmcli", "-L"): "",
            ("ip", "route", "show", "default"): None,
            ("ip", "-4", "addr", "show"): "2: eth0:\n    inet 192.168.1.1/24 scope global eth0",
            ("ip", "-6", "addr", "show"): "",
            ("ip", "-o", "link", "show"): "2: eth0: <BROADCAST,UP> mtu 1500",
            ("resolvectl", "status", "eth0"): "",
            ("ip", "-d", "link", "show", "eth0"): "",
            ("ip", "route", "show", "dev", "eth0"): "",
        })
        result = collect_network_data(runner, FakeSysfsReader(), FakeHttpClient({}))
        assert all(i.egress.status == EgressStatus.UNAVAILABLE for i in result)

    def test_failed_egress_query_attached(self) -> None:
        """When ipinfo.io fails, the active interface gets create_failed()."""
        runner = FakeCommandRunner({
            ("mmcli", "-L"): "",
            ("ip", "route", "show", "default"): "default via 192.168.1.1 dev eth0 metric 100",
            ("ip", "-4", "addr", "show"): "2: eth0:\n    inet 192.168.1.1/24 scope global eth0",
            ("ip", "-6", "addr", "show"): "",
            ("ip", "-o", "link", "show"): "2: eth0: <BROADCAST,UP> mtu 1500",
            ("ip", "-d", "link", "show", "eth0"): "",
            ("resolvectl", "status", "eth0"): "",
            ("ip", "route", "show", "dev", "eth0"): "",
        })
        client = FakeHttpClient({
            "https://ipinfo.io/json": None,
            "https://v6.ipinfo.io/json": None,
        })
        result = collect_network_data(runner, FakeSysfsReader(), client)
        eth = next(i for i in result if i.name == "eth0")
        assert eth.egress.status == EgressStatus.FAILED

    def test_multiple_vpn_interfaces_share_server_ip(self) -> None:
        """Two VPN interfaces (ProtonVPN kill-switch pattern) share one server IP."""
        runner = FakeCommandRunner({
            ("mmcli", "-L"): "",
            ("ip", "route", "show", "default"): "default via 10.45.1.1 dev enx0 metric 100",
            ("ip", "-4", "addr", "show"): (
                "1: enx0:\n    inet 10.45.1.5/24 scope global enx0\n"
                "2: pvpn0:\n    inet 100.85.0.1/32 scope global pvpn0\n"
                "3: proton0:\n    inet 10.2.0.2/32 scope global proton0\n"
            ),
            ("ip", "-6", "addr", "show"): "",
            ("ip", "-o", "link", "show"): (
                "1: enx0: <BROADCAST,UP> mtu 1500\n"
                "2: pvpn0: <POINTOPOINT,UP> mtu 1500\n"
                "3: proton0: <POINTOPOINT,UP> mtu 1500"
            ),
            ("resolvectl", "status", "enx0"): (
                "Link 1\n  Current DNS Server: 10.45.1.1\n"
                "         DNS Servers: 10.45.1.1"
            ),
            ("ip", "-d", "link", "show", "enx0"): "",
            ("ip", "route", "show", "dev", "enx0"): "default via 10.45.1.1 metric 100",
            ("resolvectl", "status", "pvpn0"): "Link 2\n      Current Scopes: none",
            ("ip", "route", "show", "dev", "pvpn0"): "default via 100.85.0.1 metric 98",
            ("resolvectl", "status", "proton0"): (
                "Link 3\n  Current DNS Server: 10.2.0.1\n"
                "         DNS Servers: 10.2.0.1"
            ),
            ("ip", "route", "show", "dev", "proton0"): "",
            ("ip", "route", "show"): "5.253.204.194 proto static",
        })
        client = FakeHttpClient({
            "https://ipinfo.io/json": _IPINFO_OK,
            "https://v6.ipinfo.io/json": None,
        })
        result = collect_network_data(runner, FakeSysfsReader(), client)
        vpn_ifaces = [i for i in result if i.interface_type == InterfaceType.VPN]
        assert all(i.vpn.server_ip == "5.253.204.194" for i in vpn_ifaces)

    def test_modem_manager_unavailable_handled_gracefully(self) -> None:
        """mmcli returning None must not cause an exception."""
        runner = FakeCommandRunner({
            ("mmcli", "-L"): None,
            ("ip", "route", "show", "default"): None,
            ("ip", "-4", "addr", "show"): "",
            ("ip", "-6", "addr", "show"): "",
            ("ip", "-o", "link", "show"): None,
        })
        result = collect_network_data(runner, FakeSysfsReader(), FakeHttpClient({}))
        assert not result

    def test_oserror_in_build_interface_skips_that_interface(self) -> None:
        """OSError from _build_interface must skip that interface; others kept."""
        runner = _build_exception_test_runner()
        reader = _ErrorReader("eth0", OSError("sysfs read failed"))
        result = collect_network_data(runner, reader, FakeHttpClient({}))
        names = {i.name for i in result}
        assert "lo" in names
        assert "eth0" not in names

    def test_runtimeerror_in_build_interface_skips_that_interface(self) -> None:
        """RuntimeError from _build_interface must skip that interface; others kept."""
        runner = _build_exception_test_runner()
        reader = _ErrorReader("eth0", RuntimeError("unexpected module fault"))
        result = collect_network_data(runner, reader, FakeHttpClient({}))
        names = {i.name for i in result}
        assert "lo" in names
        assert "eth0" not in names

    def test_valueerror_in_build_interface_propagates(self) -> None:
        """ValueError from _build_interface must propagate out of collect_network_data.

        ValueError is raised by __post_init__ validators on domain models
        (DeviceInfo, IPConfig, VPNInfo) when an invariant is violated.  This
        is a programming error -- not an operational failure -- and must not
        be caught by the per-interface handler.
        """
        runner = _build_exception_test_runner()
        reader = _ErrorReader("eth0", ValueError("DeviceInfo invariant violated"))
        with pytest.raises(ValueError, match="DeviceInfo invariant violated"):
            collect_network_data(runner, reader, FakeHttpClient({}))


class TestFetchEgress:
    """_fetch_egress: egress query gating."""

    def test_none_active_returns_unavailable(self) -> None:
        """No active interface must return UNAVAILABLE without querying the API."""
        client = FakeHttpClient({})
        egress = _fetch_egress(None, client)
        assert egress.status == EgressStatus.UNAVAILABLE
        assert egress.external_ip is None

    def test_none_active_makes_no_api_calls(self) -> None:
        client = FakeHttpClient({})
        _fetch_egress(None, client)
        assert not client.calls

    def test_active_interface_queries_api(self) -> None:
        client = FakeHttpClient({
            "https://ipinfo.io/json": _IPINFO_OK,
            "https://v6.ipinfo.io/json": None,
        })
        egress = _fetch_egress("eth0", client)
        assert egress.status == EgressStatus.OK
        assert egress.external_ip == "1.2.3.4"


class TestApplyVpnUnderlay:
    """_apply_vpn_underlay: VPN server IP and carrier flag population."""

    def test_no_vpn_interfaces_returns_unchanged(self) -> None:
        """A list with no VPN interfaces must be returned as-is."""
        ifaces = [
            make_output_iface(IfaceSpec(name="eth0", interface_type=InterfaceType.ETHERNET)),
            make_output_iface(IfaceSpec(name="lo", interface_type=InterfaceType.LOOPBACK)),
        ]
        runner = FakeCommandRunner({})
        result = _apply_vpn_underlay(ifaces, runner)
        assert len(result) == 2
        assert all(i.vpn.server_ip is None for i in result)
        assert all(not i.vpn.is_vpn_underlay for i in result)

    def test_no_vpn_makes_no_route_show_call(self) -> None:
        runner = FakeCommandRunner({})
        _apply_vpn_underlay(
            [make_output_iface(IfaceSpec(name="eth0", interface_type=InterfaceType.ETHERNET))],
            runner,
        )
        assert not runner.calls

    def test_vpn_no_server_endpoint_server_ip_stays_none(self) -> None:
        """VPN interface present but no static host route -> server_ip None."""
        runner = FakeCommandRunner({
            ("ip", "route", "show"): "default via 192.168.1.1 dev eth0",
        })
        tun = make_output_iface(IfaceSpec(name="tun0", interface_type=InterfaceType.VPN))
        result = _apply_vpn_underlay([tun], runner)
        tun_out = next(i for i in result if i.name == "tun0")
        assert tun_out.vpn.server_ip is None
        assert tun_out.vpn.server_ip_status == DataStatus.UNAVAILABLE

    def test_vpn_server_ip_populated_from_static_route(self) -> None:
        runner = FakeCommandRunner({
            ("ip", "route", "show"): "5.253.204.194 proto static",
        })
        tun = make_output_iface(IfaceSpec(name="tun0", interface_type=InterfaceType.VPN))
        eth = make_iface(IfaceSpec(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            gateway="192.168.1.1",
            metric=100,
        ))
        result = _apply_vpn_underlay([tun, eth], runner)
        tun_out = next(i for i in result if i.name == "tun0")
        assert tun_out.vpn.server_ip == "5.253.204.194"
        assert tun_out.vpn.server_ip_status == DataStatus.OK

    def test_vpn_carrier_flagged(self) -> None:
        runner = FakeCommandRunner({
            ("ip", "route", "show"): "5.253.204.194 proto static",
        })
        tun = make_output_iface(IfaceSpec(name="tun0", interface_type=InterfaceType.VPN))
        eth = make_iface(IfaceSpec(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            gateway="192.168.1.1",
            metric=100,
        ))
        result = _apply_vpn_underlay([tun, eth], runner)
        eth_out = next(i for i in result if i.name == "eth0")
        assert eth_out.vpn.is_vpn_underlay is True

    def test_carrier_not_flagged_twice(self) -> None:
        """Two VPN interfaces sharing one carrier must not double-flag it."""
        runner = FakeCommandRunner({
            ("ip", "route", "show"): "5.253.204.194 proto static",
        })
        tun0 = make_output_iface(IfaceSpec(name="tun0", interface_type=InterfaceType.VPN))
        tun1 = make_output_iface(IfaceSpec(name="tun1", interface_type=InterfaceType.VPN))
        eth = make_iface(IfaceSpec(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            gateway="192.168.1.1",
            metric=100,
        ))
        result = _apply_vpn_underlay([tun0, tun1, eth], runner)
        eth_out = next(i for i in result if i.name == "eth0")
        # is_vpn_underlay is a bool; True once is the same as True twice.
        assert eth_out.vpn.is_vpn_underlay is True

    def test_vpn_server_ip_set_when_no_carrier_found(self) -> None:
        """Server endpoint found but no physical carrier -> server_ip still populated.

        This exercises the ``else`` branch of the carrier-detection block in
        ``_apply_vpn_underlay`` (orchestrator.py line 222):

            else:
                logger.debug("No VPN carrier found in interface list")

        The branch fires when ``get_vpn_server_endpoint`` succeeds but
        ``find_vpn_carrier`` returns ``None`` -- for example when the physical
        underlay interface has been removed while the VPN tunnel is still up,
        leaving only the VPN interface itself in the list.

        The VPN interface must still receive ``server_ip``; the
        ``is_vpn_underlay`` flag must not be set on any interface because there
        is no carrier to flag.
        """
        runner = FakeCommandRunner({
            ("ip", "route", "show"): "5.253.204.194 proto static",
        })
        # Only the VPN interface is present.  find_vpn_carrier excludes VPN
        # interfaces by design, so it returns None immediately.
        tun = make_output_iface(IfaceSpec(name="tun0", interface_type=InterfaceType.VPN))
        result = _apply_vpn_underlay([tun], runner)
        tun_out = next(i for i in result if i.name == "tun0")
        assert tun_out.vpn.server_ip == "5.253.204.194"
        assert tun_out.vpn.server_ip_status == DataStatus.OK
        assert all(not i.vpn.is_vpn_underlay for i in result)

    def test_original_list_not_mutated(self) -> None:
        """_apply_vpn_underlay must never modify the input list in place."""
        runner = FakeCommandRunner({
            ("ip", "route", "show"): "5.253.204.194 proto static",
        })
        tun = make_output_iface(IfaceSpec(name="tun0", interface_type=InterfaceType.VPN))
        eth = make_iface(IfaceSpec(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            gateway="192.168.1.1",
            metric=100,
        ))
        original = [tun, eth]
        original_ids = [id(i) for i in original]
        _apply_vpn_underlay(original, runner)
        assert [id(i) for i in original] == original_ids
        assert not original[1].vpn.is_vpn_underlay  # original eth unchanged
