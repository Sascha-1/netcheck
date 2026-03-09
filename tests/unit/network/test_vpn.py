"""Smoke tests for netcheck.network.vpn.

``get_vpn_server_endpoint`` detects the VPN server by parsing static host
routes from ``ip route show``.  VPN clients must inject a bypass route for
the server so that server-bound traffic does not recurse through the tunnel;
this route is protocol-agnostic and readable without elevated privileges.

``find_vpn_carrier`` identifies the physical interface carrying VPN traffic
by selecting the lowest-metric gateway-bearing interface from the collected
interface list.

``get_vpn_server_endpoint`` returns a ``(server_ip, DataStatus)`` tuple:
``OK`` with the IP when a route is found, ``UNAVAILABLE`` when the command
ran but found no qualifying route, ``ERROR`` when the command failed.
"""

from netcheck.core.enums import DataStatus, InterfaceType
from netcheck.core.models import (
    DeviceInfo,
    InterfaceInfo,
)
from netcheck.network.vpn import find_vpn_carrier, get_vpn_server_endpoint, is_private_or_cgnat
from tests.fakes import FakeCommandRunner
from tests.helpers import IfaceSpec, make_iface


def _physical_iface(
    name: str,
    iface_type: InterfaceType,
    gateway: str | None,
    metric: int | None,
) -> InterfaceInfo:
    """Build a minimal InterfaceInfo for VPN carrier-detection tests."""
    return make_iface(IfaceSpec(
        name=name,
        interface_type=iface_type,
        device=DeviceInfo.not_applicable(),
        gateway=gateway,
        metric=metric,
    ))


class TestGetVpnServerEndpoint:
    """get_vpn_server_endpoint takes only runner and reads ip route show."""

    def test_static_host_route_detected(self) -> None:
        """A 'proto static' host route to a public IP must be returned."""
        output = (
            "5.253.204.194 via 192.168.1.1 dev eth0 proto static\n"
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100"
        )
        runner = FakeCommandRunner({("ip", "route", "show"): output})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip == "5.253.204.194"
        assert status == DataStatus.OK

    def test_private_destination_excluded(self) -> None:
        """A static host route to a private IP must not be returned."""
        output = "192.168.50.1 via 192.168.1.1 dev eth0 proto static"
        runner = FakeCommandRunner({("ip", "route", "show"): output})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_non_static_proto_excluded(self) -> None:
        """Routes with proto kernel/dhcp/etc must be ignored."""
        output = "203.0.113.5 via 192.168.1.1 dev eth0 proto kernel"
        runner = FakeCommandRunner({("ip", "route", "show"): output})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_default_route_ignored(self) -> None:
        """The default route must never be returned as the VPN endpoint."""
        output = "default via 192.168.1.1 dev eth0 proto static"
        runner = FakeCommandRunner({("ip", "route", "show"): output})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_command_failure_returns_none_and_error(self) -> None:
        """Command failure must return None and DataStatus.ERROR."""
        runner = FakeCommandRunner({("ip", "route", "show"): None})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.ERROR

    def test_no_qualifying_routes_returns_none_and_unavailable(self) -> None:
        """Output with no static host routes must return None and UNAVAILABLE."""
        runner = FakeCommandRunner({("ip", "route", "show"): ""})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE


class TestFindVpnCarrier:
    """find_vpn_carrier selects the lowest-metric physical interface."""

    def test_single_physical_interface_returned(self) -> None:
        eth = _physical_iface("eth0", InterfaceType.ETHERNET, "192.168.1.1", 100)
        assert find_vpn_carrier([eth]) == "eth0"

    def test_lowest_metric_wins(self) -> None:
        eth = _physical_iface("eth0", InterfaceType.ETHERNET, "192.168.1.1", 100)
        wlan = _physical_iface("wlan0", InterfaceType.WIRELESS, "192.168.1.1", 50)
        assert find_vpn_carrier([eth, wlan]) == "wlan0"

    def test_interface_without_gateway_excluded(self) -> None:
        eth = _physical_iface("eth0", InterfaceType.ETHERNET, None, None)
        assert find_vpn_carrier([eth]) is None

    def test_vpn_interface_not_carrier(self) -> None:
        tun = _physical_iface("tun0", InterfaceType.VPN, "10.8.0.1", 50)
        eth = _physical_iface("eth0", InterfaceType.ETHERNET, "192.168.1.1", 100)
        assert find_vpn_carrier([tun, eth]) == "eth0"

    def test_empty_list_returns_none(self) -> None:
        assert find_vpn_carrier([]) is None


class TestIsPrivateOrCgnat:
    """is_private_or_cgnat classifies addresses."""

    def test_rfc1918_10_is_private(self) -> None:
        assert is_private_or_cgnat("10.8.0.1") is True

    def test_rfc1918_192_is_private(self) -> None:
        assert is_private_or_cgnat("192.168.1.1") is True

    def test_cgnat_is_excluded(self) -> None:
        assert is_private_or_cgnat("100.64.1.1") is True

    def test_public_is_not_private(self) -> None:
        assert is_private_or_cgnat("5.253.204.194") is False

    def test_invalid_string_returns_true(self) -> None:
        """Conservative fail-safe: unparseable input must return True."""
        assert is_private_or_cgnat("not-an-ip") is True


class TestGetVpnServerEndpointExtended:
    """get_vpn_server_endpoint: additional filtering cases."""

    def test_private_ip_host_route_skipped(self) -> None:
        """A static host route to a private IP must not be returned."""
        runner = FakeCommandRunner({("ip", "route", "show"): "192.168.1.1 proto static"})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_cgnat_ip_skipped(self) -> None:
        """CGNAT addresses (100.64.0.0/10) must not be returned as VPN servers."""
        runner = FakeCommandRunner({("ip", "route", "show"): "100.85.0.1 proto static"})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_route_without_proto_field_skipped(self) -> None:
        """Host route lacking 'proto' keyword must be skipped."""
        runner = FakeCommandRunner(
            {("ip", "route", "show"): "5.253.204.194 dev eth0 scope link"}
        )
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_proto_dhcp_not_static_skipped(self) -> None:
        """Host route with proto=dhcp (not static) must be skipped."""
        runner = FakeCommandRunner({("ip", "route", "show"): "5.253.204.194 proto dhcp"})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_default_route_line_skipped(self) -> None:
        """The 'default' route line must be skipped regardless of proto."""
        runner = FakeCommandRunner(
            {("ip", "route", "show"): "default via 192.168.1.1 dev eth0 proto static"}
        )
        ip, status = get_vpn_server_endpoint(runner)
        assert ip is None
        assert status == DataStatus.UNAVAILABLE

    def test_explicit_slash32_accepted(self) -> None:
        """A /32 host route with proto static must be returned."""
        runner = FakeCommandRunner({("ip", "route", "show"): "5.253.204.194/32 proto static"})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip == "5.253.204.194"
        assert status == DataStatus.OK

    def test_subnet_route_skipped_host_route_found(self) -> None:
        """A subnet route (non-host destination) must be skipped; the parser
        must continue to find the valid static host route on the next line.

        ``ip route show`` output typically contains subnet routes (e.g.
        ``192.168.1.0/24``) interleaved with host routes.  ``_HOST_ROUTE_RE``
        only matches bare IPv4 hosts (no prefix, or explicit ``/32``), so the
        subnet line must hit the ``continue`` branch and not prevent the
        following host route from being returned.

        This exercises the ``continue`` at line 131 of vpn.py
        (the ``if not match: continue`` branch in the route-parsing loop).
        """
        output = (
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100\n"
            "5.253.204.194 via 192.168.1.1 dev eth0 proto static\n"
        )
        runner = FakeCommandRunner({("ip", "route", "show"): output})
        ip, status = get_vpn_server_endpoint(runner)
        assert ip == "5.253.204.194"
        assert status == DataStatus.OK


class TestIsPrivateOrCgnatExtended:
    """is_private_or_cgnat: IP range coverage beyond the base test class."""

    def test_rfc1918_10_block(self) -> None:
        assert is_private_or_cgnat("10.0.0.1") is True

    def test_rfc1918_172_block(self) -> None:
        assert is_private_or_cgnat("172.16.0.1") is True

    def test_rfc1918_192_168_block(self) -> None:
        assert is_private_or_cgnat("192.168.1.1") is True

    def test_loopback_is_private(self) -> None:
        assert is_private_or_cgnat("127.0.0.1") is True

    def test_link_local_is_private(self) -> None:
        assert is_private_or_cgnat("169.254.1.1") is True

    def test_cgnat_range(self) -> None:
        assert is_private_or_cgnat("100.85.0.1") is True

    def test_public_ip_is_not_private(self) -> None:
        assert is_private_or_cgnat("5.253.204.194") is False

    def test_unparseable_returns_true(self) -> None:
        """An unparseable address string must return True (conservative fail-safe)."""
        assert is_private_or_cgnat("not_an_ip") is True

    def test_ipv6_loopback_is_private(self) -> None:
        assert is_private_or_cgnat("::1") is True

    def test_ipv6_ula_is_private(self) -> None:
        assert is_private_or_cgnat("fc00::1") is True

    def test_ipv6_link_local_is_private(self) -> None:
        assert is_private_or_cgnat("fe80::1") is True

    def test_ipv6_public_is_not_private(self) -> None:
        assert is_private_or_cgnat("2001:ac8:8:3::14") is False
