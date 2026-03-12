"""Tests for netcheck.network.dns.

Key design: leak classification uses current_server (what is *actively*
resolving) not servers (what is *configured*).  A dormant interface --
one whose current_server is None even though servers is non-empty -- is
not leaking because it is not resolving any queries.
"""

import pytest

from netcheck.core.enums import DataStatus, DnsLeakStatus, InterfaceType
from netcheck.core.models import (
    DNSConfig,
    DeviceInfo,
    InterfaceInfo,
)
from netcheck.network.dns import check_dns_leaks, get_interface_dns
from tests.fakes import FakeCommandRunner
from tests.helpers import IfaceSpec, make_iface


def _iface(
    name: str,
    iface_type: InterfaceType,
    dns_servers: tuple[str, ...] = (),
    current_server: str | None = None,
) -> InterfaceInfo:
    """Build a minimal InterfaceInfo for DNS leak-detection tests."""
    return make_iface(IfaceSpec(
        name=name,
        interface_type=iface_type,
        device=DeviceInfo.not_applicable(),
        dns_servers=dns_servers,
        current_server=current_server,
    ))


class TestGetInterfaceDns:
    """get_interface_dns must return DNSConfig with query_status set."""

    def test_returns_dns_config(self) -> None:
        """Return type must be DNSConfig."""
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"):
             "         DNS Servers: 192.168.1.1\n  Current DNS Server: 192.168.1.1"}
        )
        result = get_interface_dns("eth0", runner)
        assert isinstance(result, DNSConfig)

    def test_server_extracted(self) -> None:
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"):
             "         DNS Servers: 192.168.1.1\n  Current DNS Server: 192.168.1.1"}
        )
        result = get_interface_dns("eth0", runner)
        assert "192.168.1.1" in result.servers

    def test_current_server_extracted(self) -> None:
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"):
             "         DNS Servers: 192.168.1.1\n  Current DNS Server: 192.168.1.1"}
        )
        assert get_interface_dns("eth0", runner).current_server == "192.168.1.1"

    def test_current_server_none_when_absent(self) -> None:
        """When the Current DNS Server line is missing, current_server is None."""
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"):
             "         DNS Servers: 192.168.1.1"}
        )
        assert get_interface_dns("eth0", runner).current_server is None

    def test_status_ok_when_servers_found(self) -> None:
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"):
             "         DNS Servers: 192.168.1.1\n  Current DNS Server: 192.168.1.1"}
        )
        assert get_interface_dns("eth0", runner).query_status == DataStatus.OK

    def test_status_unavailable_when_no_servers(self) -> None:
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"): "Link 2 (eth0)\n      Current Scopes: none"}
        )
        result = get_interface_dns("eth0", runner)
        assert result.query_status == DataStatus.UNAVAILABLE
        assert not result.servers

    def test_command_failure_is_error_status(self) -> None:
        """Runner returning None (subprocess failed) must yield ERROR.

        ``None`` is the contract signal for a subprocess failure, timeout,
        or missing executable.  It must be classified ``DataStatus.ERROR``,
        not ``UNAVAILABLE``.  See ADR-008 Decision section 3.
        """
        runner = FakeCommandRunner({("resolvectl", "status", "eth0"): None})
        result = get_interface_dns("eth0", runner)
        assert result.query_status == DataStatus.ERROR
        assert not result.servers

    def test_empty_output_is_unavailable_not_error(self) -> None:
        """Runner returning '' (command succeeded, no output) must yield UNAVAILABLE.

        ``resolvectl status <iface>`` can return an empty string when the
        interface has no DNS configuration at all.  The command ran
        successfully and produced no DNS entries -- that is
        ``DataStatus.UNAVAILABLE``, not a runner failure
        (``DataStatus.ERROR``).

        ADR-008 Decision section 3: ``if output is None`` is the ERROR
        gate.  An empty string falls through to the parsing branch, which
        produces no servers and no current_server; the function then
        returns ``UNAVAILABLE`` via the ``DataStatus.OK if servers else
        DataStatus.UNAVAILABLE`` expression.

        This test would have failed before the fix because the old
        ``if not output:`` guard treated ``""`` and ``None`` identically,
        returning ``DataStatus.ERROR`` for both.
        """
        runner = FakeCommandRunner({("resolvectl", "status", "eth0"): ""})
        result = get_interface_dns("eth0", runner)
        assert result.query_status == DataStatus.UNAVAILABLE
        assert not result.servers
        assert result.current_server is None

    def test_leak_status_placeholder(self) -> None:
        """get_interface_dns sets leak_status to NOT_APPLICABLE (placeholder)."""
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"):
             "         DNS Servers: 192.168.1.1\n  Current DNS Server: 192.168.1.1"}
        )
        assert get_interface_dns("eth0", runner).leak_status == DnsLeakStatus.NOT_APPLICABLE

    def test_servers_is_tuple(self) -> None:
        runner = FakeCommandRunner(
            {("resolvectl", "status", "eth0"):
             "         DNS Servers: 1.1.1.1\n  Current DNS Server: 1.1.1.1"}
        )
        assert isinstance(get_interface_dns("eth0", runner).servers, tuple)


class TestCheckDnsLeaks:
    """check_dns_leaks must return a new list with leak_status populated."""

    def test_returns_new_list(self) -> None:
        ifaces = [_iface("lo", InterfaceType.LOOPBACK)]
        assert check_dns_leaks(ifaces) is not ifaces

    def test_originals_not_mutated(self) -> None:
        eth = _iface("eth0", InterfaceType.ETHERNET, ("192.168.1.1",),
                     current_server="192.168.1.1")
        original_status = eth.dns.leak_status
        check_dns_leaks([eth])
        assert eth.dns.leak_status == original_status

    def test_no_vpn_all_no_vpn_status(self) -> None:
        # When no VPN interface exists, vpn_dns is empty -> NO_VPN.
        eth = _iface("eth0", InterfaceType.ETHERNET, ("192.168.1.1",),
                     current_server="192.168.1.1")
        result = check_dns_leaks([eth])
        assert result[0].dns.leak_status == DnsLeakStatus.NO_VPN

    def test_vpn_dns_gets_ok(self) -> None:
        # VPN interface with an active current_server in vpn_dns -> OK.
        eth = _iface("eth0", InterfaceType.ETHERNET, ("192.168.1.1",),
                     current_server="192.168.1.1")
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([eth, tun])
        tun_out = next(r for r in result if r.name == "tun0")
        assert tun_out.dns.leak_status == DnsLeakStatus.OK

    def test_isp_dns_active_on_vpn_is_leak(self) -> None:
        # VPN interface actively using an ISP DNS address -> LEAK.
        eth = _iface("eth0", InterfaceType.ETHERNET, ("192.168.1.1",),
                     current_server="192.168.1.1")
        tun = _iface("tun0", InterfaceType.VPN, ("192.168.1.1",),
                     current_server="192.168.1.1")
        result = check_dns_leaks([eth, tun])
        tun_out = next(r for r in result if r.name == "tun0")
        assert tun_out.dns.leak_status == DnsLeakStatus.LEAK

    def test_dormant_physical_not_a_leak(self) -> None:
        """Physical interface with ISP servers configured but current_server=None
        must be classified as DORMANT, not LEAK and not NOT_APPLICABLE.

        DORMANT is the correct status: a VPN is active and systemd-resolved
        has correctly shifted DNS activity to the VPN interface.  The
        interface is not leaking because it is not resolving any queries,
        and the VPN precondition IS met -- so NOT_APPLICABLE would be
        inaccurate."""
        # wifi has ISP DNS configured but is dormant (current_server=None)
        wifi = _iface("wlp1s0", InterfaceType.WIRELESS, ("192.168.1.1",),
                      current_server=None)
        # VPN interface is actively resolving
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([wifi, tun])
        wifi_out = next(r for r in result if r.name == "wlp1s0")
        assert wifi_out.dns.leak_status == DnsLeakStatus.DORMANT, (
            "Dormant physical interface must be DORMANT, not NOT_APPLICABLE or LEAK"
        )

    def test_physical_active_on_vpn_is_leak(self) -> None:
        """Physical interface that still has an active current_server while VPN
        is running IS a genuine leak and must be classified LEAK."""
        wifi = _iface("wlp1s0", InterfaceType.WIRELESS, ("192.168.1.1",),
                      current_server="192.168.1.1")
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([wifi, tun])
        wifi_out = next(r for r in result if r.name == "wlp1s0")
        assert wifi_out.dns.leak_status == DnsLeakStatus.LEAK


class TestDormantClassification:
    """check_dns_leaks: DORMANT classification and its distinction from NOT_APPLICABLE.

    DORMANT means: a VPN is active AND this DNS-provider interface has no
    current DNS activity (current_server is None).
    NOT_APPLICABLE means: the interface type is not a DNS provider (loopback,
    VPN, bridge, virtual, unknown), or it is a DNS-provider type that has no
    DNS activity and no VPN is stepping it aside.
    NO_VPN means: no VPN is active system-wide; leak detection has nothing to
    compare against.
    These are three distinct facts about the system and must not be aliased.
    """

    def test_dormant_when_vpn_active_and_no_current_server(self) -> None:
        """Interface with servers configured but current_server=None while VPN
        is active must be DORMANT."""
        eth = _iface("eth0", InterfaceType.ETHERNET, ("192.168.1.1",),
                     current_server=None)
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([eth, tun])
        eth_out = next(r for r in result if r.name == "eth0")
        assert eth_out.dns.leak_status == DnsLeakStatus.DORMANT

    def test_no_vpn_status_when_no_vpn_and_no_current_server(self) -> None:
        """Interface with no current_server and NO VPN active must be
        NO_VPN, not DORMANT.  The VPN precondition is not met."""
        eth = _iface("eth0", InterfaceType.ETHERNET, ("192.168.1.1",),
                     current_server=None)
        # no VPN interface in the list
        result = check_dns_leaks([eth])
        eth_out = result[0]
        assert eth_out.dns.leak_status == DnsLeakStatus.NO_VPN

    def test_loopback_is_not_applicable_when_vpn_active(self) -> None:
        """Loopback must be NOT_APPLICABLE even when a VPN is active.

        Loopback is not a DNS provider type and cannot step aside for a VPN.
        """
        lo = _iface("lo", InterfaceType.LOOPBACK)  # servers=(), current_server=None
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([lo, tun])
        lo_out = next(r for r in result if r.name == "lo")
        assert lo_out.dns.leak_status == DnsLeakStatus.NOT_APPLICABLE

    def test_vpn_without_current_server_is_not_applicable(self) -> None:
        """A VPN interface with no active current_server must be NOT_APPLICABLE.

        VPN is not a DNS provider type.  An interface like pvpnksintrf0 that
        acts as a kill-switch (no current_server) must not be labelled DORMANT
        -- that status is reserved for physical interfaces that have stepped
        aside for another VPN interface.
        """
        kill_switch = _iface("pvpnksintrf0", InterfaceType.VPN,
                             current_server=None)
        tunnel = _iface("proton0", InterfaceType.VPN, ("10.2.0.1",),
                        current_server="10.2.0.1")
        result = check_dns_leaks([kill_switch, tunnel])
        ks_out = next(r for r in result if r.name == "pvpnksintrf0")
        assert ks_out.dns.leak_status == DnsLeakStatus.NOT_APPLICABLE

    def test_vpn_with_active_current_server_gets_ok(self) -> None:
        """A VPN interface whose current_server is in vpn_dns must get OK.

        proton0-style: VPN interface is the active DNS provider.
        """
        tunnel = _iface("proton0", InterfaceType.VPN, ("10.2.0.1",),
                        current_server="10.2.0.1")
        result = check_dns_leaks([tunnel])
        tunnel_out = result[0]
        assert tunnel_out.dns.leak_status == DnsLeakStatus.OK

    def test_dns_provider_type_with_no_dns_activity_is_not_applicable(self) -> None:
        """A DNS-provider-type interface with no DNS activity must be NOT_APPLICABLE.

        CELLULAR is in _DNS_PROVIDER_TYPES, but a modem with no SIM
        (dns_query_status=UNAVAILABLE, current_server=None) has never provided
        DNS and cannot in its current state.  Labelling it DORMANT would
        misrepresent it as having stepped aside for a VPN, implying prior DNS
        activity that never occurred.
        """
        # No servers, no current_server -> query_status=UNAVAILABLE (simulates
        # a failed modem).  Pass a VPN interface to trigger the DORMANT path
        # for other interfaces.
        modem = _iface("wwp195s0f3u4", InterfaceType.CELLULAR)  # servers=()
        tunnel = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                        current_server="10.8.0.1")
        result = check_dns_leaks([modem, tunnel])
        modem_out = next(r for r in result if r.name == "wwp195s0f3u4")
        assert modem_out.dns.leak_status == DnsLeakStatus.NOT_APPLICABLE

    def test_dormant_interfaces_do_not_trigger_leak_detection(self) -> None:
        """A system with all physical interfaces dormant must have no LEAK
        status -- only DORMANT and OK."""
        wifi = _iface("wlp1s0", InterfaceType.WIRELESS, ("192.168.1.1",),
                      current_server=None)
        eth = _iface("eth0", InterfaceType.ETHERNET, ("10.0.0.1",),
                     current_server=None)
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([wifi, eth, tun])
        statuses = {r.name: r.dns.leak_status for r in result}
        assert statuses["wlp1s0"] == DnsLeakStatus.DORMANT
        assert statuses["eth0"] == DnsLeakStatus.DORMANT
        assert statuses["tun0"] == DnsLeakStatus.OK
        assert DnsLeakStatus.LEAK not in statuses.values()


class TestCheckDnsLeaksExtended:
    """check_dns_leaks: PUBLIC and WARN classifications, multi-server scenarios."""

    @pytest.mark.parametrize("configured, current_server, expected_status", [
        # ISP configured 192.168.1.1; currently resolving via Cloudflare.
        # 1.1.1.1 is a public resolver but NOT in isp_dns -> PUBLIC.
        (("192.168.1.1",), "1.1.1.1",    DnsLeakStatus.PUBLIC),
        # ISP configured 172.31.0.1; currently resolving via an unknown server.
        # 203.0.113.5 is not in isp_dns, vpn_dns, or PUBLIC_DNS_SERVERS -> WARN.
        (("172.31.0.1",), "203.0.113.5", DnsLeakStatus.WARN),
        # ISP configured 192.168.1.1; currently resolving via Google DNS.
        # 8.8.8.8 is public but NOT in isp_dns (ISP did not push it) -> PUBLIC.
        (("192.168.1.1",), "8.8.8.8",    DnsLeakStatus.PUBLIC),
    ])
    def test_physical_dns_status_while_vpn_active(
        self,
        configured: tuple[str, ...],
        current_server: str,
        expected_status: DnsLeakStatus,
    ) -> None:
        """Physical interface DNS classification while VPN is active.

        All cases share the same structure: an ethernet interface with a
        known ISP-configured server that is currently resolving through a
        *different* active server, alongside an active VPN tunnel.  The
        expected status depends on where the active server falls in the
        category hierarchy (isp_dns > vpn_dns > PUBLIC_DNS_SERVERS > WARN).
        """
        eth = _iface("eth0", InterfaceType.ETHERNET, configured,
                     current_server=current_server)
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([eth, tun])
        eth_out = next(r for r in result if r.name == "eth0")
        assert eth_out.dns.leak_status == expected_status

    @pytest.mark.parametrize("iface_name, iface_type, dns_server", [
        ("wwp0", InterfaceType.CELLULAR, "10.0.0.1"),
        ("enx0", InterfaceType.TETHER,   "10.45.1.1"),
    ])
    def test_isp_interface_type_contributes_to_isp_dns(
        self,
        iface_name: str,
        iface_type: InterfaceType,
        dns_server: str,
    ) -> None:
        """Cellular and tether interfaces contribute to isp_dns.

        Both interface types carry ISP-assigned DNS that is NOT the VPN's
        DNS.  When such an interface is the active resolver while the VPN
        is running, it is a genuine DNS leak and must be classified LEAK.
        """
        isp_iface = _iface(iface_name, iface_type, (dns_server,),
                           current_server=dns_server)
        tun = _iface("tun0", InterfaceType.VPN, ("10.8.0.1",),
                     current_server="10.8.0.1")
        result = check_dns_leaks([isp_iface, tun])
        isp_out = next(r for r in result if r.name == iface_name)
        assert isp_out.dns.leak_status == DnsLeakStatus.LEAK


class TestGetInterfaceDnsMultiLine:
    """get_interface_dns: multi-line DNS server list parsing."""

    def test_multiline_servers_all_extracted(self) -> None:
        """DNS servers spanning continuation lines must all be included.

        The real resolvectl output has 'Current DNS Server' BEFORE 'DNS Servers',
        so the continuation-line parser does not accidentally pick up the current
        server line as an extra server entry.
        """
        output = (
            "Link 2 (eth0)\n"
            "  Current DNS Server: 192.168.1.1\n"
            "         DNS Servers: 192.168.1.1\n"
            "                      8.8.8.8\n"
            "          DNS Domain: ~.\n"
        )
        runner = FakeCommandRunner({("resolvectl", "status", "eth0"): output})
        result = get_interface_dns("eth0", runner)
        assert "192.168.1.1" in result.servers
        assert "8.8.8.8" in result.servers
        assert len(result.servers) == 2

    def test_ipv6_dns_server_extracted(self) -> None:
        """IPv6 DNS server addresses must be extracted correctly."""
        output = (
            "Link 2 (eth0)\n"
            "  Current DNS Server: fdc5:1883:2846:0::1\n"
            "         DNS Servers: fdc5:1883:2846:0::1\n"
        )
        runner = FakeCommandRunner({("resolvectl", "status", "eth0"): output})
        result = get_interface_dns("eth0", runner)
        assert "fdc5:1883:2846:0::1" in result.servers
        assert result.current_server == "fdc5:1883:2846:0::1"

    def test_servers_section_stops_at_non_indented_line(self) -> None:
        """A non-indented line after the DNS Servers block must end the section.

        The continuation-line loop uses ``line.startswith(" ")`` to identify
        extra server addresses.  When a non-indented line appears (e.g. a
        ``Protocols:`` header), the loop must ``break`` immediately.  Lines
        after the break must not be parsed as server addresses -- even if they
        happen to contain IP-like strings.

        This exercises the ``break`` at line 174 of dns.py
        (``elif in_section: if line.startswith(" "): ... else: break``).
        """
        output = (
            "         DNS Servers: 192.168.1.1\n"
            "                      8.8.8.8\n"
            "Protocols: +DefaultRoute\n"  # non-indented: must stop the section
            "         DNS Servers: 10.0.0.1\n"  # must NOT be parsed
        )
        runner = FakeCommandRunner({("resolvectl", "status", "eth0"): output})
        result = get_interface_dns("eth0", runner)
        assert "192.168.1.1" in result.servers
        assert "8.8.8.8" in result.servers
        assert "10.0.0.1" not in result.servers, (
            "Servers after a non-indented line must be ignored once break fires"
        )

    def test_current_dns_server_line_with_no_ip_yields_none(self) -> None:
        """A ``Current DNS Server:`` line whose remainder contains no parseable
        IP must not crash -- ``current_server`` must be ``None``.

        systemd-resolved can emit ``Current DNS Server: (none)`` or an empty
        field when the interface has no active resolver.  The parser must
        tolerate this and fall through to ``return None``.

        This exercises the ``if ips:`` false branch at line 192 of dns.py.
        """
        output = (
            "Link 2 (eth0)\n"
            "  Current DNS Server: (none)\n"
            "         DNS Servers: 192.168.1.1\n"
        )
        runner = FakeCommandRunner({("resolvectl", "status", "eth0"): output})
        result = get_interface_dns("eth0", runner)
        assert result.current_server is None
        assert "192.168.1.1" in result.servers
