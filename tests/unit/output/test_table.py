"""Smoke tests for netcheck.output.table.

Covers ``render_table`` (pure string output) and ``format_table`` (I/O
wrapper), the DataStatus-aware field renderers, the color priority chain,
and the DNS dormant-server display convention.
"""

import dataclasses
import io

from netcheck.core.enums import DataStatus, DnsLeakStatus, EgressStatus, InterfaceType
from netcheck.core.models import (
    DNSConfig,
    DeviceInfo,
    EgressInfo,
    IPConfig,
    RoutingInfo,
)
from netcheck.output.table import (
    _CYAN,
    _GREEN,
    _MAGENTA,
    _RED,
    _RESET,
    _WIDTH,
    _YELLOW,
    _egress_country,
    _egress_ipv4,
    _egress_ipv6,
    _egress_isp,
    _render_device,
    _render_dns_server,
    _render_gateway,
    _render_ipv4,
    _render_ipv6,
    _render_metric,
    _row_color,
    format_table,
    render_table,
)
from tests.helpers import IfaceSpec, make_output_iface


class TestRowColor:
    """_row_color priority chain."""

    def test_leak_gets_magenta(self) -> None:
        iface = make_output_iface(IfaceSpec(leak=DnsLeakStatus.LEAK, egress_status=EgressStatus.OK))
        assert _row_color(iface) == _MAGENTA

    def test_warn_gets_yellow(self) -> None:
        assert _row_color(make_output_iface(IfaceSpec(leak=DnsLeakStatus.WARN))) == _YELLOW

    def test_vpn_ok_dns_gets_green(self) -> None:
        """A VPN interface with server_ip set and DNS OK must be GREEN.

        server_ip is the authoritative gate: it confirms the orchestrator
        detected a live static host route to the VPN endpoint.
        dns.leak_status=OK means DNS queries are actively resolved through
        the VPN provider -- the ideal, fully-confirmed tunnel state.
        """
        iface = make_output_iface(IfaceSpec(
            interface_type=InterfaceType.VPN,
            leak=DnsLeakStatus.OK,
            server_ip="5.253.204.194",
        ))
        assert _row_color(iface) == _GREEN

    def test_is_vpn_underlay_gets_cyan(self) -> None:
        assert _row_color(make_output_iface(IfaceSpec(is_vpn_underlay=True))) == _CYAN

    def test_direct_internet_gets_red(self) -> None:
        assert _row_color(make_output_iface(IfaceSpec(egress_status=EgressStatus.OK))) == _RED

    def test_loopback_no_color(self) -> None:
        iface = make_output_iface(IfaceSpec(
            interface_type=InterfaceType.LOOPBACK,
            egress_status=EgressStatus.UNAVAILABLE,
        ))
        assert _row_color(iface) == ""

    def test_leak_beats_is_vpn_underlay(self) -> None:
        iface = make_output_iface(IfaceSpec(leak=DnsLeakStatus.LEAK, is_vpn_underlay=True))
        assert _row_color(iface) == _MAGENTA


class TestFormatTable:
    """format_table smoke tests."""

    def test_returns_str(self) -> None:
        result = render_table([make_output_iface(IfaceSpec())])
        assert isinstance(result, str)

    def test_ends_with_newline(self) -> None:
        """render_table contract: result ends with a trailing newline."""
        result = render_table([make_output_iface(IfaceSpec())])
        assert result.endswith("\n")

    def test_empty_list_produces_header(self) -> None:
        result = render_table([])
        assert "INTERFACE" in result

    def test_interface_name_appears(self) -> None:
        result = render_table([make_output_iface(IfaceSpec(name="wlp1s0"))])
        assert "wlp1s0" in result

    def test_legend_present(self) -> None:
        result = render_table([make_output_iface(IfaceSpec())])
        assert "Legend:" in result

    def test_colored_row_contains_ansi_codes(self) -> None:
        """A RED interface row must contain the color and reset codes."""
        result = render_table([make_output_iface(IfaceSpec(egress_status=EgressStatus.OK))])
        assert _RED in result
        assert _RESET in result

    def test_no_color_row_has_no_leading_ansi(self) -> None:
        """A loopback row must not be wrapped in any color code.

        The full render_table output always contains ANSI codes in the legend,
        so this test isolates just the data row by finding the line that begins
        with the interface name and verifying it has no leading escape sequence.
        """
        iface = make_output_iface(IfaceSpec(
            name="lo",
            interface_type=InterfaceType.LOOPBACK,
            egress_status=EgressStatus.UNAVAILABLE,
        ))
        result = render_table([iface])
        # The data row starts with the (padded) interface name, not an ESC byte.
        data_row = next(
            line for line in result.splitlines()
            if line.startswith("lo")
        )
        assert not data_row.startswith("\033"), (
            f"loopback row should have no leading ANSI code, got: {data_row!r}"
        )

    def test_format_table_writes_render_table_output(self) -> None:
        """format_table must write exactly what render_table returns."""
        ifaces = [make_output_iface(IfaceSpec(name="eth0"))]
        expected = render_table(ifaces)
        buf = io.StringIO()
        format_table(ifaces, file=buf)
        assert buf.getvalue() == expected

    def test_divider_spans_full_width(self) -> None:
        """The divider line must be exactly _WIDTH characters wide."""
        result = render_table([])
        divider = "=" * _WIDTH
        assert divider in result

    def test_dormant_dns_shown_in_parentheses(self) -> None:
        """A dormant DNS server must appear in parentheses in the rendered table."""
        iface = make_output_iface(IfaceSpec(
            dns_servers=("192.168.1.1",),
            current_server=None,
            leak=DnsLeakStatus.DORMANT,
        ))
        result = render_table([iface])
        assert "(192.168.1.1)" in result

    def test_non_empty_output(self) -> None:
        buf = io.StringIO()
        format_table([make_output_iface(IfaceSpec())], file=buf)
        assert len(buf.getvalue()) > 0

    def test_interface_name_appears_in_format(self) -> None:
        buf = io.StringIO()
        format_table([make_output_iface(IfaceSpec(name="wlp1s0"))], file=buf)
        assert "wlp1s0" in buf.getvalue()

    def test_legend_present_in_format(self) -> None:
        buf = io.StringIO()
        format_table([make_output_iface(IfaceSpec())], file=buf)
        assert "Legend:" in buf.getvalue()

    def test_colored_row_includes_reset(self) -> None:
        """A colored row must include the ANSI reset code."""
        buf = io.StringIO()
        format_table([make_output_iface(IfaceSpec(egress_status=EgressStatus.OK))], file=buf)
        assert _RESET in buf.getvalue()

    def test_empty_list_produces_header_in_format(self) -> None:
        buf = io.StringIO()
        format_table([], file=buf)
        assert "INTERFACE" in buf.getvalue()

    def test_none_ipv4_renders_dash(self) -> None:
        buf = io.StringIO()
        format_table([make_output_iface(IfaceSpec(ipv4=None))], file=buf)
        assert "--" in buf.getvalue()

    def test_none_metric_renders_dash(self) -> None:
        """An interface with no default route has metric '--' in the table."""
        buf = io.StringIO()
        format_table([make_output_iface(IfaceSpec(gateway=None))], file=buf)
        assert "--" in buf.getvalue()


class TestRenderDnsServer:
    """_render_dns_server: active, dormant, absent, and error states."""

    def test_active_server_shown_as_is(self) -> None:
        dns = DNSConfig(
            query_status=DataStatus.OK,
            servers=("10.8.0.1",),
            current_server="10.8.0.1",
            leak_status=DnsLeakStatus.OK,
        )
        assert _render_dns_server(dns) == "10.8.0.1"

    def test_dormant_server_shown_in_parentheses(self) -> None:
        """When current_server is None but servers is non-empty, show first server in ()."""
        dns = DNSConfig(
            query_status=DataStatus.OK,
            servers=("192.168.1.1",),
            current_server=None,
            leak_status=DnsLeakStatus.DORMANT,
        )
        assert _render_dns_server(dns) == "(192.168.1.1)"

    def test_no_servers_shows_dash(self) -> None:
        dns = DNSConfig(
            query_status=DataStatus.UNAVAILABLE,
            servers=(),
            current_server=None,
            leak_status=DnsLeakStatus.NOT_APPLICABLE,
        )
        assert _render_dns_server(dns) == "--"

    def test_error_status_shows_err(self) -> None:
        dns = DNSConfig(
            query_status=DataStatus.ERROR,
            servers=(),
            current_server=None,
            leak_status=DnsLeakStatus.NOT_APPLICABLE,
        )
        assert _render_dns_server(dns) == "ERR"

    def test_active_server_takes_priority_over_dormant(self) -> None:
        """When current_server is set, it is shown directly (not in parentheses)."""
        dns = DNSConfig(
            query_status=DataStatus.OK,
            servers=("10.8.0.1",),
            current_server="10.8.0.1",
            leak_status=DnsLeakStatus.OK,
        )
        result = _render_dns_server(dns)
        assert result == "10.8.0.1"
        assert "(" not in result

    def test_dormant_in_table_output(self) -> None:
        """The full table must show the dormant server in parentheses."""
        iface = make_output_iface(IfaceSpec(
            dns_servers=("192.168.1.1",),
            current_server=None,
            leak=DnsLeakStatus.DORMANT,
        ))
        result = render_table([iface])
        assert "(192.168.1.1)" in result


class TestRenderDevice:
    """_render_device: status-to-string mapping."""

    def test_not_applicable_renders_na(self) -> None:
        assert _render_device(DeviceInfo.not_applicable()) == "N/A"

    def test_unavailable_renders_dash(self) -> None:
        assert _render_device(DeviceInfo.unavailable()) == "--"

    def test_error_renders_err(self) -> None:
        assert _render_device(DeviceInfo.error()) == "ERR"

    def test_ok_renders_cleaned_name(self) -> None:
        device = DeviceInfo.ok("Intel Corporation Ethernet Connection I219-V")
        result = _render_device(device)
        assert "Intel" in result
        assert "Corporation" not in result

    def test_ok_with_usb_name_strips_bus_prefix(self) -> None:
        device = DeviceInfo.ok("Bus 001 Device 005: ID 18d1:4ee3 Google Pixel 6")
        result = _render_device(device)
        assert "Bus 001" not in result
        assert "Google" in result


class TestRenderIPv4IPv6:
    """_render_ipv4 and _render_ipv6: status-to-string mapping."""

    def test_ipv4_ok_renders_address(self) -> None:
        iface = make_output_iface(IfaceSpec(ipv4="192.168.1.10"))
        assert _render_ipv4(iface) == "192.168.1.10"

    def test_ipv4_unavailable_renders_dash(self) -> None:
        iface = make_output_iface(IfaceSpec(ipv4=None))
        assert _render_ipv4(iface) == "--"

    def test_ipv4_error_renders_err(self) -> None:
        iface = make_output_iface(IfaceSpec(ipv4=None))
        # Bypass the spec helper to force ERROR status directly.
        ip_error = IPConfig.error()
        iface = dataclasses.replace(iface, ip=ip_error)
        assert _render_ipv4(iface) == "ERR"

    def test_ipv6_ok_renders_address(self) -> None:
        """_render_ipv6 OK branch: a non-None IPv6 address must be returned as-is.

        ``IfaceSpec`` has no ipv6 field, so the OK path is reached by
        constructing an ``IPConfig`` with both addresses populated and
        splicing it directly onto the interface via ``dataclasses.replace``.

        ``IPConfig.ok(ipv4, ipv6)`` sets ``ipv6_status=OK`` automatically
        when ``ipv6`` is non-None, satisfying the ``__post_init__`` invariant.
        This covers the ``return iface.ip.ipv6`` branch in ``_render_ipv6``
        (table.py line 256) that was previously unreachable from tests.
        """
        iface = make_output_iface(IfaceSpec(ipv4="10.2.0.2"))
        ip_with_v6 = IPConfig.ok("10.2.0.2", "2a07:b944::2:2")
        iface = dataclasses.replace(iface, ip=ip_with_v6)
        assert _render_ipv6(iface) == "2a07:b944::2:2"

    def test_ipv6_unavailable_renders_dash(self) -> None:
        iface = make_output_iface(IfaceSpec(ipv4=None))
        assert _render_ipv6(iface) == "--"

    def test_ipv6_error_renders_err(self) -> None:
        iface = make_output_iface(IfaceSpec())
        ip_error = IPConfig.error()
        iface = dataclasses.replace(iface, ip=ip_error)
        assert _render_ipv6(iface) == "ERR"


class TestRenderGateway:
    """_render_gateway: status-to-string mapping."""

    def test_not_applicable_renders_na(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.NOT_APPLICABLE, gateway=None, metric=None
        )
        assert _render_gateway(routing) == "N/A"

    def test_error_renders_err(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.ERROR, gateway=None, metric=None
        )
        assert _render_gateway(routing) == "ERR"

    def test_unavailable_renders_dash(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.UNAVAILABLE, gateway=None, metric=None
        )
        assert _render_gateway(routing) == "--"

    def test_ok_with_gateway_renders_ip(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.OK, gateway="192.168.1.1", metric=100
        )
        assert _render_gateway(routing) == "192.168.1.1"

    def test_ok_without_gateway_renders_dash(self) -> None:
        """OK status with gateway=None means a directly-connected route; render '--'."""
        routing = RoutingInfo(
            query_status=DataStatus.OK, gateway=None, metric=0
        )
        assert _render_gateway(routing) == "--"


class TestRenderMetric:
    """_render_metric: status-to-string mapping."""

    def test_not_applicable_renders_na(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.NOT_APPLICABLE, gateway=None, metric=None
        )
        assert _render_metric(routing) == "N/A"

    def test_error_renders_err(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.ERROR, gateway=None, metric=None
        )
        assert _render_metric(routing) == "ERR"

    def test_unavailable_renders_dash(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.UNAVAILABLE, gateway=None, metric=None
        )
        assert _render_metric(routing) == "--"

    def test_ok_explicit_metric(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.OK, gateway="192.168.1.1", metric=100
        )
        assert _render_metric(routing) == "100"

    def test_ok_zero_metric(self) -> None:
        routing = RoutingInfo(
            query_status=DataStatus.OK, gateway="192.168.1.1", metric=0
        )
        assert _render_metric(routing) == "0"

    def test_ok_none_metric_renders_zero(self) -> None:
        """OK with metric=None means the kernel implicitly used 0; render '0'."""
        routing = RoutingInfo(
            query_status=DataStatus.OK, gateway="192.168.1.1", metric=None
        )
        assert _render_metric(routing) == "0"


class TestEgressRenderers:
    """_egress_* renderers: FAILED, UNAVAILABLE, and OK states."""

    def test_egress_ipv4_failed_renders_err(self) -> None:
        assert _egress_ipv4(EgressInfo.create_failed()) == "ERR"

    def test_egress_ipv6_failed_renders_err(self) -> None:
        assert _egress_ipv6(EgressInfo.create_failed()) == "ERR"

    def test_egress_isp_failed_renders_err(self) -> None:
        assert _egress_isp(EgressInfo.create_failed()) == "ERR"

    def test_egress_country_failed_renders_err(self) -> None:
        assert _egress_country(EgressInfo.create_failed()) == "ERR"

    def test_egress_ipv4_unavailable_renders_dash(self) -> None:
        assert _egress_ipv4(EgressInfo.create_unavailable()) == "--"

    def test_egress_ipv6_ok_with_address(self) -> None:
        egress = EgressInfo(
            status=EgressStatus.OK,
            external_ip="1.2.3.4",
            external_ipv6="2001:db8::1",
            isp="AS1 ISP",
            country="DE",
        )
        assert _egress_ipv6(egress) == "2001:db8::1"

    def test_egress_ipv6_ok_no_ipv6_renders_dash(self) -> None:
        egress = EgressInfo(
            status=EgressStatus.OK,
            external_ip="1.2.3.4",
            external_ipv6=None,
            isp="AS1 ISP",
            country="DE",
        )
        assert _egress_ipv6(egress) == "--"


class TestRowColorExtended:
    """_row_color: additional edge cases for VPN and dormant states."""

    def test_dormant_gets_no_color(self) -> None:
        """A physical DORMANT interface must not receive any color.

        DORMANT means a VPN is active and this interface correctly stepped
        aside -- it is not resolving queries and requires no user attention.
        """
        iface = make_output_iface(IfaceSpec(leak=DnsLeakStatus.DORMANT))
        assert _row_color(iface) == ""

    def test_not_applicable_gets_no_color(self) -> None:
        """NOT_APPLICABLE (interface excluded from leak detection) must produce no color."""
        iface = make_output_iface(IfaceSpec(leak=DnsLeakStatus.NOT_APPLICABLE))
        assert _row_color(iface) == ""

    def test_no_vpn_gets_no_color(self) -> None:
        """NO_VPN (no VPN active system-wide) must also produce no color.

        NO_VPN falls through all explicit leak-status branches in _row_color
        because none of LEAK/WARN/PUBLIC/OK apply.  An interface with NO_VPN
        and no egress activity has no color.
        """
        iface = make_output_iface(IfaceSpec(leak=DnsLeakStatus.NO_VPN))
        assert _row_color(iface) == ""

    def test_kill_switch_vpn_not_green(self) -> None:
        """A VPN kill-switch interface (NOT_APPLICABLE DNS, egress OK) must not be GREEN.

        Kill-switch interfaces (pvpnksintrf0) have ``dns_leak_status=NOT_APPLICABLE``
        because the VPN type is excluded from DNS provider checks.  GREEN is
        only awarded when ``dns_leak_status=OK``; falling through all checks
        with egress=OK on a VPN interface correctly produces no color.
        """
        iface = make_output_iface(IfaceSpec(
            interface_type=InterfaceType.VPN,
            leak=DnsLeakStatus.NOT_APPLICABLE,
            egress_status=EgressStatus.OK,
            server_ip="5.253.204.194",
        ))
        assert _row_color(iface) == ""

    def test_kill_switch_with_dormant_dns_not_green(self) -> None:
        """A VPN kill-switch interface with DORMANT DNS must also not be GREEN.

        Belt-and-suspenders: even if a VPN interface somehow received DORMANT
        status (e.g. from a future code path), it must not be colored GREEN.
        """
        iface = make_output_iface(IfaceSpec(
            interface_type=InterfaceType.VPN,
            leak=DnsLeakStatus.DORMANT,
            egress_status=EgressStatus.OK,
            server_ip="5.253.204.194",
        ))
        assert _row_color(iface) == ""

    def test_vpn_tunnel_with_ok_dns_gets_green(self) -> None:
        """A VPN tunnel with server_ip set and DNS OK must be GREEN.

        This is the proton0 scenario: the real tunnel with active VPN DNS.
        server_ip is set, DNS is actively resolving through the VPN provider.
        """
        iface = make_output_iface(IfaceSpec(
            interface_type=InterfaceType.VPN,
            leak=DnsLeakStatus.OK,
            egress_status=EgressStatus.UNAVAILABLE,
            server_ip="5.253.204.194",
        ))
        assert _row_color(iface) == _GREEN

    def test_vpn_with_external_dns_not_green(self) -> None:
        """A VPN interface whose DNS is NOT_APPLICABLE must not be GREEN,
        even when egress is OK and server_ip is confirmed.

        VPN interfaces without an active systemd-resolved current_server
        receive dns_leak_status=NOT_APPLICABLE regardless of whether they
        are a kill-switch or using an external resolver (/etc/resolv.conf).
        These two scenarios are indistinguishable at the leak_status level.
        The conservative choice is to require DNS OK for GREEN -- egress OK
        alone is not a sufficient signal for a VPN interface.
        """
        iface = make_output_iface(IfaceSpec(
            interface_type=InterfaceType.VPN,
            leak=DnsLeakStatus.NOT_APPLICABLE,
            egress_status=EgressStatus.OK,
            server_ip="5.253.204.194",
        ))
        assert _row_color(iface) == ""


class TestRenderTable:
    """render_table: pure string rendering without I/O."""

    def test_returns_str(self) -> None:
        result = render_table([make_output_iface(IfaceSpec())])
        assert isinstance(result, str)

    def test_ends_with_newline(self) -> None:
        """render_table contract: result ends with a trailing newline."""
        result = render_table([make_output_iface(IfaceSpec())])
        assert result.endswith("\n")

    def test_empty_list_produces_header(self) -> None:
        result = render_table([])
        assert "INTERFACE" in result

    def test_interface_name_appears(self) -> None:
        result = render_table([make_output_iface(IfaceSpec(name="wlp1s0"))])
        assert "wlp1s0" in result

    def test_legend_present(self) -> None:
        result = render_table([make_output_iface(IfaceSpec())])
        assert "Legend:" in result

    def test_colored_row_contains_ansi_codes(self) -> None:
        """A RED interface row must contain the color and reset codes."""
        result = render_table([make_output_iface(IfaceSpec(egress_status=EgressStatus.OK))])
        assert _RED in result
        assert _RESET in result

    def test_no_color_row_has_no_leading_ansi(self) -> None:
        """A loopback row must not be wrapped in any color code.

        The full render_table output always contains ANSI codes in the legend,
        so this test isolates just the data row by finding the line that begins
        with the interface name and verifying it has no leading escape sequence.
        """
        iface = make_output_iface(IfaceSpec(
            name="lo",
            interface_type=InterfaceType.LOOPBACK,
            egress_status=EgressStatus.UNAVAILABLE,
        ))
        result = render_table([iface])
        # The data row starts with the (padded) interface name, not an ESC byte.
        data_row = next(
            line for line in result.splitlines()
            if line.startswith("lo")
        )
        assert not data_row.startswith("\033"), (
            f"loopback row should have no leading ANSI code, got: {data_row!r}"
        )

    def test_format_table_writes_render_table_output(self) -> None:
        """format_table must write exactly what render_table returns."""
        ifaces = [make_output_iface(IfaceSpec(name="eth0"))]
        expected = render_table(ifaces)
        buf = io.StringIO()
        format_table(ifaces, file=buf)
        assert buf.getvalue() == expected

    def test_divider_spans_full_width(self) -> None:
        """The divider line must be exactly _WIDTH characters wide."""
        result = render_table([])
        divider = "=" * _WIDTH
        assert divider in result

    def test_dormant_dns_shown_in_parentheses(self) -> None:
        """A dormant DNS server must appear in parentheses in the rendered table."""
        iface = make_output_iface(IfaceSpec(
            dns_servers=("192.168.1.1",),
            current_server=None,
            leak=DnsLeakStatus.DORMANT,
        ))
        result = render_table([iface])
        assert "(192.168.1.1)" in result
