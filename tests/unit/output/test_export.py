"""Smoke tests for netcheck.output.export.

Verifies that ``format_json`` serialises all ``InterfaceInfo`` fields
correctly and that the metadata block contains the expected keys.
"""

import json
from typing import Any

from netcheck.core.enums import DnsLeakStatus, EgressStatus, InterfaceType
from netcheck.core.models import (
    EgressInfo,
    InterfaceInfo,
    ModemInfo,
)
from netcheck.output.export import format_json
from tests.helpers import IfaceSpec, make_output_iface


def _parse(interfaces: list[InterfaceInfo]) -> Any:
    return json.loads(format_json(interfaces))


class TestFormatJsonStructure:
    """format_json must produce valid JSON with the expected top-level keys."""

    def test_produces_valid_json(self) -> None:
        result = format_json([make_output_iface(IfaceSpec())])
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_metadata_and_interfaces_keys_present(self) -> None:
        data = _parse([make_output_iface(IfaceSpec())])
        assert "metadata" in data
        assert "interfaces" in data

    def test_interface_count_correct(self) -> None:
        data = _parse([make_output_iface(IfaceSpec()), make_output_iface(IfaceSpec(name="lo"))])
        assert data["metadata"]["interface_count"] == 2

    def test_empty_list_produces_zero_count(self) -> None:
        data = _parse([])
        assert data["metadata"]["interface_count"] == 0
        assert data["interfaces"] == []

    def test_tool_name_is_netcheck(self) -> None:
        assert _parse([make_output_iface(IfaceSpec())])["metadata"]["tool"] == "netcheck"

    def test_timestamp_present(self) -> None:
        assert "timestamp" in _parse([make_output_iface(IfaceSpec())])["metadata"]


class TestFormatJsonInterface:
    """Individual interface fields in the JSON output."""

    def test_name_field(self) -> None:
        data = _parse([make_output_iface(IfaceSpec(name="wlp1s0"))])
        assert data["interfaces"][0]["name"] == "wlp1s0"

    def test_type_field_is_string_value(self) -> None:
        data = _parse([make_output_iface(IfaceSpec(interface_type=InterfaceType.WIRELESS))])
        assert data["interfaces"][0]["type"] == "wireless"

    def test_ipv4_field(self) -> None:
        data = _parse([make_output_iface(IfaceSpec(ipv4="10.0.0.1"))])
        record = data["interfaces"][0]
        assert record["ipv4"] == "10.0.0.1"
        assert record["ipv4_status"] == "ok"

    def test_ipv4_null_when_none(self) -> None:
        data = _parse([make_output_iface(IfaceSpec(ipv4=None))])
        record = data["interfaces"][0]
        assert record["ipv4"] is None
        assert record["ipv4_status"] == "unavailable"

    def test_ipv6_status_field_present(self) -> None:
        """ipv6_status must appear in the JSON output."""
        record = _parse([make_output_iface(IfaceSpec())])["interfaces"][0]
        assert "ipv6_status" in record
        assert record["ipv6_status"] == "unavailable"

    def test_vpn_server_ip_status_field_present(self) -> None:
        """vpn_server_ip_status must appear in the JSON output."""
        # ETHERNET interface: concept does not apply; status is not_applicable.
        record = _parse([make_output_iface(IfaceSpec())])["interfaces"][0]
        assert "vpn_server_ip_status" in record
        assert record["vpn_server_ip_status"] == "not_applicable"

    def test_vpn_server_ip_status_ok_when_server_ip_set(self) -> None:
        record = _parse([make_output_iface(
            IfaceSpec(interface_type=InterfaceType.VPN, server_ip="5.253.204.194")
        )])["interfaces"][0]
        assert record["vpn_server_ip"] == "5.253.204.194"
        assert record["vpn_server_ip_status"] == "ok"

    def test_dns_servers_null_when_query_unavailable(self) -> None:
        """dns_servers must be null when dns_query_status is not ok."""
        # IfaceSpec() defaults produce dns_query_status=UNAVAILABLE (no servers).
        record = _parse([make_output_iface(IfaceSpec())])[
            "interfaces"
        ][0]
        assert record["dns_query_status"] == "unavailable"
        assert record["dns_servers"] is None

    def test_dns_servers_list_when_query_ok(self) -> None:
        """dns_servers must be a list when dns_query_status is ok."""
        record = _parse([make_output_iface(
            IfaceSpec(dns_servers=("10.2.0.1",), current_server="10.2.0.1")
        )])[
            "interfaces"
        ][0]
        assert record["dns_query_status"] == "ok"
        assert record["dns_servers"] == ["10.2.0.1"]

    def test_metric_null_when_none(self) -> None:
        assert _parse([make_output_iface(IfaceSpec())])["interfaces"][0]["metric"] is None

    def test_egress_null_when_unavailable(self) -> None:
        record = _parse([make_output_iface(IfaceSpec())])["interfaces"][0]
        assert record["external_ipv4"] is None
        assert record["isp"] is None

    def test_egress_populated_when_ok(self) -> None:
        ok_egress = EgressInfo(
            status=EgressStatus.OK,
            external_ip="203.0.113.45",
            external_ipv6=None,
            isp="AS3320 Deutsche Telekom AG",
            country="DE",
        )
        record = _parse([make_output_iface(IfaceSpec(egress=ok_egress))])["interfaces"][0]
        assert record["external_ipv4"] == "203.0.113.45"
        assert record["country"] == "DE"

    def test_vpn_active_summary_uses_server_ip(self) -> None:
        """vpn_active must be True when a VPN interface has a confirmed server
        endpoint (server_ip set), regardless of whether it has egress data.

        The server_ip signal is authoritative: it is set only when the
        orchestrator finds a static host route to the VPN server in the global
        routing table.  A VPN interface's IP address alone does not confirm
        a live tunnel -- the address persists after the tunnel drops.
        """
        ifaces = [
            make_output_iface(IfaceSpec(
                interface_type=InterfaceType.VPN,
                server_ip="5.253.204.194",
            )),
            make_output_iface(IfaceSpec(name="eth0")),
        ]
        data = _parse(ifaces)
        assert data["metadata"]["summary"]["vpn_active"] is True

    def test_vpn_active_false_when_ip_present_but_no_server_ip(self) -> None:
        """vpn_active must be False when a VPN interface has an IP but no
        confirmed server endpoint.

        This is the tunnel-dropped scenario: the interface retains its
        address after the tunnel drops, but the static host route to the
        server is removed.  vpn_active must not fire in this case.
        """
        ifaces = [
            make_output_iface(IfaceSpec(
                interface_type=InterfaceType.VPN,
                ipv4="10.8.0.2",
                # server_ip defaults to None -- no confirmed endpoint
            )),
            make_output_iface(IfaceSpec(name="eth0")),
        ]
        data = _parse(ifaces)
        assert data["metadata"]["summary"]["vpn_active"] is False

    def test_vpn_active_via_egress_ok(self) -> None:
        """vpn_active must also be True when a VPN interface is the active
        egress path, even if server_ip is not set.

        This covers configurations where the static bypass route is absent
        but the VPN interface is the confirmed outbound path.
        """
        ok_egress = EgressInfo(
            status=EgressStatus.OK,
            external_ip="5.253.204.204",
            external_ipv6=None,
            isp="AS9009 M247 Europe SRL",
            country="BE",
        )
        ifaces = [
            make_output_iface(IfaceSpec(
                interface_type=InterfaceType.VPN,
                egress=ok_egress,
            )),
        ]
        data = _parse(ifaces)
        assert data["metadata"]["summary"]["vpn_active"] is True

    def test_dns_leak_detected(self) -> None:
        data = _parse([make_output_iface(IfaceSpec(leak=DnsLeakStatus.LEAK))])
        assert data["metadata"]["summary"]["dns_leak_detected"] is True

    def test_modem_state_null_for_non_cellular(self) -> None:
        assert _parse([make_output_iface(IfaceSpec())])["interfaces"][0]["modem_state"] is None

    def test_modem_state_for_cellular(self) -> None:
        modem = ModemInfo(state="connected", state_reason=None)
        iface = make_output_iface(IfaceSpec(interface_type=InterfaceType.CELLULAR, modem=modem))
        data = _parse([iface])
        assert data["interfaces"][0]["modem_state"] == "connected"
