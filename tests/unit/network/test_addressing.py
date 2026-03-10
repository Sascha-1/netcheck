"""Unit tests for netcheck.network.addressing.

All subprocess calls use FakeCommandRunner.

Test groups
-----------
``TestGetAllIPv4Addresses``
    Parses ``ip -4 addr show`` fixture output.

``TestGetAllIPv6Addresses``
    Parses ``ip -6 addr show`` fixture output, verifying that link-local
    addresses and non-global addresses are excluded.

Both test groups verify the ``DataStatus`` returned alongside the dict:
``OK`` when the command ran (even if the dict is empty), ``ERROR`` when the
runner returned ``None``.
"""

from pathlib import Path

from netcheck.core.enums import DataStatus
from netcheck.network.addressing import get_all_ipv4_addresses, get_all_ipv6_addresses
from tests.fakes import FakeCommandRunner

_F = Path(__file__).parent.parent.parent / "fixtures" / "ip"


def _read(name: str) -> str:
    return (_F / name).read_text().strip()


class TestGetAllIPv4Addresses:
    """Tests for get_all_ipv4_addresses."""

    def test_all_interfaces_in_result(self) -> None:
        """All interfaces with an IPv4 address must appear in the result."""
        runner = FakeCommandRunner(
            {("ip", "-4", "addr", "show"): _read("addr4_show.txt")}
        )
        addrs, status = get_all_ipv4_addresses(runner)
        assert status == DataStatus.OK
        assert "lo" in addrs
        assert "eth0" in addrs
        assert "tun0" in addrs

    def test_correct_addresses_extracted(self) -> None:
        """Each interface must have its correct address."""
        runner = FakeCommandRunner(
            {("ip", "-4", "addr", "show"): _read("addr4_show.txt")}
        )
        addrs, _ = get_all_ipv4_addresses(runner)
        assert addrs["lo"] == "127.0.0.1"
        assert addrs["eth0"] == "192.168.1.100"
        assert addrs["tun0"] == "10.8.0.2"

    def test_command_failure_returns_empty_dict_and_error(self) -> None:
        """Command failure must return an empty dict and DataStatus.ERROR."""
        runner = FakeCommandRunner({("ip", "-4", "addr", "show"): None})
        addrs, status = get_all_ipv4_addresses(runner)
        assert not addrs
        assert status == DataStatus.ERROR

    def test_only_first_address_per_interface(self) -> None:
        """When an interface has multiple addresses only the first is kept."""
        multi = (
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    link/ether 00:1a:2b:3c:4d:5e brd ff:ff:ff:ff:ff:ff\n"
            "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n"
            "       valid_lft forever preferred_lft forever\n"
            "    inet 192.168.1.101/24 brd 192.168.1.255 scope global secondary eth0\n"
            "       valid_lft forever preferred_lft forever\n"
        )
        runner = FakeCommandRunner({("ip", "-4", "addr", "show"): multi})
        addrs, status = get_all_ipv4_addresses(runner)
        assert status == DataStatus.OK
        assert addrs.get("eth0") == "192.168.1.100"


class TestGetAllIPv6Addresses:
    """Tests for get_all_ipv6_addresses."""

    def test_global_ipv6_address_included(self) -> None:
        """A global-scope IPv6 address must appear in the result."""
        runner = FakeCommandRunner(
            {("ip", "-6", "addr", "show"): _read("addr6_show.txt")}
        )
        addrs, status = get_all_ipv6_addresses(runner)
        assert status == DataStatus.OK
        assert "eth0" in addrs
        assert addrs["eth0"] == "2001:db8::1"

    def test_link_local_excluded(self) -> None:
        """Link-local (fe80::) addresses must be excluded."""
        runner = FakeCommandRunner(
            {("ip", "-6", "addr", "show"): _read("addr6_show.txt")}
        )
        addrs, _ = get_all_ipv6_addresses(runner)
        for addr in addrs.values():
            assert not addr.startswith("fe80")

    def test_loopback_excluded(self) -> None:
        """The loopback ::1 address must not appear (scope host, not global)."""
        runner = FakeCommandRunner(
            {("ip", "-6", "addr", "show"): _read("addr6_show.txt")}
        )
        addrs, _ = get_all_ipv6_addresses(runner)
        assert "lo" not in addrs

    def test_interface_without_global_ipv6_absent(self) -> None:
        """An interface with only link-local IPv6 must not appear."""
        runner = FakeCommandRunner(
            {("ip", "-6", "addr", "show"): _read("addr6_show.txt")}
        )
        addrs, _ = get_all_ipv6_addresses(runner)
        assert "wlp1s0" not in addrs  # fixture only has fe80:: for wlp1s0

    def test_command_failure_returns_empty_dict_and_error(self) -> None:
        """Command failure must return an empty dict and DataStatus.ERROR."""
        runner = FakeCommandRunner({("ip", "-6", "addr", "show"): None})
        addrs, status = get_all_ipv6_addresses(runner)
        assert not addrs
        assert status == DataStatus.ERROR


class TestGetAllIPv6AddressesExtended:
    """get_all_ipv6_addresses: IPv6 address filtering edge cases."""

    def test_temporary_address_excluded(self) -> None:
        """Temporary IPv6 addresses must be excluded from results."""
        output = (
            "2: eth0: <BROADCAST,UP>\n"
            "    inet6 2001:db8::1/64 scope global temporary\n"
            "       valid_lft forever preferred_lft forever\n"
        )
        runner = FakeCommandRunner({("ip", "-6", "addr", "show"): output})
        addrs, _ = get_all_ipv6_addresses(runner)
        assert "eth0" not in addrs

    def test_deprecated_address_excluded(self) -> None:
        """Deprecated IPv6 addresses must be excluded from results."""
        output = (
            "2: eth0: <BROADCAST,UP>\n"
            "    inet6 2001:db8::1/64 scope global deprecated\n"
            "       valid_lft forever preferred_lft forever\n"
        )
        runner = FakeCommandRunner({("ip", "-6", "addr", "show"): output})
        addrs, _ = get_all_ipv6_addresses(runner)
        assert "eth0" not in addrs

    def test_non_global_scope_excluded(self) -> None:
        """Addresses without 'scope global' must be excluded."""
        output = (
            "2: eth0: <BROADCAST,UP>\n"
            "    inet6 ::1/128 scope host\n"
            "       valid_lft forever preferred_lft forever\n"
        )
        runner = FakeCommandRunner({("ip", "-6", "addr", "show"): output})
        addrs, _ = get_all_ipv6_addresses(runner)
        assert "eth0" not in addrs

    def test_first_global_address_kept_second_skipped(self) -> None:
        """Only the first qualifying global address per interface is recorded."""
        output = (
            "2: eth0: <BROADCAST,UP>\n"
            "    inet6 2001:db8::1/64 scope global\n"
            "       valid_lft forever preferred_lft forever\n"
            "    inet6 2001:db8::2/64 scope global\n"
            "       valid_lft forever preferred_lft forever\n"
        )
        runner = FakeCommandRunner({("ip", "-6", "addr", "show"): output})
        addrs, status = get_all_ipv6_addresses(runner)
        assert status == DataStatus.OK
        assert addrs.get("eth0") == "2001:db8::1"

    def test_inet6_line_before_interface_header_ignored(self) -> None:
        """An indented inet6 line with no preceding interface header must be ignored.

        ``current_iface`` starts as ``None``.  If the very first line is
        already indented and contains ``inet6 ``, the compound condition
        ``line.strip().startswith("inet6 ") and current_iface is not None``
        evaluates True/False -- the entire ``elif`` body is skipped.

        This exercises the False arm of the ``current_iface is not None``
        sub-condition (partial branch in ``get_all_ipv6_addresses``).
        """
        output = "    inet6 2001:db8::1/64 scope global\n"
        runner = FakeCommandRunner({("ip", "-6", "addr", "show"): output})
        addrs, status = get_all_ipv6_addresses(runner)
        assert status == DataStatus.OK
        assert not addrs

    def test_inet6_line_with_no_extractable_address_ignored(self) -> None:
        """An inet6 line whose address field does not match the regex is ignored.

        The regex ``inet6\\s+([0-9a-f:]+)`` requires at least one hex digit
        or colon before the slash.  A malformed line such as ``inet6 /64``
        produces no match, so ``addr_match`` is ``None`` and the
        ``if addr_match:`` branch is not taken -- the interface is not added
        to the result dict.

        This exercises the False arm of the ``if addr_match:`` branch
        (partial branch in ``get_all_ipv6_addresses``).
        """
        output = (
            "2: eth0: <BROADCAST,UP>\n"
            "    inet6 /64 scope global\n"
        )
        runner = FakeCommandRunner({("ip", "-6", "addr", "show"): output})
        addrs, status = get_all_ipv6_addresses(runner)
        assert status == DataStatus.OK
        assert "eth0" not in addrs


class TestGetAllIPv4AddressesExtended:
    """get_all_ipv4_addresses: additional parsing edge cases."""

    def test_interface_with_no_inet_line_absent(self) -> None:
        """Interface block without an inet line must not appear in the result."""
        output = (
            "2: eth0: <BROADCAST,MULTICAST,UP>\n"
            "    link/ether 00:1a:2b:3c:4d:5e brd ff:ff:ff:ff:ff:ff\n"
        )
        runner = FakeCommandRunner({("ip", "-4", "addr", "show"): output})
        addrs, status = get_all_ipv4_addresses(runner)
        assert status == DataStatus.OK
        assert "eth0" not in addrs

    def test_multiple_interfaces_independent(self) -> None:
        """Each interface's address must be recorded independently."""
        output = (
            "2: eth0: <BROADCAST,UP>\n"
            "    inet 10.0.0.1/24 scope global eth0\n"
            "3: eth1: <BROADCAST,UP>\n"
            "    inet 10.0.1.1/24 scope global eth1\n"
        )
        runner = FakeCommandRunner({("ip", "-4", "addr", "show"): output})
        addrs, status = get_all_ipv4_addresses(runner)
        assert status == DataStatus.OK
        assert addrs["eth0"] == "10.0.0.1"
        assert addrs["eth1"] == "10.0.1.1"

    def test_successful_command_with_no_addresses_returns_ok(self) -> None:
        """Command succeeding with no inet lines must return OK, not ERROR."""
        output = (
            "1: lo: <LOOPBACK,UP>\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        )
        runner = FakeCommandRunner({("ip", "-4", "addr", "show"): output})
        addrs, status = get_all_ipv4_addresses(runner)
        assert status == DataStatus.OK
        assert not addrs

    def test_inet_line_before_interface_header_ignored(self) -> None:
        """An indented inet line with no preceding interface header must be ignored.

        ``current_iface`` starts as ``None``.  If the very first line is
        already indented (starts with a space) and contains ``inet ``, the
        compound condition ``line.strip().startswith("inet ") and
        current_iface is not None`` evaluates True/False -- the entire
        ``elif`` body is skipped.

        This exercises the False arm of the ``current_iface is not None``
        sub-condition (partial branch in ``get_all_ipv4_addresses``).
        """
        output = "    inet 10.0.0.1/24 scope global eth0\n"
        runner = FakeCommandRunner({("ip", "-4", "addr", "show"): output})
        addrs, status = get_all_ipv4_addresses(runner)
        assert status == DataStatus.OK
        assert not addrs

    def test_inet_line_with_no_extractable_ip_ignored(self) -> None:
        """An inet line whose address field does not match the regex is ignored.

        The regex ``inet\\s+([0-9.]+)`` requires at least one digit before
        the slash.  A malformed line such as ``inet /24`` produces no match,
        so ``addr_match`` is ``None`` and the ``if addr_match:`` branch is
        not taken -- the interface is not added to the result dict.

        This exercises the False arm of the ``if addr_match:`` branch
        (partial branch in ``get_all_ipv4_addresses``).
        """
        output = (
            "2: eth0: <BROADCAST,UP>\n"
            "    inet /24 scope global eth0\n"
        )
        runner = FakeCommandRunner({("ip", "-4", "addr", "show"): output})
        addrs, status = get_all_ipv4_addresses(runner)
        assert status == DataStatus.OK
        assert "eth0" not in addrs
