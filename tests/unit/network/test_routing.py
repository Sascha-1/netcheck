"""Smoke tests for netcheck.network.routing.

``get_route_info`` returns a ``RoutingInfo`` dataclass whose ``query_status``
field distinguishes three outcomes: a route was found (``OK``), the command
succeeded but no default route exists for this interface (``UNAVAILABLE``),
or the command itself failed (``ERROR``).  These tests encode that contract.
"""

from netcheck.core.enums import DataStatus
from netcheck.core.models import RoutingInfo
from netcheck.network.routing import get_active_interface, get_metric_sort_key, get_route_info
from tests.fakes import FakeCommandRunner


class TestGetMetricSortKey:
    """get_metric_sort_key is a pure function -- no fakes needed."""

    def test_integer_metric_category_zero(self) -> None:
        assert get_metric_sort_key(50) == (0, 50)

    def test_zero_is_valid_metric(self) -> None:
        assert get_metric_sort_key(0) == (0, 0)

    def test_none_is_lowest_priority(self) -> None:
        assert get_metric_sort_key(None) == (1, 0)

    def test_none_sorts_after_any_integer(self) -> None:
        assert get_metric_sort_key(None) > get_metric_sort_key(9999)

    def test_sort_order(self) -> None:
        assert sorted([None, 100, 0, 50], key=get_metric_sort_key) == [0, 50, 100, None]


class TestGetRouteInfo:
    """get_route_info must return a RoutingInfo dataclass, never a tuple."""

    def test_returns_routing_info_type(self) -> None:
        """Return value must be RoutingInfo, not a bare tuple."""
        runner = FakeCommandRunner(
            {("ip", "route", "show", "dev", "eth0"):
             "default via 192.168.1.1 dev eth0 metric 100"}
        )
        result = get_route_info("eth0", runner)
        assert isinstance(result, RoutingInfo)

    def test_route_found_status_ok(self) -> None:
        """When a default route exists, query_status must be OK."""
        runner = FakeCommandRunner(
            {("ip", "route", "show", "dev", "eth0"):
             "default via 192.168.1.1 dev eth0 metric 100"}
        )
        result = get_route_info("eth0", runner)
        assert result.query_status == DataStatus.OK

    def test_gateway_extracted(self) -> None:
        runner = FakeCommandRunner(
            {("ip", "route", "show", "dev", "eth0"):
             "default via 192.168.1.1 dev eth0 metric 100"}
        )
        assert get_route_info("eth0", runner).gateway == "192.168.1.1"

    def test_metric_extracted_as_int(self) -> None:
        runner = FakeCommandRunner(
            {("ip", "route", "show", "dev", "eth0"):
             "default via 192.168.1.1 dev eth0 metric 100"}
        )
        result = get_route_info("eth0", runner)
        assert result.metric == 100
        assert isinstance(result.metric, int)

    def test_absent_metric_keyword_returns_zero(self) -> None:
        """Missing 'metric' keyword means kernel uses 0; we must return 0."""
        runner = FakeCommandRunner(
            {("ip", "route", "show", "dev", "eth0"):
             "default via 192.168.1.1 proto dhcp src 192.168.1.100"}
        )
        result = get_route_info("eth0", runner)
        assert result.query_status == DataStatus.OK
        assert result.metric == 0

    def test_no_default_route_is_unavailable(self) -> None:
        """No default route must set query_status=UNAVAILABLE and fields to None."""
        runner = FakeCommandRunner(
            {("ip", "route", "show", "dev", "lo"):
             "192.168.1.0/24 dev lo proto kernel scope link src 192.168.1.1"}
        )
        result = get_route_info("lo", runner)
        assert result.query_status == DataStatus.UNAVAILABLE
        assert result.gateway is None
        assert result.metric is None

    def test_command_failure_is_error(self) -> None:
        """Command failure must set query_status=ERROR and fields to None."""
        runner = FakeCommandRunner({("ip", "route", "show", "dev", "eth0"): None})
        result = get_route_info("eth0", runner)
        assert result.query_status == DataStatus.ERROR
        assert result.gateway is None
        assert result.metric is None


class TestGetActiveInterface:
    """get_active_interface returns the interface with the lowest metric."""

    def test_lowest_metric_wins(self) -> None:
        output = (
            "default via 192.168.1.1 dev eth0 metric 100\n"
            "default via 10.8.0.1 dev tun0 metric 50"
        )
        runner = FakeCommandRunner({("ip", "route", "show", "default"): output})
        assert get_active_interface(runner) == "tun0"

    def test_no_default_route_returns_none(self) -> None:
        runner = FakeCommandRunner({("ip", "route", "show", "default"): None})
        assert get_active_interface(runner) is None

    def test_single_route_returned(self) -> None:
        runner = FakeCommandRunner(
            {("ip", "route", "show", "default"):
             "default via 192.168.1.1 dev eth0 metric 100"}
        )
        assert get_active_interface(runner) == "eth0"


class TestGetActiveInterfaceExtended:
    """get_active_interface: edge cases in route table parsing."""

    def test_empty_output_returns_none(self) -> None:
        """Empty ip route show default output must return None."""
        runner = FakeCommandRunner({("ip", "route", "show", "default"): ""})
        assert get_active_interface(runner) is None

    def test_route_without_dev_keyword_skipped(self) -> None:
        """A default route line with no 'dev' keyword must be skipped."""
        output = "default via 192.168.1.1 proto dhcp\n"
        runner = FakeCommandRunner({("ip", "route", "show", "default"): output})
        assert get_active_interface(runner) is None

    def test_absent_metric_treated_as_zero(self) -> None:
        """Default route without a 'metric' keyword uses implicit metric 0."""
        output = "default via 192.168.1.1 dev eth0 proto dhcp"
        runner = FakeCommandRunner({("ip", "route", "show", "default"): output})
        assert get_active_interface(runner) == "eth0"

    def test_metric_zero_beats_higher_metric(self) -> None:
        """Implicit metric 0 must rank below explicit metric 100."""
        output = (
            "default via 192.168.1.1 dev eth0 metric 100\n"
            "default via 10.8.0.1 dev tun0\n"  # no metric = 0
        )
        runner = FakeCommandRunner({("ip", "route", "show", "default"): output})
        assert get_active_interface(runner) == "tun0"

    def test_first_among_equal_metrics_wins(self) -> None:
        """When two interfaces share a metric, the first in output is returned."""
        output = (
            "default via 192.168.1.1 dev eth0 metric 100\n"
            "default via 192.168.1.2 dev eth1 metric 100\n"
        )
        runner = FakeCommandRunner({("ip", "route", "show", "default"): output})
        assert get_active_interface(runner) == "eth0"
