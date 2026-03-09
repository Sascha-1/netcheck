"""Routing table analysis for netcheck.

Provides:
- ``get_metric_sort_key`` -- pure function for deterministic route ordering.
- ``get_route_info``      -- default gateway, metric, and query status for one
                            interface, returned as a ``RoutingInfo``.
- ``get_active_interface``-- interface that holds the lowest-metric default route.

``get_route_info`` return value
--------------------------------
``RoutingInfo.query_status`` conveys the outcome of the routing query:

- ``DataStatus.OK``          -- a default route was found.  ``metric`` is
                               set.  ``gateway`` is the ``via`` address when
                               present, or ``None`` for a directly-connected
                               route (no ``via`` keyword in the route entry).
- ``DataStatus.UNAVAILABLE`` -- the command succeeded but no default route
                               exists for this interface.  ``gateway`` and
                               ``metric`` are ``None``.
- ``DataStatus.ERROR``       -- the command failed or produced no output.
                               ``gateway`` and ``metric`` are ``None``.

Distinguishing ``UNAVAILABLE`` from ``ERROR`` matters to callers: a missing
default route is a normal network state (the interface is not on the default
path), whereas a command failure signals something unexpected.  A plain
``tuple`` cannot carry that distinction without an extra sentinel value.

Metric representation
---------------------
``RoutingInfo.metric`` is ``int | None``.  When the ``metric`` keyword is
absent from a routing table entry, the kernel uses ``0`` implicitly; this
module returns ``0`` in that case rather than a placeholder string.  ``None``
means no default route exists for the interface (or the query failed --
see ``query_status``).
"""

import logging
import re

from netcheck.core.enums import DataStatus
from netcheck.core.models import RoutingInfo
from netcheck.utils.command import CommandRunner

logger = logging.getLogger(__name__)


def get_metric_sort_key(metric: int | None) -> tuple[int, int]:
    """Return a sort key for deterministic route priority ordering.

    Interfaces with an explicit numeric metric sort before interfaces with
    no default route.  Within numeric metrics, lower values sort first
    (lower metric = higher kernel preference).

    Categories:
        ``(0, metric)`` -- has a default route; sort ascending by metric.
        ``(1, 0)``      -- no default route; lowest priority.

    Args:
        metric: Route metric as an integer, or ``None`` if no default route
                exists for the interface.

    Returns:
        Two-tuple suitable for use as a ``key=`` argument to ``sorted()``.

    Examples:
        >>> get_metric_sort_key(50)
        (0, 50)
        >>> get_metric_sort_key(0)
        (0, 0)
        >>> get_metric_sort_key(None)
        (1, 0)

        >>> metrics = [None, 100, 0, 50]
        >>> sorted(metrics, key=get_metric_sort_key)
        [0, 50, 100, None]
    """
    if metric is None:
        return (1, 0)
    return (0, metric)


def get_route_info(iface_name: str, runner: CommandRunner) -> RoutingInfo:
    """Return the default gateway, metric, and query status for ``iface_name``.

    Runs ``ip route show dev <iface>`` and parses the first ``default`` entry.

    Gateway handling:
        - When the ``via`` keyword is present, its value is returned as
          ``gateway``.
        - When absent, the route is directly connected (no next-hop router);
          ``gateway`` is ``None`` and ``query_status`` is still ``OK``.

    Metric handling:
        - When the ``metric`` keyword is present, its value is returned.
        - When absent, the kernel implicitly uses ``0``; this function
          returns ``0`` rather than a placeholder string.
        - When no default route exists, both ``gateway`` and ``metric`` are
          ``None`` and ``query_status`` is ``UNAVAILABLE``.
        - When the command fails, both are ``None`` and ``query_status`` is
          ``ERROR``.

    Args:
        iface_name: Interface name (e.g. ``"eth0"``).
        runner: Command runner.

    Returns:
        ``RoutingInfo`` with ``query_status``, ``gateway``, and ``metric``
        reflecting the result of the routing table query.
    """
    output = runner.run(["ip", "route", "show", "dev", iface_name])
    if output is None:
        logger.debug("%s: ip route show returned no output (status=ERROR)", iface_name)
        return RoutingInfo(
            query_status=DataStatus.ERROR,
            gateway=None,
            metric=None,
        )

    for line in output.splitlines():
        if not line.strip().startswith("default"):
            continue

        gateway_match = re.search(r"via\s+([0-9.a-fA-F:]+)", line)
        gateway = gateway_match.group(1) if gateway_match else None

        metric_match = re.search(r"metric\s+(\d+)", line)
        metric = int(metric_match.group(1)) if metric_match else 0

        logger.debug("%s: gateway=%s metric=%s (status=OK)", iface_name, gateway, metric)
        return RoutingInfo(
            query_status=DataStatus.OK,
            gateway=gateway,
            metric=metric,
        )

    logger.debug("%s: no default route found (status=UNAVAILABLE)", iface_name)
    return RoutingInfo(
        query_status=DataStatus.UNAVAILABLE,
        gateway=None,
        metric=None,
    )


def get_active_interface(runner: CommandRunner) -> str | None:
    """Return the interface name that holds the preferred default route.

    Runs ``ip route show default``, parses all default entries, and returns
    the interface associated with the lowest metric.  If multiple interfaces
    share the same metric, the first one in kernel output order is returned.

    Returns ``None`` when no default route exists on the system.

    Args:
        runner: Command runner.

    Returns:
        Interface name string, or ``None`` if no default route is present.
    """
    output = runner.run(["ip", "route", "show", "default"])
    if output is None:
        return None

    routes: list[tuple[str, int]] = []

    for line in output.splitlines():
        if not line.strip().startswith("default"):
            continue
        iface_match = re.search(r"dev\s+(\S+)", line)
        if not iface_match:
            continue
        iface = iface_match.group(1)
        metric_match = re.search(r"metric\s+(\d+)", line)
        metric = int(metric_match.group(1)) if metric_match else 0
        routes.append((iface, metric))

    if not routes:
        return None

    routes.sort(key=lambda r: get_metric_sort_key(r[1]))
    return routes[0][0]
