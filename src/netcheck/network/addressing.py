"""IP address collection for netcheck.

Provides batch queries for IPv4 and IPv6 addresses across all interfaces
in a single ``ip addr show`` invocation.  The orchestrator calls each
function once and distributes the resulting dict, avoiding per-interface
subprocess calls.

IPv6 filtering
--------------
Only globally-scoped, non-temporary, non-deprecated IPv6 addresses are
returned.  Link-local addresses (fe80::/10) are excluded because they are
not meaningful for external connectivity reporting.  The first qualifying
address per interface is used when multiple exist.
"""

import re

from netcheck.core.enums import DataStatus
from netcheck.utils.command import CommandRunner


def get_all_ipv4_addresses(
    runner: CommandRunner,
) -> tuple[dict[str, str], DataStatus]:
    """Return a mapping of interface name to first IPv4 address, with status.

    Runs ``ip -4 addr show`` once and parses all interface entries.  Only
    the first address is recorded when an interface has multiple addresses.

    Args:
        runner: Command runner.

    Returns:
        A ``(addresses, status)`` tuple where:

        - ``status`` is ``DataStatus.ERROR`` if the command produced no
          output (runner returned ``None``), or ``DataStatus.OK`` if the
          command ran successfully (the dict may still be empty if no
          interface has an IPv4 address).
        - ``addresses`` maps interface name to IPv4 address string for each
          interface that has one.
    """
    output = runner.run(["ip", "-4", "addr", "show"])
    if output is None:
        return {}, DataStatus.ERROR

    result: dict[str, str] = {}
    current_iface: str | None = None

    for line in output.splitlines():
        if not line.startswith(" "):
            iface_match = re.match(r"^\d+:\s+([^:@\s]+)", line)
            if iface_match:
                current_iface = iface_match.group(1).strip()
        elif line.strip().startswith("inet ") and current_iface is not None:
            if current_iface in result:
                continue
            addr_match = re.search(r"inet\s+([0-9.]+)", line)
            if addr_match:
                result[current_iface] = addr_match.group(1)

    return result, DataStatus.OK


def get_all_ipv6_addresses(
    runner: CommandRunner,
) -> tuple[dict[str, str], DataStatus]:
    """Return a mapping of interface name to first global IPv6 address, with status.

    Runs ``ip -6 addr show`` once.  Excludes link-local (fe80::),
    temporary, and deprecated addresses.  Only ``scope global`` addresses
    are included.

    Args:
        runner: Command runner.

    Returns:
        A ``(addresses, status)`` tuple where:

        - ``status`` is ``DataStatus.ERROR`` if the command produced no
          output (runner returned ``None``), or ``DataStatus.OK`` if the
          command ran successfully (the dict may still be empty if no
          interface has a qualifying IPv6 address).
        - ``addresses`` maps interface name to IPv6 address string for each
          interface that has a qualifying global address.
    """
    output = runner.run(["ip", "-6", "addr", "show"])
    if output is None:
        return {}, DataStatus.ERROR

    result: dict[str, str] = {}
    current_iface: str | None = None

    for line in output.splitlines():
        if not line.startswith(" "):
            iface_match = re.match(r"^\d+:\s+([^:@\s]+)", line)
            if iface_match:
                current_iface = iface_match.group(1).strip()
        elif line.strip().startswith("inet6 ") and current_iface is not None:
            if current_iface in result:
                continue
            if "fe80:" in line:
                continue
            if "temporary" in line or "deprecated" in line:
                continue
            if "scope global" not in line:
                continue
            addr_match = re.search(r"inet6\s+([0-9a-f:]+)", line)
            if addr_match:
                result[current_iface] = addr_match.group(1)

    return result, DataStatus.OK
