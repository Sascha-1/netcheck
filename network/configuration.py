"""
Network configuration module.

Queries IP addresses, routing information, and gateway configuration.
All operations query the kernel via the ip command (netlink interface).
Supports both IPv4 and IPv6.

PHASE 2 MIGRATION: 1 logging call migrated to PEP 391 compliant % formatting.
IMPROVEMENTS:
- HIGH: Batched IP queries (queries all interfaces at once)
- MEDIUM: Batched route queries (single function returns both gateway and metric)
"""

from typing import Optional, Dict

from logging_config import get_logger
from utils.system import run_command, sanitize_for_log

logger = get_logger(__name__)


# ============================================================================
# Batched IP Address Queries (HIGH Priority Optimization)
# ============================================================================

def get_all_ipv4_addresses() -> Dict[str, str]:
    """
    Get ALL IPv4 addresses for ALL interfaces in a single query.

    HIGH PRIORITY OPTIMIZATION: Instead of calling 'ip addr show <iface>'
    once per interface (14 calls for 7 interfaces), this calls once for
    all interfaces.

    Returns:
        Dict mapping interface name to IPv4 address
        Missing interfaces will not be in dict
    """
    output = run_command(["ip", "-4", "addr", "show"])

    if output is None:
        return {}

    result: Dict[str, str] = {}
    current_iface: Optional[str] = None

    for line in output.split("\n"):
        line_stripped = line.strip()

        if not line_stripped:
            continue

        if not line.startswith(" "):
            parts = line.split(":", 2)
            if len(parts) >= 2:
                current_iface = parts[1].strip()

        elif line_stripped.startswith("inet ") and current_iface:
            parts = line_stripped.split()
            if len(parts) >= 2:
                ip_with_mask = parts[1]
                ipv4 = ip_with_mask.split("/")[0]
                result[current_iface] = ipv4

    return result


def get_all_ipv6_addresses() -> Dict[str, str]:
    """
    Get ALL IPv6 addresses for ALL interfaces in a single query.

    Returns only global unicast addresses (2000::/3 range).
    Ignores link-local (fe80::) and temporary addresses.

    Returns:
        Dict mapping interface name to IPv6 address
        Missing interfaces will not be in dict
    """
    output = run_command(["ip", "-6", "addr", "show"])

    if output is None:
        return {}

    result: Dict[str, str] = {}
    current_iface: Optional[str] = None

    for line in output.split("\n"):
        line_stripped = line.strip()

        if not line_stripped:
            continue

        if not line.startswith(" "):
            parts = line.split(":", 2)
            if len(parts) >= 2:
                current_iface = parts[1].strip()

        elif line_stripped.startswith("inet6 ") and current_iface:
            parts = line_stripped.split()
            if len(parts) >= 2:
                ip_with_mask = parts[1]
                ip_addr = ip_with_mask.split("/")[0]

                if ip_addr.startswith("fe80:"):
                    continue

                if "deprecated" in line_stripped or "temporary" in line_stripped:
                    continue

                if "scope global" in line_stripped:
                    result[current_iface] = ip_addr

    return result


def get_internal_ipv4(iface_name: str) -> str:
    """
    Get the IPv4 address assigned to an interface.

    DEPRECATED: Use get_all_ipv4_addresses() for better performance.
    This function maintained for backward compatibility.
    """
    all_ipv4 = get_all_ipv4_addresses()
    return all_ipv4.get(iface_name, "N/A")


def get_internal_ipv6(iface_name: str) -> str:
    """
    Get the IPv6 address assigned to an interface.

    DEPRECATED: Use get_all_ipv6_addresses() for better performance.
    This function maintained for backward compatibility.
    """
    all_ipv6 = get_all_ipv6_addresses()
    return all_ipv6.get(iface_name, "N/A")


# ============================================================================
# Batched Route Queries (MEDIUM Priority Optimization)
# ============================================================================

def get_route_info(iface_name: str) -> tuple[str, str]:
    """
    Get both default gateway and routing metric in a single query.

    MEDIUM PRIORITY OPTIMIZATION: Instead of calling 'ip route show'
    twice per interface (once for gateway, once for metric), this
    calls once and extracts both values.

    Returns:
        Tuple of (gateway, metric)
        - gateway: IP address of gateway, or "NONE" if no default route
        - metric: Routing metric, or "DEFAULT" if not specified, or "NONE" if no route
    """
    output = run_command(["ip", "route", "show", "dev", iface_name])

    if output is None:
        return ("NONE", "NONE")

    for line in output.split("\n"):
        if line.startswith("default via "):
            parts = line.split()
            if len(parts) >= 3:
                gateway = parts[2]

                # FIXED: metric should be str, not DataMarker
                metric: str
                if "metric" in parts:
                    try:
                        idx = parts.index("metric")
                        metric = parts[idx + 1] if idx + 1 < len(parts) else "DEFAULT"
                    except (ValueError, IndexError):
                        metric = "DEFAULT"
                else:
                    metric = "DEFAULT"

                return (gateway, metric)

    return ("NONE", "NONE")


def get_default_gateway(iface_name: str) -> str:
    """
    Get the default gateway configured for an interface.

    DEPRECATED: Use get_route_info() for better performance.
    This function maintained for backward compatibility.
    """
    gateway, _ = get_route_info(iface_name)
    return gateway


def get_route_metric(iface_name: str) -> str:
    """
    Get the routing metric for the default route on an interface.

    DEPRECATED: Use get_route_info() for better performance.
    This function maintained for backward compatibility.
    """
    _, metric = get_route_info(iface_name)
    return metric


# ============================================================================
# Active Interface Detection
# ============================================================================

def get_active_interface() -> Optional[str]:
    """
    Get the interface currently routing internet traffic.

    Identifies which interface has the default route with lowest metric.
    No elevated privileges required.
    """
    logger.debug("Querying active default route")

    output = run_command(["ip", "route", "show", "default"])

    if output is None:
        logger.warning("No default route found in system")
        return None

    for line in output.split("\n"):
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default" and parts[1] == "via":
            if "dev" in parts:
                try:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        iface = parts[dev_index + 1]
                        safe_iface = sanitize_for_log(iface)
                        # MIGRATED: f-string → % formatting (1/1)
                        logger.debug("Active interface: %s", safe_iface)
                        return iface
                except (ValueError, IndexError):
                    pass

    logger.warning("Could not parse default route output")
    return None
