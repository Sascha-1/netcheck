"""
Network configuration module.

Queries IP addresses, routing information, and gateway configuration.
All operations query the kernel via the ip command (netlink interface).
Supports both IPv4 and IPv6.
"""

from typing import Optional

from logging_config import get_logger
from utils.system import run_command, sanitize_for_log

logger = get_logger(__name__)


def get_internal_ipv4(iface_name: str) -> str:
    """
    Get the IPv4 address assigned to an interface.
    
    Uses ip command to query kernel routing tables via netlink.
    No elevated privileges required.
    """
    safe_name = sanitize_for_log(iface_name)
    logger.debug(f"[{safe_name}] Querying IPv4 address")
    
    output = run_command(["ip", "-4", "addr", "show", iface_name])
    
    if output is None:
        logger.debug(f"[{safe_name}] No IPv4 configuration found")
        return "N/A"
    
    for line in output.split("\n"):
        line_stripped = line.strip()
        if line_stripped.startswith("inet "):
            parts = line_stripped.split()
            if len(parts) >= 2:
                ip_with_mask = parts[1]
                ipv4 = ip_with_mask.split("/")[0]
                logger.debug(f"[{safe_name}] IPv4: {ipv4}")
                return ipv4
    
    logger.debug(f"[{safe_name}] No IPv4 address assigned")
    return "N/A"


def get_internal_ipv6(iface_name: str) -> str:
    """
    Get the IPv6 address assigned to an interface.
    
    Returns the first global unicast address (2000::/3 range).
    Ignores link-local (fe80::) and temporary addresses.
    No elevated privileges required.
    """
    safe_name = sanitize_for_log(iface_name)
    logger.debug(f"[{safe_name}] Querying IPv6 address")
    
    output = run_command(["ip", "-6", "addr", "show", iface_name])
    
    if output is None:
        logger.debug(f"[{safe_name}] No IPv6 configuration found")
        return "N/A"
    
    for line in output.split("\n"):
        line_stripped = line.strip()
        if line_stripped.startswith("inet6 "):
            parts = line_stripped.split()
            if len(parts) >= 2:
                ip_with_mask = parts[1]
                ip_addr = ip_with_mask.split("/")[0]
                
                if ip_addr.startswith("fe80:"):
                    continue
                
                if "deprecated" in line_stripped or "temporary" in line_stripped:
                    continue
                
                if "scope global" in line_stripped:
                    logger.debug(f"[{safe_name}] IPv6: {ip_addr}")
                    return ip_addr
    
    logger.debug(f"[{safe_name}] No global IPv6 address assigned")
    return "N/A"


def get_default_gateway(iface_name: str) -> str:
    """
    Get the default gateway configured for an interface.
    
    Queries kernel routing table for default route on this interface.
    No elevated privileges required.
    """
    safe_name = sanitize_for_log(iface_name)
    logger.debug(f"[{safe_name}] Querying default gateway")
    
    output = run_command(["ip", "route", "show", "dev", iface_name])
    
    if output is None:
        logger.debug(f"[{safe_name}] No routes found")
        return "NONE"
    
    for line in output.split("\n"):
        if line.startswith("default via "):
            parts = line.split()
            if len(parts) >= 3:
                gateway = parts[2]
                logger.debug(f"[{safe_name}] Gateway: {gateway}")
                return gateway
    
    logger.debug(f"[{safe_name}] No default gateway configured")
    return "NONE"


def get_route_metric(iface_name: str) -> str:
    """
    Get the routing metric for the default route on an interface.
    
    Lower metrics have higher priority in route selection.
    Returns the actual metric value from the kernel.
    No elevated privileges required.
    """
    safe_name = sanitize_for_log(iface_name)
    logger.debug(f"[{safe_name}] Querying route metric")
    
    output = run_command(["ip", "route", "show", "dev", iface_name])
    
    if output is None:
        logger.debug(f"[{safe_name}] No routes found")
        return "NONE"
    
    for line in output.split("\n"):
        if line.startswith("default via "):
            parts = line.split()
            
            if "metric" in parts:
                try:
                    metric_index = parts.index("metric")
                    if metric_index + 1 < len(parts):
                        metric = parts[metric_index + 1]
                        logger.debug(f"[{safe_name}] Metric: {metric}")
                        return metric
                except (ValueError, IndexError):
                    pass
            
            logger.debug(f"[{safe_name}] Metric: DEFAULT (kernel-assigned)")
            return "DEFAULT"
    
    logger.debug(f"[{safe_name}] No default route")
    return "NONE"


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
                        logger.debug(f"Active interface: {safe_iface}")
                        return iface
                except (ValueError, IndexError):
                    pass
    
    logger.warning("Could not parse default route output")
    return None
