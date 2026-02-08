"""
DNS configuration and leak detection module.

Consolidates DNS server detection and DNS leak monitoring.
Queries DNS configuration using systemd-resolved (resolvectl).
Uses deterministic configured DNS checking with no timing dependencies.

Thread-safe DNS queries with optimized deduplication.
No elevated privileges required.
"""

import subprocess
import threading
from typing import List, Tuple, Optional, Dict, Set, TYPE_CHECKING

from logging_config import get_logger
from config import (
    TIMEOUT_SECONDS,
    PUBLIC_DNS_SERVERS,
    DNS_CURRENT_SERVER_MARKER,
    DNS_SERVERS_MARKER,
    DNS_GLOBAL_SECTION_MARKER,
    DNS_LINK_SECTION_MARKER,
)
from utils.system import is_valid_ip, sanitize_for_log
from enums import DnsLeakStatus, InterfaceType

if TYPE_CHECKING:
    from models import InterfaceInfo

logger = get_logger(__name__)

_dns_query_lock = threading.Lock()


def _extract_ips_from_text(text: str) -> List[str]:
    """Extract all valid IP addresses from space-separated text."""
    return [token for token in text.split() if is_valid_ip(token)]


def _parse_dns_section(lines: List[str], start_marker: str = DNS_SERVERS_MARKER) -> List[str]:
    """
    Parse DNS server IPs from resolvectl output section.

    Handles multi-line format where DNS servers can appear on
    the same line as marker or following indented lines.
    Uses dict as ordered set for efficient deduplication.
    """
    dns_servers: Dict[str, None] = {}
    in_section = False

    for line in lines:
        line_stripped = line.strip()

        if not line_stripped:
            continue

        if start_marker in line:
            in_section = True
            if ':' in line:
                dns_part = line.split(':', 1)[1].strip()
                for ip in _extract_ips_from_text(dns_part):
                    dns_servers[ip] = None
            continue

        if in_section and line_stripped:
            if line[0].isspace() or line_stripped[0].isdigit() or line_stripped[0] == ':':
                for ip in _extract_ips_from_text(line_stripped):
                    dns_servers[ip] = None
                continue

            if ':' in line and not is_valid_ip(line.split(':')[0].strip()):
                break

    return list(dns_servers.keys())


def _extract_current_dns(lines: List[str]) -> Optional[str]:
    """Extract the currently active DNS server from resolvectl output."""
    for line in lines:
        if DNS_CURRENT_SERVER_MARKER in line:
            if ':' in line:
                dns_part = line.split(':', 1)[1].strip()
                ips = _extract_ips_from_text(dns_part)
                return ips[0] if ips else None
    return None


def _check_dns_overlap(configured: List[str], reference_set: Set[str]) -> Optional[List[str]]:
    """
    Check if any configured DNS servers overlap with reference set.

    FIXED: Returns None (not empty list) when there's no overlap.

    Args:
        configured: List of configured DNS servers
        reference_set: Set of reference DNS servers to check against

    Returns:
        List of overlapping DNS servers, or None if no overlap
    """
    if not configured or not reference_set:
        return None

    overlapping = [dns for dns in configured if dns in reference_set]
    return overlapping if overlapping else None


def _check_isp_dns_leak(configured_dns: List[str], isp_dns: List[str]) -> Optional[List[str]]:
    """Check if any configured DNS servers are ISP DNS (leak)."""
    leaking = [dns for dns in configured_dns if dns in isp_dns]
    return leaking if leaking else None


def _check_vpn_dns_usage(configured_dns: List[str], vpn_dns: List[str]) -> Optional[List[str]]:
    """Check if any configured DNS servers are VPN DNS (secure)."""
    vpn_configured = [dns for dns in configured_dns if dns in vpn_dns]
    return vpn_configured if vpn_configured else None


def _check_public_dns_usage(configured_dns: List[str]) -> Optional[List[str]]:
    """
    Check if using well-known public DNS providers (acceptable when VPN active).

    Recognizes major public DNS providers defined in config.PUBLIC_DNS_SERVERS.
    """
    public_configured = [dns for dns in configured_dns if dns in PUBLIC_DNS_SERVERS]
    return public_configured if public_configured else None


def get_interface_dns(iface_name: str) -> Tuple[List[str], Optional[str]]:
    """
    Get ALL DNS servers configured for interface AND which one is currently active.

    Uses resolvectl to query systemd-resolved for per-interface DNS configuration.
    Thread-safe to prevent race conditions during VPN connect/disconnect operations.

    Returns:
        Tuple of (all_dns_servers, current_dns_server)
    """
    safe_name = sanitize_for_log(iface_name)
    logger.debug("[%s] Querying DNS configuration", safe_name)

    with _dns_query_lock:
        try:
            result = subprocess.run(
                ["resolvectl", "status", iface_name],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                check=False
            )

            if result.returncode != 0:
                logger.debug("[%s] resolvectl query failed", safe_name)
                return [], None

            lines = result.stdout.split('\n')

            current_dns = _extract_current_dns(lines)
            dns_servers = _parse_dns_section(lines)

            if current_dns:
                if current_dns in dns_servers:
                    dns_servers.remove(current_dns)
                dns_servers.insert(0, current_dns)

            if dns_servers:
                if current_dns:
                    safe_current = sanitize_for_log(current_dns)
                    logger.debug("[%s] DNS servers: %s (current: %s)",
                               safe_name, ", ".join(dns_servers), safe_current)
                else:
                    logger.debug("[%s] DNS servers: %s", safe_name, ", ".join(dns_servers))
            else:
                logger.debug("[%s] No DNS servers configured", safe_name)

            return dns_servers, current_dns

        except subprocess.TimeoutExpired:
            logger.warning("[%s] resolvectl timeout", safe_name)
            return [], None
        except FileNotFoundError:
            logger.error("resolvectl not found (systemd-resolved not installed)")
            return [], None
        except Exception as e:
            logger.error("[%s] Failed to get DNS: %s", safe_name, e)
            return [], None


def get_system_dns() -> List[str]:
    """
    Get the system-wide DNS servers currently in use.

    Queries the global DNS configuration from systemd-resolved.
    Thread-safe.
    """
    logger.debug("Querying system-wide DNS configuration")

    with _dns_query_lock:
        try:
            result = subprocess.run(
                ["resolvectl", "status"],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                check=False
            )

            if result.returncode != 0:
                logger.warning("System DNS: resolvectl query failed")
                return []

            lines = result.stdout.split('\n')

            global_lines = []
            in_global = False

            for line in lines:
                line_stripped = line.strip()

                if not line_stripped:
                    continue

                if DNS_GLOBAL_SECTION_MARKER in line:
                    in_global = True
                    continue

                if DNS_LINK_SECTION_MARKER in line and in_global:
                    break

                if in_global:
                    global_lines.append(line)

            dns_servers = _parse_dns_section(global_lines)

            if dns_servers:
                logger.debug("System-wide DNS: %s", ", ".join(dns_servers))
            else:
                logger.debug("System-wide DNS: None configured")

            return dns_servers

        except subprocess.TimeoutExpired:
            logger.warning("System DNS: resolvectl timeout")
            return []
        except FileNotFoundError:
            logger.error("System DNS: resolvectl not found")
            return []
        except Exception as e:
            logger.error("System DNS: Failed to query: %s", e)
            return []


def detect_dns_leak(interface_name: str,
                   interface_ip: str,  # pylint: disable=unused-argument
                   configured_dns: List[str],
                   is_vpn: bool,  # pylint: disable=unused-argument
                   vpn_dns: List[str],
                   isp_dns: List[str]) -> str:
    """
    Detect if DNS queries leak to ISP when VPN is active.

    Uses deterministic method: checks configured DNS servers.
    No timing-dependent connection monitoring.
    No elevated privileges required.
    """
    safe_name = sanitize_for_log(interface_name)

    if not vpn_dns:
        return str(DnsLeakStatus.NOT_APPLICABLE)

    if not configured_dns:
        return str(DnsLeakStatus.NOT_APPLICABLE)

    logger.debug("[%s] Checking configured DNS: %s", safe_name, configured_dns)

    if leaking_dns := _check_isp_dns_leak(configured_dns, isp_dns):
        logger.warning("[%s] LEAK: Configured with ISP DNS %s", safe_name, leaking_dns)
        return str(DnsLeakStatus.LEAK)

    if vpn_configured := _check_vpn_dns_usage(configured_dns, vpn_dns):
        logger.debug("[%s] OK: Configured with VPN DNS %s", safe_name, vpn_configured)
        return str(DnsLeakStatus.OK)

    if public_configured := _check_public_dns_usage(configured_dns):
        logger.debug("[%s] OK: Using public DNS %s", safe_name, public_configured)
        return str(DnsLeakStatus.OK)

    logger.warning("[%s] WARN: Using unknown DNS %s", safe_name, configured_dns)
    return str(DnsLeakStatus.WARN)


def collect_dns_servers_by_category(interfaces: List["InterfaceInfo"]) -> Tuple[List[str], List[str]]:
    """Categorize DNS servers as VPN or ISP."""
    vpn_dns: List[str] = []
    isp_dns: List[str] = []

    for interface in interfaces:
        if interface.dns_servers:
            if interface.interface_type == str(InterfaceType.VPN):
                vpn_dns.extend(interface.dns_servers)
            elif interface.interface_type in [
                str(InterfaceType.ETHERNET),
                str(InterfaceType.WIRELESS),
                str(InterfaceType.TETHER)
            ]:
                isp_dns.extend(interface.dns_servers)

    return list(set(vpn_dns)), list(set(isp_dns))


def check_dns_leaks_all_interfaces(interfaces: List["InterfaceInfo"]) -> None:
    """
    Check for DNS leaks across all interfaces.

    Updates each InterfaceInfo object with dns_leak_status.
    No elevated privileges required.
    """
    logger.debug("Checking for DNS leaks...")

    vpn_dns, isp_dns = collect_dns_servers_by_category(interfaces)

    if vpn_dns:
        logger.debug("VPN DNS servers: %s", ", ".join(vpn_dns))
        if isp_dns:
            logger.debug("ISP DNS servers: %s", ", ".join(isp_dns))

    for interface in interfaces:
        if interface.internal_ipv4 == "N/A":
            interface.dns_leak_status = str(DnsLeakStatus.NOT_APPLICABLE)
            continue

        leak_status = detect_dns_leak(
            interface_name=interface.name,
            interface_ip=interface.internal_ipv4,
            configured_dns=interface.dns_servers,
            is_vpn=(interface.interface_type == str(InterfaceType.VPN)),
            vpn_dns=vpn_dns,
            isp_dns=isp_dns
        )

        interface.dns_leak_status = leak_status
