"""
DNS configuration and leak detection module.

Consolidates DNS server detection and DNS leak monitoring.
Queries DNS configuration using systemd-resolved (resolvectl).
Uses DETERMINISTIC configured DNS checking (no timing dependencies).

IMPROVEMENTS:
- Thread-safe DNS queries (fixes race condition #3)
- Optimized deduplication (fixes #13)
- No elevated privileges required

Requires:
    systemd-resolved to be active (no sudo needed)
"""

import subprocess
import threading
from typing import List, Tuple, Optional, Set, TYPE_CHECKING, Dict

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


# ============================================================================
# Thread Safety: DNS Query Lock (Fix #3 - Race Condition)
# ============================================================================

# Global lock to ensure atomic DNS state snapshots
# Prevents race condition during VPN connect/disconnect
# Uses threading.Lock (no file system access, no sudo required)
_dns_query_lock = threading.Lock()


# ============================================================================
# Private Helper Functions
# ============================================================================

def _extract_ips_from_text(text: str) -> List[str]:
    """
    Extract all valid IP addresses from space-separated text.
    
    Args:
        text: String containing space-separated tokens
        
    Returns:
        List of valid IP addresses found in text
        
    Examples:
        >>> _extract_ips_from_text("8.8.8.8 8.8.4.4 invalid")
        ['8.8.8.8', '8.8.4.4']
    """
    return [token for token in text.split() if is_valid_ip(token)]


def _parse_dns_section(lines: List[str], start_marker: str = DNS_SERVERS_MARKER) -> List[str]:
    """
    Parse DNS server IPs from resolvectl output section.
    
    Handles the multi-line format where DNS servers can appear on:
    1. Same line as marker: "DNS Servers: 8.8.8.8 8.8.4.4"
    2. Following indented lines
    
    OPTIMIZED (Fix #13): Uses dict as ordered set for efficient deduplication
    
    Args:
        lines: Lines from resolvectl output
        start_marker: Section start marker (e.g., "DNS Servers:")
        
    Returns:
        List of unique DNS server IPs (preserves order)
    """
    # Use dict for O(1) lookup and order preservation (Fix #13)
    dns_servers: Dict[str, None] = {}
    in_section = False
    
    for line in lines:
        line_stripped = line.strip()
        
        # Skip empty lines
        if not line_stripped:
            continue
        
        # Start of DNS section
        if start_marker in line:
            in_section = True
            # Extract IPs from same line if present
            if ':' in line:
                dns_part = line.split(':', 1)[1].strip()
                for ip in _extract_ips_from_text(dns_part):
                    dns_servers[ip] = None
            continue
        
        # Process continuation lines (indented or IP-like)
        if in_section and line_stripped:
            # Check if line is indented or starts with digit/colon (IPv4/IPv6)
            if line[0].isspace() or line_stripped[0].isdigit() or line_stripped[0] == ':':
                for ip in _extract_ips_from_text(line_stripped):
                    dns_servers[ip] = None
                continue
            
            # End of section: non-indented line with colon (new section header)
            if ':' in line and not is_valid_ip(line.split(':')[0].strip()):
                break
    
    # Return list of keys (already deduplicated, order preserved)
    return list(dns_servers.keys())


def _extract_current_dns(lines: List[str]) -> Optional[str]:
    """
    Extract the currently active DNS server from resolvectl output.
    
    Args:
        lines: Lines from resolvectl output
        
    Returns:
        First DNS server IP from "Current DNS Server:" line, or None
    """
    for line in lines:
        if DNS_CURRENT_SERVER_MARKER in line:
            if ':' in line:
                dns_part = line.split(':', 1)[1].strip()
                ips = _extract_ips_from_text(dns_part)
                return ips[0] if ips else None
    return None


def _check_isp_dns_leak(configured_dns: List[str], isp_dns: List[str]) -> Optional[List[str]]:
    """
    Check if any configured DNS servers are ISP DNS (leak).
    
    Args:
        configured_dns: DNS servers configured on interface
        isp_dns: Known ISP DNS servers
        
    Returns:
        List of leaking DNS servers, or None if no leak
    """
    leaking = [dns for dns in configured_dns if dns in isp_dns]
    return leaking if leaking else None


def _check_vpn_dns_usage(configured_dns: List[str], vpn_dns: List[str]) -> Optional[List[str]]:
    """
    Check if any configured DNS servers are VPN DNS (secure).
    
    Args:
        configured_dns: DNS servers configured on interface
        vpn_dns: Known VPN DNS servers
        
    Returns:
        List of VPN DNS servers in use, or None if none found
    """
    vpn_configured = [dns for dns in configured_dns if dns in vpn_dns]
    return vpn_configured if vpn_configured else None


def _check_public_dns_usage(configured_dns: List[str]) -> Optional[List[str]]:
    """
    Check if using well-known public DNS providers (acceptable when VPN active).
    
    Recognizes major public DNS providers defined in config.PUBLIC_DNS_SERVERS.
    
    Args:
        configured_dns: DNS servers configured on interface
        
    Returns:
        List of public DNS servers in use, or None if none found
    """
    public_configured = [dns for dns in configured_dns if dns in PUBLIC_DNS_SERVERS]
    return public_configured if public_configured else None


# ============================================================================
# DNS Configuration Detection (Thread-Safe)
# ============================================================================

def get_interface_dns(iface_name: str) -> Tuple[List[str], Optional[str]]:
    """
    Get ALL DNS servers configured for interface AND which one is currently active.
    
    Uses resolvectl to query systemd-resolved for per-interface DNS configuration.
    Returns both the complete list and the currently active DNS server.
    
    Thread-Safe (Fix #3): Acquires lock to prevent race conditions during
    VPN connect/disconnect operations.
    
    Args:
        iface_name: Network interface name
        
    Returns:
        Tuple of (all_dns_servers, current_dns_server)
        - all_dns_servers: List of all configured DNS (IPv4 and IPv6)
        - current_dns_server: The DNS server currently being used (or None)
        
    Security:
        No elevated privileges required - reads systemd-resolved config only
    """
    safe_name = sanitize_for_log(iface_name)
    logger.debug(f"[{safe_name}] Querying DNS configuration")
    
    # THREAD SAFETY: Acquire lock for atomic DNS state snapshot (Fix #3)
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
                logger.debug(f"[{safe_name}] resolvectl query failed (not configured or no systemd-resolved)")
                return [], None
            
            lines = result.stdout.split('\n')
            
            # Extract current DNS (single line)
            current_dns = _extract_current_dns(lines)
            
            # Extract all DNS servers (optimized deduplication - Fix #13)
            dns_servers = _parse_dns_section(lines)
            
            # Ensure current DNS is first in list
            if current_dns:
                if current_dns in dns_servers:
                    dns_servers.remove(current_dns)
                dns_servers.insert(0, current_dns)
            
            # Logging
            if dns_servers:
                if current_dns:
                    safe_current = sanitize_for_log(current_dns)
                    logger.debug(f"[{safe_name}] DNS servers: {', '.join(dns_servers)} (current: {safe_current})")
                else:
                    logger.debug(f"[{safe_name}] DNS servers: {', '.join(dns_servers)}")
            else:
                logger.debug(f"[{safe_name}] No DNS servers configured")
            
            return dns_servers, current_dns
            
        except subprocess.TimeoutExpired:
            logger.warning(f"[{safe_name}] resolvectl timeout")
            return [], None
        except FileNotFoundError:
            logger.error("resolvectl not found (systemd-resolved not installed)")
            return [], None
        except Exception as e:
            logger.error(f"[{safe_name}] Failed to get DNS: {e}")
            return [], None


def get_system_dns() -> List[str]:
    """
    Get the system-wide DNS servers currently in use.
    
    Queries the global DNS configuration from systemd-resolved.
    
    Thread-Safe (Fix #3): Acquires lock for consistency.
    
    Returns:
        List of all DNS server IP addresses (IPv4 and IPv6)
        
    Security:
        No elevated privileges required
    """
    logger.debug("Querying system-wide DNS configuration")
    
    # THREAD SAFETY: Acquire lock (Fix #3)
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
            
            # Extract Global section
            global_lines = []
            in_global = False
            
            for line in lines:
                line_stripped = line.strip()
                
                if not line_stripped:
                    continue
                
                # Start of Global section
                if DNS_GLOBAL_SECTION_MARKER in line:
                    in_global = True
                    continue
                
                # End of Global section (Link section starts)
                if DNS_LINK_SECTION_MARKER in line and in_global:
                    break
                
                if in_global:
                    global_lines.append(line)
            
            # Parse DNS from Global section (optimized - Fix #13)
            dns_servers = _parse_dns_section(global_lines)
            
            if dns_servers:
                logger.debug(f"System-wide DNS: {', '.join(dns_servers)}")
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
            logger.error(f"System DNS: Failed to query: {e}")
            return []


# ============================================================================
# DNS Leak Detection
# ============================================================================

def detect_dns_leak(interface_name: str, 
                   interface_ip: str,
                   configured_dns: List[str],
                   is_vpn: bool,
                   vpn_dns: List[str],
                   isp_dns: List[str]) -> str:
    """
    Detect if DNS queries leak to ISP when VPN is active.
    
    Uses DETERMINISTIC method: checks configured DNS servers.
    No timing-dependent connection monitoring.
    No elevated privileges required.
    
    Args:
        interface_name: Network interface name
        interface_ip: IP address of this interface
        configured_dns: DNS servers configured for this interface
        is_vpn: True if this is a VPN interface
        vpn_dns: List of known VPN DNS servers
        isp_dns: List of known ISP DNS servers
        
    Returns:
        DnsLeakStatus value:
        - OK: No leak detected (using VPN DNS or other safe DNS)
        - LEAK: DNS leak detected (using ISP DNS)
        - WARN: Using unknown DNS servers
        - NOT_APPLICABLE: Not applicable (no VPN active)
    """
    safe_name = sanitize_for_log(interface_name)
    
    # Only check for leaks if VPN is active somewhere
    if not vpn_dns:
        return str(DnsLeakStatus.NOT_APPLICABLE)
    
    # No DNS configured on this interface
    if not configured_dns:
        return str(DnsLeakStatus.NOT_APPLICABLE)
    
    logger.debug(f"[{safe_name}] Checking configured DNS: {configured_dns}")
    
    # Check for ISP DNS leak (CRITICAL)
    if leaking_dns := _check_isp_dns_leak(configured_dns, isp_dns):
        logger.warning(f"[{safe_name}] LEAK: Configured with ISP DNS {leaking_dns}")
        return str(DnsLeakStatus.LEAK)
    
    # Check for VPN DNS usage (SECURE)
    if vpn_configured := _check_vpn_dns_usage(configured_dns, vpn_dns):
        logger.debug(f"[{safe_name}] OK: Configured with VPN DNS {vpn_configured}")
        return str(DnsLeakStatus.OK)
    
    # Check for public DNS usage (ACCEPTABLE)
    if public_configured := _check_public_dns_usage(configured_dns):
        logger.debug(f"[{safe_name}] OK: Using public DNS {public_configured}")
        return str(DnsLeakStatus.OK)
    
    # Unknown DNS servers (SUSPICIOUS)
    logger.warning(f"[{safe_name}] WARN: Using unknown DNS {configured_dns}")
    return str(DnsLeakStatus.WARN)


def collect_dns_servers_by_category(interfaces: List["InterfaceInfo"]) -> Tuple[List[str], List[str]]:
    """
    Categorize DNS servers as VPN or ISP.
    
    Args:
        interfaces: List of InterfaceInfo objects
        
    Returns:
        Tuple of (vpn_dns_list, isp_dns_list)
    """
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
    
    # Remove duplicates
    return list(set(vpn_dns)), list(set(isp_dns))


def check_dns_leaks_all_interfaces(interfaces: List["InterfaceInfo"]) -> None:
    """
    Check for DNS leaks across all interfaces.
    
    Updates each InterfaceInfo object with dns_leak_status.
    No elevated privileges required.
    
    Args:
        interfaces: List of InterfaceInfo objects (will be modified in-place)
    """
    logger.debug("Checking for DNS leaks...")
    
    # Categorize DNS servers
    vpn_dns, isp_dns = collect_dns_servers_by_category(interfaces)
    
    if vpn_dns:
        logger.debug(f"VPN DNS servers: {', '.join(vpn_dns)}")
        if isp_dns:
            logger.debug(f"ISP DNS servers: {', '.join(isp_dns)}")
    
    # Check each interface
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
