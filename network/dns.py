"""
DNS configuration and leak detection module.

Consolidates DNS server detection and DNS leak monitoring.
Queries DNS configuration using systemd-resolved (resolvectl).
Uses DETERMINISTIC configured DNS checking (no timing dependencies).
Requires systemd-resolved to be active.
"""

import subprocess
from typing import List, Tuple, Optional, Set

from logging_config import get_logger
from config import TIMEOUT_SECONDS
from utils.system import is_valid_ip

logger = get_logger(__name__)


# ============================================================================
# DNS Configuration Detection
# ============================================================================

def get_interface_dns(iface_name: str) -> Tuple[List[str], Optional[str]]:
    """
    Get ALL DNS servers configured for interface AND which one is currently active.
    
    Uses resolvectl to query systemd-resolved for per-interface DNS configuration.
    Returns both the complete list and the currently active DNS server.
    
    Args:
        iface_name: Network interface name
        
    Returns:
        Tuple of (all_dns_servers, current_dns_server)
        - all_dns_servers: List of all configured DNS (IPv4 and IPv6)
        - current_dns_server: The DNS server currently being used (or None)
    """
    logger.debug(f"[{iface_name}] Querying DNS configuration")
    
    try:
        result = subprocess.run(
            ["resolvectl", "status", iface_name],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False
        )
        
        if result.returncode != 0:
            logger.debug(f"[{iface_name}] resolvectl query failed (not configured or no systemd-resolved)")
            return [], None
        
        dns_servers: List[str] = []
        current_dns: Optional[str] = None
        in_dns_section = False
        
        for line in result.stdout.split('\n'):
            line_stripped = line.strip()
            
            if not line_stripped:
                continue
            
            # Look for "Current DNS Server:" (the one actively being used)
            if "Current DNS Server:" in line:
                if len(parts := line.split(':', 1)) == 2:
                    dns_part = parts[1].strip()
                    # Take first IP (in case multiple listed)
                    for dns in dns_part.split():
                        if is_valid_ip(dns):
                            current_dns = dns
                            # Also add to full list if not already there
                            if dns not in dns_servers:
                                dns_servers.insert(0, dns)  # Put current first
                            logger.debug(f"[{iface_name}] Current DNS: {current_dns}")
                            break
                continue
            
            # Look for "DNS Servers:" section
            if "DNS Servers:" in line:
                in_dns_section = True
                if len(parts := line.split(':', 1)) == 2:
                    dns_part = parts[1].strip()
                    for dns in dns_part.split():
                        if is_valid_ip(dns) and dns not in dns_servers:
                            dns_servers.append(dns)
                continue
            
            # Additional DNS servers on following lines
            if in_dns_section and line_stripped:
                if line[0].isspace() or line_stripped[0].isdigit() or ':' in line_stripped:
                    for dns in line_stripped.split():
                        if is_valid_ip(dns) and dns not in dns_servers:
                            dns_servers.append(dns)
                    continue
            
            # End DNS section on new labeled section
            if in_dns_section and line and not line[0].isspace():
                if ':' in line and not is_valid_ip(line.split(':')[0].strip()):
                    in_dns_section = False
        
        if dns_servers:
            if current_dns:
                logger.debug(f"[{iface_name}] DNS servers: {', '.join(dns_servers)} (current: {current_dns})")
            else:
                logger.debug(f"[{iface_name}] DNS servers: {', '.join(dns_servers)}")
        else:
            logger.debug(f"[{iface_name}] No DNS servers configured")
        
        return dns_servers, current_dns
        
    except subprocess.TimeoutExpired:
        logger.warning(f"[{iface_name}] resolvectl timeout")
        return [], None
    except FileNotFoundError:
        logger.error("resolvectl not found (systemd-resolved not installed)")
        return [], None
    except Exception as e:
        logger.error(f"[{iface_name}] Failed to get DNS: {e}")
        return [], None


def get_system_dns() -> List[str]:
    """
    Get the system-wide DNS servers currently in use.
    
    Queries the global DNS configuration from systemd-resolved.
    
    Returns:
        List of all DNS server IP addresses (IPv4 and IPv6)
    """
    logger.debug("Querying system-wide DNS configuration")
    
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
        
        dns_servers = []
        in_global_section = False
        in_dns_section = False
        
        for line in result.stdout.split('\n'):
            line_stripped = line.strip()
            
            if not line_stripped:
                continue
            
            # Look for Global section
            if "Global" in line:
                in_global_section = True
                continue
            
            # End of global section
            if "Link " in line and in_global_section:
                in_global_section = False
                break
            
            if in_global_section:
                # Look for DNS Servers
                if "DNS Servers:" in line:
                    in_dns_section = True
                    if len(parts := line.split(':', 1)) > 1:
                        dns_part = parts[1].strip()
                        for dns in dns_part.split():
                            if is_valid_ip(dns) and dns not in dns_servers:
                                dns_servers.append(dns)
                    continue
                
                # Additional DNS servers
                if in_dns_section and line_stripped:
                    if line[0].isspace() or line_stripped[0].isdigit() or ':' in line_stripped:
                        for dns in line_stripped.split():
                            if is_valid_ip(dns) and dns not in dns_servers:
                                dns_servers.append(dns)
                        continue
                
                # End DNS section
                if in_dns_section and line and not line[0].isspace():
                    if ':' in line and not is_valid_ip(line.split(':')[0].strip()):
                        in_dns_section = False
        
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
    
    Args:
        interface_name: Network interface name
        interface_ip: IP address of this interface
        configured_dns: DNS servers configured for this interface
        is_vpn: True if this is a VPN interface
        vpn_dns: List of known VPN DNS servers
        isp_dns: List of known ISP DNS servers
        
    Returns:
        "OK" - No leak detected (using VPN DNS or other safe DNS)
        "LEAK" - DNS leak detected (using ISP DNS)
        "WARN" - Using unknown DNS servers
        "--" - Not applicable (no VPN active)
    """
    # Only check for leaks if VPN is active somewhere
    if not vpn_dns:
        return "--"
    
    # No DNS configured on this interface
    if not configured_dns:
        return "--"
    
    # Check configured DNS servers (deterministic)
    logger.debug(f"[{interface_name}] Checking configured DNS: {configured_dns}")
    
    # Check if any configured DNS is ISP DNS (LEAK)
    if leaking_dns := [dns for dns in configured_dns if dns in isp_dns]:
        logger.warning(f"[{interface_name}] LEAK: Configured with ISP DNS {leaking_dns}")
        return "LEAK"
    
    # Check if any configured DNS is VPN DNS (OK)
    if vpn_configured := [dns for dns in configured_dns if dns in vpn_dns]:
        logger.debug(f"[{interface_name}] OK: Configured with VPN DNS {vpn_configured}")
        return "OK"
    
    # Check if using other public DNS (Cloudflare, Google, Quad9, etc.) - OK
    public_dns = {
        "1.1.1.1", "1.0.0.1",  # Cloudflare
        "8.8.8.8", "8.8.4.4",  # Google
        "9.9.9.9", "149.112.112.112",  # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare IPv6
        "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google IPv6
    }
    
    if public_configured := [dns for dns in configured_dns if dns in public_dns]:
        logger.debug(f"[{interface_name}] OK: Using public DNS {public_configured}")
        return "OK"
    
    # Unknown DNS servers (neither VPN, ISP, nor known public)
    logger.warning(f"[{interface_name}] WARN: Using unknown DNS {configured_dns}")
    return "WARN"


def collect_dns_servers_by_category(interfaces) -> Tuple[List[str], List[str]]:
    """
    Categorize DNS servers as VPN or ISP.
    
    Args:
        interfaces: List of InterfaceInfo objects
        
    Returns:
        Tuple of (vpn_dns_list, isp_dns_list)
    """
    vpn_dns = []
    isp_dns = []
    
    for interface in interfaces:
        if interface.dns_servers:
            if interface.interface_type == "vpn":
                vpn_dns.extend(interface.dns_servers)
            elif interface.interface_type in ["ethernet", "wireless", "tether"]:
                isp_dns.extend(interface.dns_servers)
    
    # Remove duplicates
    return list(set(vpn_dns)), list(set(isp_dns))


def check_dns_leaks_all_interfaces(interfaces) -> None:
    """
    Check for DNS leaks across all interfaces.
    
    Updates each InterfaceInfo object with dns_leak_status.
    
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
            interface.dns_leak_status = "--"
            continue
        
        leak_status = detect_dns_leak(
            interface_name=interface.name,
            interface_ip=interface.internal_ipv4,
            configured_dns=interface.dns_servers,
            is_vpn=(interface.interface_type == "vpn"),
            vpn_dns=vpn_dns,
            isp_dns=isp_dns
        )
        
        interface.dns_leak_status = leak_status
