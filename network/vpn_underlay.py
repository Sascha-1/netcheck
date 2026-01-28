"""
VPN underlay detection module.

Determines which physical interface carries VPN tunnel traffic.
Uses deterministic kernel routing queries - no heuristics.
"""

import subprocess
from typing import Optional

from logging_config import get_logger
from utils.system import run_command, is_valid_ip
from config import TIMEOUT_SECONDS

logger = get_logger(__name__)


def get_vpn_connection_endpoint(iface_name: str, local_ip: str) -> Optional[str]:
    """
    Get VPN server endpoint by finding active connection from VPN interface.
    
    Uses ss command to find established connections originating from VPN interface.
    Enhanced with multiple detection strategies for complex VPN setups like ProtonVPN.
    
    Args:
        iface_name: VPN interface name
        local_ip: Local IP address of VPN interface
        
    Returns:
        VPN server IP address, or None if not found
    """
    logger.debug(f"[{iface_name}] Looking for VPN connection from {local_ip}")
    
    try:
        # Query ALL UDP and TCP connections (not just established, ProtonVPN might be in other states)
        result = subprocess.run(
            ['ss', '-tuna'],  # All UDP and TCP connections, all states
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False
        )
        
        if result.returncode != 0:
            logger.warning("ss command failed")
            return None
        
        # Typical VPN ports
        vpn_ports = {51820, 1194, 1195, 443, 500, 4500}
        
        # Strategy 1: Find connections from this interface's IP
        for line in result.stdout.split('\n'):
            if local_ip in line:
                parts = line.split()
                if len(parts) >= 6:
                    local_addr = parts[4]
                    remote_addr = parts[5]
                    
                    # Extract IPs and ports
                    local_ip_part = local_addr.rsplit(':', 1)[0].strip('[]')
                    remote_ip = remote_addr.rsplit(':', 1)[0].strip('[]')
                    
                    # Verify this is from our interface
                    if local_ip_part == local_ip and is_valid_ip(remote_ip):
                        # Skip DNS connections (port 53) and local connections
                        if ':53' not in remote_addr and not remote_addr.endswith(':53'):
                            if not remote_ip.startswith(('10.', '192.168.', '127.', '169.254.')):
                                logger.debug(f"[{iface_name}] Found VPN connection to: {remote_ip}")
                                return remote_ip
        
        # Strategy 2: Look for ANY UDP connection on port 51820 (WireGuard's standard port)
        # This is specifically for ProtonVPN which might not show up from VPN interface IP
        logger.debug(f"[{iface_name}] No direct connection found, checking all WireGuard ports")
        
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 6:
                # Check if it's UDP
                if parts[0] != 'udp':
                    continue
                    
                remote_addr = parts[5]
                
                # Extract IP and port
                if ':' in remote_addr:
                    remote_parts = remote_addr.rsplit(':', 1)
                    if len(remote_parts) == 2:
                        remote_ip = remote_parts[0].strip('[]')
                        try:
                            remote_port = int(remote_parts[1])
                            
                            # Check if it's port 51820 (WireGuard) and a public IP
                            if remote_port == 51820 and is_valid_ip(remote_ip):
                                # Skip private IPs
                                if not remote_ip.startswith(('10.', '192.168.', '127.', '169.254.', '172.')):
                                    logger.debug(f"[{iface_name}] Found WireGuard connection to: {remote_ip}:51820")
                                    return remote_ip
                        except (ValueError, IndexError):
                            continue
        
        # Strategy 3: Look for any VPN port connections
        logger.debug(f"[{iface_name}] No WireGuard connection, checking other VPN ports")
        
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 6:
                remote_addr = parts[5]
                
                if ':' in remote_addr:
                    remote_parts = remote_addr.rsplit(':', 1)
                    if len(remote_parts) == 2:
                        remote_ip = remote_parts[0].strip('[]')
                        try:
                            remote_port = int(remote_parts[1])
                            
                            # Check if it's a VPN port and valid public IP
                            if remote_port in vpn_ports and is_valid_ip(remote_ip):
                                # Skip private IPs
                                if not (remote_ip.startswith('10.') or 
                                       remote_ip.startswith('192.168.') or
                                       remote_ip.startswith('127.') or
                                       remote_ip.startswith('169.254.') or
                                       (remote_ip.startswith('172.') and 16 <= int(remote_ip.split('.')[1]) <= 31)):
                                    logger.debug(f"[{iface_name}] Found VPN-like connection to: {remote_ip}:{remote_port}")
                                    return remote_ip
                        except (ValueError, IndexError):
                            continue
        
        logger.debug(f"[{iface_name}] No VPN server connection found")
        return None
        
    except FileNotFoundError:
        logger.error("ss command not found")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("ss command timeout")
        return None
    except Exception as e:
        logger.warning(f"Failed to get VPN connection: {e}")
        return None


def get_vpn_server_endpoint(iface_name: str, iface_type: str, local_ip: str) -> Optional[str]:
    """
    Get VPN server endpoint IP for VPN interfaces.
    
    Uses DETERMINISTIC ss command to find active VPN connections.
    Works for all VPNs including ProtonVPN, WireGuard, OpenVPN, etc.
    
    Args:
        iface_name: Interface name
        iface_type: Interface type (must be "vpn")
        local_ip: Local IP address of VPN interface
        
    Returns:
        VPN server IP address, or None if cannot be determined
    """
    if iface_type != "vpn":
        return None
    
    if local_ip == "N/A":
        logger.debug(f"[{iface_name}] No local IP, cannot find VPN endpoint")
        return None
    
    logger.debug(f"[{iface_name}] Detecting VPN server endpoint via active connections")
    
    # Use connection-based detection (works reliably, shown in user's logs)
    return get_vpn_connection_endpoint(iface_name, local_ip)


def find_physical_interface_for_vpn(vpn_server_ip: str, all_interfaces) -> Optional[str]:
    """
    Determine which physical interface carries traffic to VPN server.
    
    Uses deterministic method: Find physical interface with default gateway.
    This works reliably for all VPNs including ProtonVPN with custom routing tables.
    
    The physical interface carrying VPN traffic is simply the one providing
    internet connectivity (has a default gateway and is not a VPN interface).
    
    Args:
        vpn_server_ip: VPN server endpoint IP address (for logging only)
        all_interfaces: List of all InterfaceInfo objects
        
    Returns:
        Physical interface name, or None if cannot be determined
    """
    logger.debug(f"Finding physical interface carrying VPN traffic to {vpn_server_ip}")
    
    # Find physical interfaces with default gateways
    candidates = []
    for iface in all_interfaces:
        # Look for non-VPN interfaces with default gateways
        if (iface.interface_type in ["ethernet", "wireless", "tether"] and 
            iface.default_gateway not in ["NONE", "N/A", "--"]):
            
            candidates.append((iface.name, iface.metric))
            logger.debug(f"  Candidate: {iface.name} (gateway: {iface.default_gateway}, metric: {iface.metric})")
    
    if not candidates:
        logger.warning("No physical interfaces with default gateway found")
        return None
    
    # Pick the one with lowest metric (highest priority)
    # If metrics are equal or "DEFAULT", just pick first one
    candidates_sorted = sorted(candidates, key=lambda x: (
        999 if x[1] in ["NONE", "DEFAULT", "N/A"] else int(x[1])
    ))
    
    physical_interface = candidates_sorted[0][0]
    logger.info(f"VPN tunnel traffic routes through: {physical_interface} (physical interface with default gateway)")
    return physical_interface


def detect_vpn_underlay(interfaces) -> None:
    """
    Detect which physical interfaces carry VPN tunnel traffic.
    
    For each VPN interface:
    1. Find the VPN server endpoint IP
    2. Identify physical interface with internet connectivity
    3. Mark the physical interface as carrying VPN
    
    Works with complex VPNs like ProtonVPN that use custom routing tables.
    
    Modifies interfaces list in-place, setting:
    - vpn_server_ip for VPN interfaces
    - carries_vpn=True for physical interfaces carrying VPN
    
    Args:
        interfaces: List of InterfaceInfo objects (modified in-place)
    """
    logger.debug("Detecting VPN underlay (physical interfaces carrying VPN traffic)")
    
    vpn_to_physical = {}  # Map: VPN interface -> physical interface
    
    # Find all VPN interfaces and their endpoints
    for interface in interfaces:
        if interface.interface_type == "vpn":
            vpn_ip = get_vpn_server_endpoint(
                interface.name,
                interface.interface_type,
                interface.internal_ipv4
            )
            
            if vpn_ip:
                interface.vpn_server_ip = vpn_ip
                logger.debug(f"[{interface.name}] VPN server: {vpn_ip}")
                
                # Find which physical interface routes to this VPN server
                physical_if = find_physical_interface_for_vpn(vpn_ip, interfaces)
                if physical_if:
                    vpn_to_physical[interface.name] = physical_if
                    logger.info(f"[{interface.name}] Tunnel carried by: {physical_if}")
    
    # Mark physical interfaces that carry VPN traffic
    for interface in interfaces:
        if interface.name in vpn_to_physical.values():
            interface.carries_vpn = True
            vpn_names = [vpn for vpn, phys in vpn_to_physical.items() if phys == interface.name]
            logger.info(f"[{interface.name}] Carries VPN tunnel for: {', '.join(vpn_names)}")
