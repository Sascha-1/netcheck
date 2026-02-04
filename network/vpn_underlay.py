"""
VPN underlay detection module.

Determines which physical interface carries VPN tunnel traffic.
Uses deterministic kernel routing queries.

IMPROVED:
- Uses enums directly without str() conversions
- Port 443 removed from COMMON_VPN_PORTS to avoid false positives
"""

import subprocess
from typing import Optional, List, TYPE_CHECKING

from logging_config import get_logger
from utils.system import run_command, is_valid_ip, sanitize_for_log
from config import TIMEOUT_SECONDS, COMMON_VPN_PORTS
from enums import InterfaceType

if TYPE_CHECKING:
    from models import InterfaceInfo

logger = get_logger(__name__)


def get_vpn_connection_endpoint(iface_name: str, local_ip: str) -> Optional[str]:
    """
    Get VPN server endpoint by finding active connection from VPN interface.

    Uses ss command to find established connections originating from VPN interface.
    Enhanced with multiple detection strategies for complex VPN setups.

    Strategy:
    1. Look for connections from this interface's IP
    2. Check for WireGuard connections (port 51820) to public IPs
    3. Check for other common VPN ports (OpenVPN, IKEv2, etc.)

    NOTE: Port 443 was removed from COMMON_VPN_PORTS as it caused false positives
    with HTTPS traffic (Google services, CDNs, etc.)
    """
    safe_name = sanitize_for_log(iface_name)
    safe_ip = sanitize_for_log(local_ip)

    logger.debug(f"[{safe_name}] Looking for VPN connection from {safe_ip}")

    try:
        result = subprocess.run(
            ['ss', '-tuna'],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False
        )

        if result.returncode != 0:
            logger.warning("ss command failed")
            return None

        vpn_ports = set(COMMON_VPN_PORTS.keys())

        # Strategy 1: Look for direct connections from VPN interface IP
        for line in result.stdout.split('\n'):
            if local_ip in line:
                parts = line.split()
                if len(parts) >= 6:
                    state = parts[1]
                    if state not in ('ESTAB', 'ESTABLISHED'):
                        continue

                    local_addr = parts[4]
                    remote_addr = parts[5]

                    local_ip_part = local_addr.rsplit(':', 1)[0].strip('[]')
                    remote_ip = remote_addr.rsplit(':', 1)[0].strip('[]')

                    if remote_ip in ('0.0.0.0', '*', '::', '[::]'):
                        continue

                    if local_ip_part == local_ip and is_valid_ip(remote_ip):
                        # Skip DNS (port 53)
                        if ':53' not in remote_addr and not remote_addr.endswith(':53'):
                            # Skip private IPs
                            if remote_ip.startswith(('10.', '192.168.', '127.', '169.254.')):
                                continue
                            # Skip CGNAT range (100.64.0.0/10)
                            if remote_ip.startswith('100.'):
                                try:
                                    second_octet = int(remote_ip.split('.')[1])
                                    if 64 <= second_octet <= 127:
                                        continue
                                except (ValueError, IndexError):
                                    pass
                            # Skip private range 172.16.0.0/12
                            if remote_ip.startswith('172.'):
                                try:
                                    second_octet = int(remote_ip.split('.')[1])
                                    if 16 <= second_octet <= 31:
                                        continue
                                except (ValueError, IndexError):
                                    pass

                            logger.debug(f"[{safe_name}] Found VPN connection to: {sanitize_for_log(remote_ip)}")
                            return remote_ip

        # Strategy 2: Check for WireGuard (port 51820) to public IPs
        logger.debug(f"[{safe_name}] No direct connection found, checking all WireGuard ports")

        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 6:
                if parts[0] != 'udp':
                    continue
                state = parts[1]
                if state not in ('ESTAB', 'ESTABLISHED'):
                    continue

                remote_addr = parts[5]

                if remote_addr.startswith(('0.0.0.0:', '*:', '[::]:')):
                    continue

                if ':' in remote_addr:
                    remote_parts = remote_addr.rsplit(':', 1)
                    if len(remote_parts) == 2:
                        remote_ip = remote_parts[0].strip('[]')

                        if remote_ip in ('0.0.0.0', '*', '::'):
                            continue

                        try:
                            remote_port = int(remote_parts[1])

                            if remote_port == 51820 and is_valid_ip(remote_ip):
                                # Skip private IPs
                                if remote_ip.startswith(('10.', '192.168.', '127.', '169.254.')):
                                    continue
                                if remote_ip.startswith('100.'):
                                    second_octet = int(remote_ip.split('.')[1])
                                    if 64 <= second_octet <= 127:
                                        continue
                                if remote_ip.startswith('172.'):
                                    second_octet = int(remote_ip.split('.')[1])
                                    if 16 <= second_octet <= 31:
                                        continue

                                protocol = COMMON_VPN_PORTS.get(remote_port, "Unknown")
                                logger.debug(f"[{safe_name}] Found {protocol} connection to: {sanitize_for_log(remote_ip)}:51820")
                                return remote_ip
                        except (ValueError, IndexError):
                            continue

        # Strategy 3: Check for other VPN ports
        logger.debug(f"[{safe_name}] No WireGuard connection, checking other VPN ports")

        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 6:
                state = parts[1]
                if state not in ('ESTAB', 'ESTABLISHED'):
                    continue

                remote_addr = parts[5]

                if remote_addr.startswith(('0.0.0.0:', '*:', '[::]:')):
                    continue

                if ':' in remote_addr:
                    remote_parts = remote_addr.rsplit(':', 1)
                    if len(remote_parts) == 2:
                        remote_ip = remote_parts[0].strip('[]')

                        if remote_ip in ('0.0.0.0', '*', '::'):
                            continue

                        try:
                            remote_port = int(remote_parts[1])

                            if remote_port in vpn_ports and is_valid_ip(remote_ip):
                                # Skip private IPs
                                if remote_ip.startswith(('10.', '192.168.', '127.', '169.254.')):
                                    continue
                                if remote_ip.startswith('100.'):
                                    second_octet = int(remote_ip.split('.')[1])
                                    if 64 <= second_octet <= 127:
                                        continue
                                if remote_ip.startswith('172.'):
                                    second_octet = int(remote_ip.split('.')[1])
                                    if 16 <= second_octet <= 31:
                                        continue

                                protocol = COMMON_VPN_PORTS.get(remote_port, "Unknown")
                                logger.debug(f"[{safe_name}] Found VPN-like connection to: {sanitize_for_log(remote_ip)}:{remote_port} ({protocol})")
                                return remote_ip
                        except (ValueError, IndexError):
                            continue

        logger.debug(f"[{safe_name}] No VPN server connection found")
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


def get_vpn_server_endpoint(iface_name: str, iface_type: InterfaceType | str, local_ip: str) -> Optional[str]:
    """
    Get VPN server endpoint IP for VPN interfaces.

    Uses deterministic ss command to find active VPN connections.
    Works for all VPNs including ProtonVPN, WireGuard, OpenVPN, etc.

    IMPROVED: Accepts both InterfaceType enum and string.
    """
    # Convert to string for comparison
    iface_type_str = str(iface_type)
    if iface_type_str != str(InterfaceType.VPN):
        return None

    safe_name = sanitize_for_log(iface_name)

    if local_ip == "N/A":
        logger.debug(f"[{safe_name}] No local IP, cannot find VPN endpoint")
        return None

    logger.debug(f"[{safe_name}] Detecting VPN server endpoint via active connections")

    return get_vpn_connection_endpoint(iface_name, local_ip)


def find_physical_interface_for_vpn(vpn_server_ip: str, all_interfaces: List["InterfaceInfo"]) -> Optional[str]:
    """
    Determine which physical interface carries traffic to VPN server.

    Uses deterministic method: Find physical interface with default gateway.
    This works reliably for all VPNs including ProtonVPN with custom routing tables.

    The physical interface carrying VPN traffic is simply the one providing
    internet connectivity (has a default gateway and is not a VPN interface).

    IMPROVED: Uses InterfaceType enum for comparisons.
    """
    safe_ip = sanitize_for_log(vpn_server_ip)
    logger.debug(f"Finding physical interface carrying VPN traffic to {safe_ip}")

    candidates: List[tuple[str, str]] = []
    for iface in all_interfaces:
        # Convert to string for comparison
        iface_type_str = str(iface.interface_type)
        physical_types = [
            str(InterfaceType.ETHERNET),
            str(InterfaceType.WIRELESS),
            str(InterfaceType.TETHER)
        ]

        if (iface_type_str in physical_types and
            iface.default_gateway not in ["NONE", "N/A", "--"]):

            candidates.append((iface.name, iface.metric))
            safe_name = sanitize_for_log(iface.name)
            safe_gateway = sanitize_for_log(iface.default_gateway)
            safe_metric = sanitize_for_log(iface.metric)
            logger.debug(f"  Candidate: {safe_name} (gateway: {safe_gateway}, metric: {safe_metric})")

    if not candidates:
        logger.warning("No physical interfaces with default gateway found")
        return None

    # Sort by metric (lower is better)
    candidates_sorted = sorted(candidates, key=lambda x: (
        999 if x[1] in ["NONE", "DEFAULT", "N/A"] else int(x[1])
    ))

    physical_interface: str = candidates_sorted[0][0]
    safe_name = sanitize_for_log(physical_interface)
    logger.info(f"VPN tunnel traffic routes through: {safe_name} (physical interface with default gateway)")
    return physical_interface


def detect_vpn_underlay(interfaces: List["InterfaceInfo"]) -> None:
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

    IMPROVED: Uses InterfaceType enum for comparisons.
    """
    logger.debug("Detecting VPN underlay (physical interfaces carrying VPN traffic)")

    vpn_to_physical: dict[str, str] = {}

    for interface in interfaces:
        if str(interface.interface_type) == str(InterfaceType.VPN):
            vpn_ip = get_vpn_server_endpoint(
                interface.name,
                interface.interface_type,
                interface.internal_ipv4
            )

            if vpn_ip:
                interface.vpn_server_ip = vpn_ip
                safe_name = sanitize_for_log(interface.name)
                safe_ip = sanitize_for_log(vpn_ip)
                logger.debug(f"[{safe_name}] VPN server: {safe_ip}")

                physical_if = find_physical_interface_for_vpn(vpn_ip, interfaces)
                if physical_if:
                    vpn_to_physical[interface.name] = physical_if
                    logger.info(f"[{safe_name}] Tunnel carried by: {sanitize_for_log(physical_if)}")

    for interface in interfaces:
        if interface.name in vpn_to_physical.values():
            interface.carries_vpn = True
            vpn_names = [vpn for vpn, phys in vpn_to_physical.items() if phys == interface.name]
            safe_vpn_names = [sanitize_for_log(name) for name in vpn_names]
            safe_iface = sanitize_for_log(interface.name)
            logger.info(f"[{safe_iface}] Carries VPN tunnel for: {', '.join(safe_vpn_names)}")
