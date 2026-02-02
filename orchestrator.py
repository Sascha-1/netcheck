"""
Data collection orchestration module.

Coordinates interface detection, hardware identification, network configuration,
DNS detection, and external API queries to build complete network interface information.

Supports optional parallel processing for faster execution.
"""

import shutil
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from logging_config import get_logger
from models import InterfaceInfo, EgressInfo
from config import REQUIRED_COMMANDS, MAX_WORKERS
from network.detection import get_interface_list, detect_interface_type, get_device_name
from network.configuration import get_internal_ipv4, get_internal_ipv6, get_default_gateway, get_route_metric, get_active_interface
from network.dns import get_interface_dns, check_dns_leaks_all_interfaces
from network.egress import get_egress_info
from network.vpn_underlay import detect_vpn_underlay
from enums import InterfaceType, DataMarker
from utils.system import sanitize_for_log

logger = get_logger(__name__)


def check_dependencies() -> bool:
    """
    Verify all required system commands are available.
    
    Checks for system commands: ip, lspci, lsusb, ethtool, resolvectl, ss
    and Python packages: requests, urllib3
    
    Returns:
        True if all dependencies are present, False otherwise
    """
    logger.debug("Checking dependencies...")
    
    all_present = True
    
    for cmd in REQUIRED_COMMANDS:
        if not shutil.which(cmd):
            logger.error(f"Missing: {cmd}")
            all_present = False
        else:
            logger.debug(f"Found: {cmd}")
    
    try:
        import requests
        logger.debug("Found: Python requests library")
    except ImportError:
        logger.error("Missing: Python requests library")
        logger.info("Install with: pip install requests")
        all_present = False
    
    try:
        import urllib3
        logger.debug("Found: Python urllib3 library")
    except ImportError:
        logger.warning("Missing: Python urllib3 library (recommended for retry logic)")
        logger.info("Install with: pip install urllib3")
    
    if all_present:
        logger.debug("All dependencies found")
    
    return all_present


def process_single_interface(
    iface_name: str,
    active_interface: Optional[str],
    egress: Optional[EgressInfo]
) -> InterfaceInfo:
    """
    Process a single network interface (thread-safe).
    
    Collects all information for one interface:
    - Interface type detection
    - Hardware device identification
    - IPv4/IPv6 addresses
    - DNS configuration
    - Routing information
    - Egress information (if active interface)
    """
    safe_name = sanitize_for_log(iface_name)
    logger.debug(f"\nProcessing {safe_name}...")
    
    info = InterfaceInfo.create_empty(iface_name)
    
    info.interface_type = detect_interface_type(iface_name)
    logger.debug(f"Type: {info.interface_type}")
    
    info.device = get_device_name(iface_name, info.interface_type)
    
    info.internal_ipv4 = get_internal_ipv4(iface_name)
    info.internal_ipv6 = get_internal_ipv6(iface_name)
    
    dns_list, current_dns = get_interface_dns(iface_name)
    info.dns_servers = dns_list
    info.current_dns = current_dns
    
    if len(dns_list) > 1:
        logger.debug(f"Total DNS servers: {len(dns_list)}")
    
    info.default_gateway = get_default_gateway(iface_name)
    info.metric = get_route_metric(iface_name)
    
    if iface_name == active_interface and egress:
        info.external_ipv4 = egress.external_ip
        info.external_ipv6 = egress.external_ipv6
        info.egress_isp = egress.isp
        info.egress_country = egress.country
        logger.debug(f"External IPv4: {info.external_ipv4}")
        logger.debug(f"External IPv6: {info.external_ipv6}")
        logger.debug(f"ISP: {info.egress_isp}")
        logger.debug(f"Country: {info.egress_country}")
    
    return info


def collect_network_data(parallel: bool = True) -> List[InterfaceInfo]:
    """
    Collect complete network interface information.
    
    Stores raw data - cleaning and formatting happens at display time.
    Verbosity controlled by logging level set via --verbose flag.
    
    With parallel=True: Uses thread pool for 3-4x speedup on multi-core systems
    With parallel=False: Sequential processing (safer, easier to debug)
    """
    logger.info("Collecting network interface data...")
    
    interfaces = get_interface_list()
    
    if not interfaces:
        logger.warning("No network interfaces found")
        return []
    
    logger.info(f"Found {len(interfaces)} interfaces: {', '.join(interfaces)}")
    
    active_interface = get_active_interface()
    egress = None
    
    if active_interface:
        safe_active = sanitize_for_log(active_interface)
        logger.info(f"Active interface: {safe_active}")
        logger.info("Querying ipinfo.io for egress information...")
        egress = get_egress_info()
    else:
        logger.debug("No active default route found")
    
    results: List[InterfaceInfo] = []
    
    if parallel and len(interfaces) > 1:
        logger.debug(f"Using parallel processing with {MAX_WORKERS} workers")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_iface = {
                executor.submit(process_single_interface, iface, active_interface, egress): iface
                for iface in interfaces
            }
            
            for future in as_completed(future_to_iface):
                iface = future_to_iface[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    safe_iface = sanitize_for_log(iface)
                    logger.error(f"Failed to process {safe_iface}: {e}")
                    results.append(InterfaceInfo.create_empty(iface))
        
        interface_order = {name: idx for idx, name in enumerate(interfaces)}
        results.sort(key=lambda x: interface_order.get(x.name, 999))
        
    else:
        if not parallel:
            logger.debug("Using sequential processing (parallel=False)")
        
        for iface_name in interfaces:
            try:
                info = process_single_interface(iface_name, active_interface, egress)
                results.append(info)
            except Exception as e:
                safe_iface = sanitize_for_log(iface_name)
                logger.error(f"Failed to process {safe_iface}: {e}")
                results.append(InterfaceInfo.create_empty(iface_name))
    
    logger.debug("")
    check_dns_leaks_all_interfaces(results)
    
    detect_vpn_underlay(results)
    
    return results
