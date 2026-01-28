"""
Data collection orchestration module.

Coordinates interface detection, hardware identification, network configuration,
DNS detection, IPv6 support, DNS leak detection, and external API queries to 
build complete network interface information.
"""

import shutil
from typing import List

from logging_config import get_logger
from models import InterfaceInfo
from config import REQUIRED_COMMANDS
from network.detection import get_interface_list, detect_interface_type, get_device_name
from network.configuration import get_internal_ipv4, get_internal_ipv6, get_default_gateway, get_route_metric, get_active_interface
from network.dns import get_interface_dns, check_dns_leaks_all_interfaces
from network.egress import get_egress_info
from network.vpn_underlay import detect_vpn_underlay

logger = get_logger(__name__)


def check_dependencies() -> bool:
    """
    Verify all required system commands are available.
    
    Checks for:
    - System commands: ip, lspci, lsusb, ethtool, resolvectl
    - Python packages: requests
    
    Returns:
        True if all dependencies are present, False otherwise
    """
    logger.debug("Checking dependencies...")
    
    all_present = True
    
    # Check system commands
    for cmd in REQUIRED_COMMANDS:
        if not shutil.which(cmd):
            logger.error(f"Missing: {cmd}")
            all_present = False
        else:
            logger.debug(f"Found: {cmd}")
    
    # Check Python packages
    try:
        import requests
        logger.debug(f"Found: Python requests library")
    except ImportError:
        logger.error("Missing: Python requests library")
        logger.info("Install with: pip install requests")
        all_present = False
    
    if all_present:
        logger.debug("All dependencies found")
    
    return all_present


def collect_network_data() -> List[InterfaceInfo]:
    """
    Collect complete network interface information.
    
    Stores raw data - cleaning and formatting happens at display time.
    Verbosity controlled by logging level set via --verbose flag.
    
    Returns:
        List of InterfaceInfo objects with raw data
    """
    logger.info("Collecting network interface data...")
    
    interfaces = get_interface_list()
    
    logger.info(f"Found {len(interfaces)} interfaces: {', '.join(interfaces)}")
    
    results = []
    
    # Identify active interface and get egress information
    active_interface = get_active_interface()
    egress = None
    
    if active_interface:
        logger.info(f"Active interface: {active_interface}")
        logger.info("Querying ipinfo.io for egress information...")
        egress = get_egress_info()
    else:
        logger.debug("No active default route found")
    
    # Collect information for each interface
    for iface_name in interfaces:
        logger.debug(f"\nProcessing {iface_name}...")
        
        # Create base info structure
        info = InterfaceInfo.create_empty(iface_name)
        
        # Detect interface type
        info.interface_type = detect_interface_type(iface_name)
        logger.debug(f"Type: {info.interface_type}")
        
        # Get hardware device name
        info.device = get_device_name(iface_name, info.interface_type)
        
        # Get network configuration - IPv4
        info.internal_ipv4 = get_internal_ipv4(iface_name)
        
        # Get network configuration - IPv6
        info.internal_ipv6 = get_internal_ipv6(iface_name)
        
        # Get DNS servers
        dns_list, current_dns = get_interface_dns(iface_name)
        info.dns_servers = dns_list
        info.current_dns = current_dns
        
        if len(dns_list) > 1:
            logger.debug(f"Total DNS servers: {len(dns_list)}")
        
        # Get routing information
        info.default_gateway = get_default_gateway(iface_name)
        info.metric = get_route_metric(iface_name)
        
        # Attach egress information if this is the active interface
        if iface_name == active_interface and egress:
            info.external_ipv4 = egress.external_ip
            info.external_ipv6 = egress.external_ipv6
            info.egress_isp = egress.isp
            info.egress_country = egress.country
            logger.debug(f"External IPv4: {info.external_ipv4}")
            logger.debug(f"External IPv6: {info.external_ipv6}")
            logger.debug(f"ISP: {info.egress_isp}")
            logger.debug(f"Country: {info.egress_country}")
        
        results.append(info)
    
    # Check for DNS leaks
    logger.debug("")
    check_dns_leaks_all_interfaces(results)
    
    # Detect VPN underlay (which physical interface carries VPN tunnel)
    detect_vpn_underlay(results)
    
    return results
