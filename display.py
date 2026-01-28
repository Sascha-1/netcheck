"""
Display and formatting module.

Handles all output formatting and text manipulation for terminal display.
Combines table output and text formatting utilities.
All data cleaning happens here at display time.
"""

import re
from typing import List
from models import InterfaceInfo
from config import TABLE_COLUMNS, DEVICE_NAME_CLEANUP, Colors
from utils.system import is_valid_ipv6


# ============================================================================
# Text Formatting Functions
# ============================================================================

def cleanup_device_name(device_name: str) -> str:
    """
    Clean device name by removing generic terms and technical jargon.
    
    Removes:
    - Content in parentheses and brackets (versions, codenames)
    - Common corporate terms (Corporation, Inc., etc.)
    - Technical standards (IEEE, 802.11x, Base-T variants)
    - Generic words (Controller, Adapter, Network, etc.)
    
    All removals are case-insensitive.
    
    Args:
        device_name: Raw device name from lspci or sysfs
        
    Returns:
        Cleaned device name, or original if cleaning produces empty string
    """
    cleaned = device_name
    
    # Remove content within parentheses and brackets
    cleaned = re.sub(r'\([^)]*\)', '', cleaned)
    cleaned = re.sub(r'\[[^\]]*\]', '', cleaned)
    
    # Remove specific terms (case-insensitive)
    for term in DEVICE_NAME_CLEANUP:
        cleaned = re.sub(re.escape(term), '', cleaned, flags=re.IGNORECASE)
    
    # Normalize whitespace
    cleaned = " ".join(cleaned.split())
    cleaned = cleaned.strip(" ,-")
    
    return cleaned if cleaned else device_name


def cleanup_isp_name(isp: str) -> str:
    """
    Clean ISP name by removing ASN prefix.
    
    Format is often "AS12345 ISP Name" - we want just the name.
    
    Args:
        isp: Raw ISP string from API
        
    Returns:
        Cleaned ISP name
    """
    if isp and isp.startswith("AS") and len(parts := isp.split()) > 1:
        return " ".join(parts[1:])
    return isp


def shorten_text(text: str, max_length: int) -> str:
    """
    Shorten text to fit in column, breaking at word boundaries.
    
    Args:
        text: Text to shorten
        max_length: Maximum length
        
    Returns:
        Shortened text
    """
    if not text or len(text) <= max_length:
        return text
    
    # Find last space before max_length
    truncated = text[:max_length]
    
    if (last_space := truncated.rfind(' ')) > 0:
        # Break at word boundary
        return text[:last_space]
    else:
        # No space found, hard truncate with ellipsis
        return text[:max_length - 3] + "..."


# ============================================================================
# Table Output
# ============================================================================

def format_output(interfaces: List[InterfaceInfo]) -> None:
    """
    Format and print network interface information as a table.
    
    Color coding:
    - GREEN: VPN tunnel endpoint (encrypted traffic exit point)
    - CYAN: Physical interface carrying VPN tunnel (underlay)
    - RED: Direct internet connection without VPN
    - YELLOW: DNS leak or warning
    - DEFAULT: Interface not routing internet traffic
    
    All data cleaning and formatting happens here:
    - Device names cleaned and shortened
    - ISP names cleaned and shortened
    - DNS shows only current/active server
    - Color coding applied based on interface role
    
    Args:
        interfaces: List of InterfaceInfo objects to display
    """
    # Calculate total table width
    total_width = sum(width for _, width in TABLE_COLUMNS) + len(TABLE_COLUMNS) - 1
    
    # Print header
    print("=" * 39)
    print("Network Analysis Tool - Table Output")
    print("=" * 39)
    print("=" * total_width)
    
    # Print column headers
    header_parts = []
    for col_name, col_width in TABLE_COLUMNS:
        header_parts.append(col_name.ljust(col_width))
    print(" ".join(header_parts))
    
    # Print separator line
    print("-" * total_width)
    
    # Print data rows
    for interface in interfaces:
        # Clean and shorten device name
        device_display = shorten_text(cleanup_device_name(interface.device), max_length=19)
        
        # Show only current/active DNS
        dns_display = interface.current_dns if interface.current_dns else "--"
        
        # Clean and shorten ISP name
        isp_display = shorten_text(cleanup_isp_name(interface.egress_isp), max_length=16)
        
        row_data = [
            interface.name,
            interface.interface_type,
            device_display,
            interface.internal_ipv4,
            interface.internal_ipv6,
            dns_display,
            interface.dns_leak_status,
            interface.external_ipv4,
            interface.external_ipv6,
            isp_display,
            interface.egress_country,
            interface.default_gateway,
            interface.metric
        ]
        
        # Format each column with proper width
        row_parts = []
        for (_, col_width), value in zip(TABLE_COLUMNS, row_data):
            # Truncate if value exceeds column width
            if len(value) > col_width:
                value = value[:col_width-3] + "..."
            row_parts.append(value.ljust(col_width))
        
        row_text = " ".join(row_parts)
        
        # Apply color coding based on interface role
        # Priority: DNS leak > VPN endpoint > VPN underlay > Direct internet
        if interface.dns_leak_status == "LEAK":
            # DNS leak - critical privacy issue (highest priority)
            row_text = f"{Colors.YELLOW}{row_text}{Colors.RESET}"
        elif interface.dns_leak_status == "WARN":
            # DNS warning - suspicious activity
            row_text = f"{Colors.YELLOW}{row_text}{Colors.RESET}"
        elif interface.interface_type == "vpn" and interface.external_ipv4 not in ("--", "ERR"):
            # VPN tunnel endpoint - encrypted traffic exit point
            row_text = f"{Colors.GREEN}{row_text}{Colors.RESET}"
        elif interface.carries_vpn:
            # Physical interface carrying VPN tunnel traffic (underlay)
            row_text = f"{Colors.CYAN}{row_text}{Colors.RESET}"
        elif interface.external_ipv4 not in ("--", "ERR"):
            # Direct internet connection without VPN
            row_text = f"{Colors.RED}{row_text}{Colors.RESET}"
        
        print(row_text)
    
    # Print footer
    print("=" * total_width)
    
    # Print color legend
    print()
    print("Color Legend:")
    print(f"  {Colors.GREEN}GREEN{Colors.RESET}  - VPN tunnel endpoint (encrypted)")
    print(f"  {Colors.CYAN}CYAN{Colors.RESET}   - Physical interface carrying VPN traffic")
    print(f"  {Colors.RED}RED{Colors.RESET}    - Direct internet (unencrypted)")
    print(f"  {Colors.YELLOW}YELLOW{Colors.RESET} - DNS leak or warning")
