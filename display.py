"""
Display and formatting module.

Handles all output formatting and text manipulation for terminal display.
All data cleaning happens here at display time.
"""

import re
from typing import List, Dict
from functools import lru_cache

from models import InterfaceInfo
from config import TABLE_COLUMNS, DEVICE_NAME_CLEANUP, Colors, COLUMN_SEPARATOR, CACHE_SIZE
from enums import DataMarker, DnsLeakStatus


PARENTHESES_PATTERN = re.compile(r'\([^)]*\)')
BRACKETS_PATTERN = re.compile(r'\[[^\]]*\]')


@lru_cache(maxsize=CACHE_SIZE)
def cleanup_device_name(device_name: str) -> str:
    """
    Clean device name by removing generic terms and technical jargon.
    
    Removes:
    - Content in parentheses and brackets (versions, codenames)
    - Common corporate terms (Corporation, Inc., etc.)
    - Technical standards (IEEE, 802.11x, Base-T variants)
    - Generic words (Controller, Adapter, Network, etc.)
    
    All removals are case-insensitive. Terms are processed longest-first
    to prevent partial matches.
    
    Cached with LRU cache for performance.
    """
    cleaned = device_name
    
    cleaned = PARENTHESES_PATTERN.sub('', cleaned)
    cleaned = BRACKETS_PATTERN.sub('', cleaned)
    
    sorted_terms = sorted(DEVICE_NAME_CLEANUP, key=len, reverse=True)
    
    for term in sorted_terms:
        pattern = r'\b' + re.escape(term) + r'(?=\s|[.,\-]|$)'
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
    
    cleaned = " ".join(cleaned.split())
    cleaned = cleaned.strip(" ,-")
    
    return cleaned if cleaned else device_name


@lru_cache(maxsize=CACHE_SIZE)
def cleanup_isp_name(isp: str) -> str:
    """
    Clean ISP name by removing ASN prefix.
    
    Format is often "AS12345 ISP Name" - we want just the name.
    Cached with LRU cache for performance.
    """
    if isp and isp.startswith("AS") and len(parts := isp.split()) > 1:
        return " ".join(parts[1:])
    return isp


def shorten_text(text: str, max_length: int) -> str:
    """
    Shorten text to fit in column, breaking at word boundaries.
    
    Ensures no partial words are left at the end.
    """
    if not text or len(text) <= max_length:
        return text
    
    truncated = text[:max_length]
    
    if (last_space := truncated.rfind(' ')) > 0:
        return text[:last_space]
    else:
        return text[:max_length - 3] + "..."


def get_column_width(column_name: str) -> int:
    """Get the width of a column from TABLE_COLUMNS configuration."""
    for col_name, col_width in TABLE_COLUMNS:
        if col_name == column_name:
            return col_width
    return 20


def format_output(interfaces: List[InterfaceInfo]) -> None:
    """
    Format and print network interface information as a table.
    
    Color coding shows interface status and DNS leak detection:
    - GREEN: VPN tunnel endpoint (encrypted, DNS OK)
    - CYAN: Physical interface carrying VPN tunnel (underlay)
    - RED: Direct internet connection without VPN
    - YELLOW: DNS leak or warning detected
    - DEFAULT: Interface not routing internet traffic
    
    DNS leak status is conveyed by row color.
    All data cleaning and formatting happens here.
    """
    total_width = sum(width for _, width in TABLE_COLUMNS) + len(COLUMN_SEPARATOR) * (len(TABLE_COLUMNS) - 1)
    
    print("=" * 39)
    print("Network Analysis Tool - Table Output")
    print("=" * 39)
    print("=" * total_width)
    
    header_parts = []
    for col_name, col_width in TABLE_COLUMNS:
        header_parts.append(col_name.ljust(col_width))
    print(COLUMN_SEPARATOR.join(header_parts))
    
    print("-" * total_width)
    
    device_width = get_column_width("DEVICE")
    isp_width = get_column_width("ISP")
    
    for interface in interfaces:
        device_display = shorten_text(
            cleanup_device_name(interface.device),
            max_length=device_width
        )
        
        dns_display = interface.current_dns if interface.current_dns else str(DataMarker.NOT_APPLICABLE)
        
        isp_display = shorten_text(
            cleanup_isp_name(interface.egress_isp),
            max_length=isp_width
        )
        
        row_data = [
            interface.name,
            interface.interface_type,
            device_display,
            interface.internal_ipv4,
            interface.internal_ipv6,
            dns_display,
            interface.external_ipv4,
            interface.external_ipv6,
            isp_display,
            interface.egress_country,
            interface.default_gateway,
            interface.metric
        ]
        
        row_parts = []
        for i, ((col_name, col_width), value) in enumerate(zip(TABLE_COLUMNS, row_data)):
            if col_name in ("DEVICE", "ISP") and len(value) > col_width:
                value = value[:col_width]
            row_parts.append(value.ljust(col_width))
        
        row_text = COLUMN_SEPARATOR.join(row_parts)
        
        if interface.dns_leak_status == str(DnsLeakStatus.LEAK):
            row_text = f"{Colors.YELLOW}{row_text}{Colors.RESET}"
        elif interface.dns_leak_status == str(DnsLeakStatus.WARN):
            row_text = f"{Colors.YELLOW}{row_text}{Colors.RESET}"
        elif interface.interface_type == "vpn" and interface.dns_leak_status == str(DnsLeakStatus.OK):
            row_text = f"{Colors.GREEN}{row_text}{Colors.RESET}"
        elif interface.interface_type == "vpn" and interface.external_ipv4 != str(DataMarker.NOT_APPLICABLE):
            row_text = f"{Colors.GREEN}{row_text}{Colors.RESET}"
        elif interface.carries_vpn:
            row_text = f"{Colors.CYAN}{row_text}{Colors.RESET}"
        elif interface.external_ipv4 != str(DataMarker.NOT_APPLICABLE):
            row_text = f"{Colors.RED}{row_text}{Colors.RESET}"
        
        print(row_text)
    
    print("=" * total_width)
    
    print()
    print("Color Legend:")
    print(f"  {Colors.GREEN}GREEN{Colors.RESET}  - VPN tunnel endpoint (encrypted, DNS OK)")
    print(f"  {Colors.CYAN}CYAN{Colors.RESET}   - Physical interface carrying VPN traffic")
    print(f"  {Colors.RED}RED{Colors.RESET}    - Direct internet (unencrypted)")
    print(f"  {Colors.YELLOW}YELLOW{Colors.RESET} - DNS leak or warning detected")
