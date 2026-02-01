"""
Display and formatting module.

Handles all output formatting and text manipulation for terminal display.
Combines table output and text formatting utilities.
All data cleaning happens here at display time.

IMPROVEMENTS:
- Compiled regex patterns (avoid recompilation)
- LRU caching for device name cleanup
- Better performance on large interface lists
"""

import re
from typing import List, Dict, Tuple
from functools import lru_cache

from models import InterfaceInfo
from config import TABLE_COLUMNS, DEVICE_NAME_CLEANUP, Colors, COLUMN_SEPARATOR, CACHE_SIZE
from enums import DataMarker, DnsLeakStatus
from utils.system import is_valid_ipv6


# ============================================================================
# Compiled Regex Patterns (Performance Optimization)
# ============================================================================

# Compile regexes once at module load time
PARENTHESES_PATTERN = re.compile(r'\([^)]*\)')
BRACKETS_PATTERN = re.compile(r'\[[^\]]*\]')


# ============================================================================
# Text Formatting Functions
# ============================================================================

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
    to prevent partial matches (e.g., "802.11ax" removed before "802.11a").
    
    Cached with LRU cache for performance (same device names appear repeatedly).
    
    Args:
        device_name: Raw device name from lspci or sysfs
        
    Returns:
        Cleaned device name, or original if cleaning produces empty string
        
    Examples:
        >>> cleanup_device_name("Intel Corporation I219-V (Rev 1.0)")
        'Intel I219-V'
        >>> cleanup_device_name("MEDIATEK Corp. MT7922 802.11ax Adapter")
        'MEDIATEK MT7922'
    """
    cleaned = device_name
    
    # Remove content within parentheses and brackets (using compiled patterns)
    cleaned = PARENTHESES_PATTERN.sub('', cleaned)
    cleaned = BRACKETS_PATTERN.sub('', cleaned)
    
    # Sort cleanup terms by length (longest first) to prevent partial matches
    # This ensures "802.11ax" is removed before "802.11a" could match
    sorted_terms = sorted(DEVICE_NAME_CLEANUP, key=len, reverse=True)
    
    # Remove specific terms (case-insensitive)
    # Use word boundary at start, but allow punctuation/space/end at finish
    # This handles "Corp." "Inc." etc while preventing "802.11a" matching in "802.11ax"
    for term in sorted_terms:
        # Pattern: word boundary at start, then the term, then word boundary OR punctuation
        # This allows matching "Corp." "Inc." with trailing punctuation
        pattern = r'\b' + re.escape(term) + r'(?=\s|[.,\-]|$)'
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
    
    # Normalize whitespace
    cleaned = " ".join(cleaned.split())
    cleaned = cleaned.strip(" ,-")
    
    return cleaned if cleaned else device_name


@lru_cache(maxsize=CACHE_SIZE)
def cleanup_isp_name(isp: str) -> str:
    """
    Clean ISP name by removing ASN prefix.
    
    Format is often "AS12345 ISP Name" - we want just the name.
    
    Cached with LRU cache for performance.
    
    Args:
        isp: Raw ISP string from API
        
    Returns:
        Cleaned ISP name
        
    Examples:
        >>> cleanup_isp_name("AS12345 Example ISP")
        'Example ISP'
        >>> cleanup_isp_name("Example ISP")
        'Example ISP'
    """
    if isp and isp.startswith("AS") and len(parts := isp.split()) > 1:
        return " ".join(parts[1:])
    return isp


def shorten_text(text: str, max_length: int) -> str:
    """
    Shorten text to fit in column, breaking at word boundaries.
    
    Ensures no partial words are left at the end (e.g., avoids "MEDIATEK MT7922 x").
    
    Args:
        text: Text to shorten
        max_length: Maximum length
        
    Returns:
        Shortened text, breaking at word boundary when possible
        
    Examples:
        >>> shorten_text("Very Long Device Name", 10)
        'Very Long'
        >>> shorten_text("Short", 20)
        'Short'
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

def get_column_width(column_name: str) -> int:
    """
    Get the width of a column from TABLE_COLUMNS configuration.
    
    Args:
        column_name: Name of column to look up
        
    Returns:
        Width in characters, or 20 as default fallback
    """
    for col_name, col_width in TABLE_COLUMNS:
        if col_name == column_name:
            return col_width
    return 20  # Default fallback


def format_output(interfaces: List[InterfaceInfo]) -> None:
    """
    Format and print network interface information as a table.
    
    Color coding shows interface status and DNS leak detection:
    - GREEN: VPN tunnel endpoint (encrypted, DNS OK)
    - CYAN: Physical interface carrying VPN tunnel (underlay)
    - RED: Direct internet connection without VPN
    - YELLOW: DNS leak or warning detected
    - DEFAULT: Interface not routing internet traffic
    
    DNS leak status is conveyed by row color (YELLOW = leak/warning).
    No separate DNS_LEAK column needed.
    
    All data cleaning and formatting happens here:
    - Device names cleaned and shortened to column width
    - ISP names cleaned and shortened to column width
    - DNS shows only current/active server
    - Color coding applied based on interface role and DNS status
    - Columns separated by 3 spaces for readability
    
    Args:
        interfaces: List of InterfaceInfo objects to display
    """
    # Calculate total table width (including separators)
    total_width = sum(width for _, width in TABLE_COLUMNS) + len(COLUMN_SEPARATOR) * (len(TABLE_COLUMNS) - 1)
    
    # Print header
    print("=" * 39)
    print("Network Analysis Tool - Table Output")
    print("=" * 39)
    print("=" * total_width)
    
    # Print column headers
    header_parts = []
    for col_name, col_width in TABLE_COLUMNS:
        header_parts.append(col_name.ljust(col_width))
    print(COLUMN_SEPARATOR.join(header_parts))
    
    # Print separator line
    print("-" * total_width)
    
    # Get column widths for shortening
    device_width = get_column_width("DEVICE")
    isp_width = get_column_width("ISP")
    
    # Print data rows
    for interface in interfaces:
        # Clean and shorten device name to exact column width
        device_display = shorten_text(
            cleanup_device_name(interface.device),
            max_length=device_width
        )
        
        # Show only current/active DNS
        dns_display = interface.current_dns if interface.current_dns else str(DataMarker.NOT_APPLICABLE)
        
        # Clean and shorten ISP name to exact column width
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
        
        # Format each column with proper width
        # Only DEVICE and ISP columns should be truncated
        row_parts = []
        for i, ((col_name, col_width), value) in enumerate(zip(TABLE_COLUMNS, row_data)):
            # Only truncate DEVICE and ISP columns if they exceed width
            if col_name in ("DEVICE", "ISP") and len(value) > col_width:
                value = value[:col_width]
            row_parts.append(value.ljust(col_width))
        
        row_text = COLUMN_SEPARATOR.join(row_parts)
        
        # Apply color coding based on interface role and DNS status
        # Priority: DNS leak > VPN with OK DNS > VPN underlay > Direct internet
        # DNS leak status is shown by row color (no need for separate column)
        if interface.dns_leak_status == str(DnsLeakStatus.LEAK):
            # DNS leak - critical privacy issue (highest priority)
            row_text = f"{Colors.YELLOW}{row_text}{Colors.RESET}"
        elif interface.dns_leak_status == str(DnsLeakStatus.WARN):
            # DNS warning - suspicious activity
            row_text = f"{Colors.YELLOW}{row_text}{Colors.RESET}"
        elif interface.interface_type == "vpn" and interface.dns_leak_status == str(DnsLeakStatus.OK):
            # VPN with OK DNS status - encrypted and properly configured
            row_text = f"{Colors.GREEN}{row_text}{Colors.RESET}"
        elif interface.interface_type == "vpn" and interface.external_ipv4 != str(DataMarker.NOT_APPLICABLE):
            # VPN tunnel endpoint with external IP (active VPN exit point)
            row_text = f"{Colors.GREEN}{row_text}{Colors.RESET}"
        elif interface.carries_vpn:
            # Physical interface carrying VPN tunnel traffic (underlay)
            row_text = f"{Colors.CYAN}{row_text}{Colors.RESET}"
        elif interface.external_ipv4 != str(DataMarker.NOT_APPLICABLE):
            # Direct internet connection without VPN
            row_text = f"{Colors.RED}{row_text}{Colors.RESET}"
        
        print(row_text)
    
    # Print footer
    print("=" * total_width)
    
    # Print color legend
    print()
    print("Color Legend:")
    print(f"  {Colors.GREEN}GREEN{Colors.RESET}  - VPN tunnel endpoint (encrypted, DNS OK)")
    print(f"  {Colors.CYAN}CYAN{Colors.RESET}   - Physical interface carrying VPN traffic")
    print(f"  {Colors.RED}RED{Colors.RESET}    - Direct internet (unencrypted)")
    print(f"  {Colors.YELLOW}YELLOW{Colors.RESET} - DNS leak or warning detected")
