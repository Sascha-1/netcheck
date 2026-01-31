"""
Centralized configuration for the network analysis tool.

All constants, patterns, and configuration values are defined here.
This ensures a single source of truth and makes the tool easy to maintain.

Requires:
    - Linux kernel 6.12+
    - Python 3.12+
    - systemd-resolved
"""

# ============================================================================
# System Dependencies
# ============================================================================

REQUIRED_COMMANDS = ["ip", "lspci", "lsusb", "ethtool", "resolvectl", "ss"]

# ============================================================================
# Network Detection Configuration
# ============================================================================

# Interface type detection by prefix (systemd predictable names)
INTERFACE_TYPE_PATTERNS = {
    "lo": "loopback",
    "eth": "ethernet",
    "en": "ethernet",
    "wl": "wireless",
    "ww": "wwan",
    "vpn": "vpn",
    "tun": "vpn",
    "tap": "vpn",
    "ppp": "vpn"
}

# USB tethering drivers (standard on kernel 6.12+)
# Sorted alphabetically for maintainability
USB_TETHER_DRIVERS = [
    "cdc_ether",    # USB CDC Ethernet
    "cdc_mbim",     # USB CDC MBIM (Mobile Broadband)
    "cdc_ncm",      # USB CDC NCM (Network Control Model)
    "ipheth",       # iPhone USB tethering
    "rndis_host",   # RNDIS (Remote NDIS)
]

# ============================================================================
# DNS Configuration
# ============================================================================

# Well-known public DNS servers (used to identify acceptable DNS when VPN active)
# Using a set for O(1) lookup performance
PUBLIC_DNS_SERVERS = {
    # Cloudflare DNS (1.1.1.1)
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    
    # Cloudflare for Families - Malware Blocking
    "1.1.1.2",
    "1.0.0.2",
    "2606:4700:4700::1112",
    "2606:4700:4700::1002",
    
    # Cloudflare for Families - Malware + Adult Content Blocking
    "1.1.1.3",
    "1.0.0.3",
    "2606:4700:4700::1113",
    "2606:4700:4700::1003",
    
    # Google Public DNS (8.8.8.8)
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    
    # Quad9 DNS (9.9.9.9)
    "9.9.9.9",
    "149.112.112.112",
    "2620:fe::fe",
    "2620:fe::9",
    
    # OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    "2620:119:35::35",
    "2620:119:53::53",
    
    # AdGuard DNS
    "94.140.14.14",
    "94.140.15.15",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
}

# DNS parsing markers for resolvectl output
# These strings identify sections in systemd-resolved status output
DNS_CURRENT_SERVER_MARKER = "Current DNS Server:"
DNS_SERVERS_MARKER = "DNS Servers:"
DNS_GLOBAL_SECTION_MARKER = "Global"
DNS_LINK_SECTION_MARKER = "Link "

# ============================================================================
# External API Configuration
# ============================================================================

# ipinfo.io API endpoints for egress information
IPINFO_URL = "https://ipinfo.io/json"
IPINFO_IPv6_URL = "https://v6.ipinfo.io/json"

# ============================================================================
# Data Processing Configuration
# ============================================================================

# Device name cleanup - terms to remove from hardware device names
# Sorted and grouped for maintainability
# Case-insensitive matching applied during cleanup
DEVICE_NAME_CLEANUP = [
    # Company suffixes
    "co.",
    "company",
    "corp.",
    "corporation",
    "inc.",
    "incorporated",
    "limited",
    "ltd.",
    
    # Technology terms
    "tech",
    "technologies",
    "technology",
    
    # Generic network terms (alphabetically sorted)
    "adapter",
    "controller",
    "ethernet",
    "lan",
    "network",
    "wireless",
    
    # Hardware interface standards (alphabetically sorted)
    "express",
    "pci",
    "pcie",
    
    # Ethernet speed standards (sorted by speed)
    "10base-t",
    "100base-t",
    "1000base-t",
    "2.5gbase-t",
    "5gbase-t",
    "10gbase-t",
    "nbase-t/ieee",
    
    # PCIe generations (sorted)
    "gen2",
    "gen3",
    "gen4",
    
    # IEEE 802.3 Ethernet standards (sorted)
    "802.3",
    "802.3an",
    "ieee",
    
    # WiFi (802.11) standards (sorted by generation)
    "802.11a",
    "802.11b",
    "802.11g",
    "802.11n",
    "802.11ac",
    "802.11ax",
]

# Timeout for external commands (seconds)
TIMEOUT_SECONDS = 10

# ============================================================================
# Display Configuration
# ============================================================================

# Table column definitions: (column_name, width_in_characters)
# Total width optimized for typical terminal
# DNS_LEAK column removed - status shown via color coding on DNS_SERVER
TABLE_COLUMNS = [
    ("INTERFACE", 15),      # Interface name (eth0, wlan0, tun0, etc.)
    ("TYPE", 10),           # Interface type (ethernet, wireless, vpn, etc.)
    ("DEVICE", 20),         # Hardware device name
    ("INTERNAL_IPv4", 15),  # Local IPv4 address
    ("INTERNAL_IPv6", 25),  # Local IPv6 address (global scope)
    ("DNS_SERVER", 20),     # Current DNS server (color-coded for leak status)
    ("EXTERNAL_IPv4", 15),  # Public IPv4 address (active route only)
    ("EXTERNAL_IPv6", 25),  # Public IPv6 address (active route only)
    ("ISP", 15),            # ISP name (active route only)
    ("COUNTRY", 10),         # Country code (active route only)
    ("GATEWAY", 15),        # Default gateway IP
    ("METRIC", 10),          # Route metric (lower = higher priority)
]

# ANSI color codes for terminal output
class Colors:
    """
    Terminal color codes for interface status visualization.
    
    Color scheme:
        GREEN: VPN tunnel endpoint (encrypted, secure)
               Also used for DNS_SERVER when status is OK
        CYAN: Physical interface carrying VPN traffic (underlay)
        RED: Direct internet connection (unencrypted, potentially exposed)
        YELLOW: DNS leak detected or warning condition
                Also used for DNS_SERVER when leak detected
        RESET: Reset to terminal default colors
    """
    GREEN = '\033[92m'      # VPN tunnel endpoint (encrypted) / DNS OK
    CYAN = '\033[96m'       # Physical interface carrying VPN (underlay)
    RED = '\033[91m'        # Direct internet (unencrypted)
    YELLOW = '\033[93m'     # DNS leak or warning
    RESET = '\033[0m'       # Reset to default


# Column separator for table output (3 spaces for readability)
COLUMN_SEPARATOR = "   "
