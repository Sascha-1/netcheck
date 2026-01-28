"""
Centralized configuration for the network analysis tool.

Requires Linux kernel 6.12+ and Python 3.12+.
"""

REQUIRED_COMMANDS = ["ip", "lspci", "lsusb", "ethtool", "resolvectl", "ss"]

IPINFO_URL = "https://ipinfo.io/json"
IPINFO_IPv6_URL = "https://v6.ipinfo.io/json"

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
USB_TETHER_DRIVERS = ["rndis_host", "cdc_ether", "cdc_ncm", "cdc_mbim", "ipheth"]

# Device name cleanup - single words/terms to remove (case-insensitive)
DEVICE_NAME_CLEANUP = [
    "corporation",
    "corp.",
    "incorporated",
    "inc.",
    "limited",
    "ltd.",
    "co.",
    "company",
    "technologies",
    "technology",
    "tech",
    "ethernet",
    "controller",
    "network",
    "wireless",
    "lan",
    "adapter",
    "pci",
    "express",
    "pcie",
    "gen2",
    "gen3",
    "gen4",
    "802.11ax",
    "802.11ac",
    "802.11n",
    "802.11g",
    "802.11a",
    "802.11b",
    "nbase-t/ieee",
    "ieee",
    "802.3an",
    "802.3",
    "10base-t",
    "100base-t",
    "1000base-t",
    "2.5gbase-t",
    "5gbase-t",
    "10gbase-t",
]

TIMEOUT_SECONDS = 10

# Table column definitions: (name, width)
# Optimized for readability and typical terminal width (185 chars total)
TABLE_COLUMNS = [
    ("INTERFACE", 15),
    ("TYPE", 10),
    ("DEVICE", 20),
    ("INTERNAL_IPv4", 15),
    ("INTERNAL_IPv6", 20),
    ("DNS_SERVER", 18),
    ("DNS_LEAK", 8),
    ("EXTERNAL_IPv4", 15),
    ("EXTERNAL_IPv6", 20),
    ("ISP", 20),
    ("COUNTRY", 7),
    ("GATEWAY", 15),
    ("METRIC", 6)
]

# ANSI color codes for terminal output
class Colors:
    """Terminal color codes for interface status visualization."""
    GREEN = '\033[92m'      # VPN tunnel endpoint (encrypted)
    CYAN = '\033[96m'       # Physical interface carrying VPN (underlay)
    RED = '\033[91m'        # Direct internet (unencrypted)
    YELLOW = '\033[93m'     # DNS leak or warning
    RESET = '\033[0m'       # Reset to default

