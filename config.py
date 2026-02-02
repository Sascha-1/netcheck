"""
Centralized configuration for the network analysis tool.

All constants, patterns, and configuration values are defined here.

Requires:
    - Linux kernel 6.12+
    - Python 3.12+
    - systemd-resolved
"""

REQUIRED_COMMANDS = ["ip", "lspci", "lsusb", "ethtool", "resolvectl", "ss"]

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

USB_TETHER_DRIVERS = [
    "cdc_ether",
    "cdc_mbim",
    "cdc_ncm",
    "ipheth",
    "rndis_host",
]

COMMON_VPN_PORTS = {
    51820: "WireGuard",
    1194: "OpenVPN (UDP default)",
    1195: "OpenVPN (TCP alternate)",
    443: "HTTPS/OpenVPN/SSTP",
    500: "IKEv2/IPSec",
    4500: "IKEv2/IPSec NAT-T",
}

PUBLIC_DNS_SERVERS = {
    "1.1.1.1", "1.0.0.1",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "1.1.1.2", "1.0.0.2",
    "2606:4700:4700::1112", "2606:4700:4700::1002",
    "1.1.1.3", "1.0.0.3",
    "2606:4700:4700::1113", "2606:4700:4700::1003",
    "8.8.8.8", "8.8.4.4",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "9.9.9.9", "149.112.112.112",
    "2620:fe::fe", "2620:fe::9",
    "208.67.222.222", "208.67.220.220",
    "2620:119:35::35", "2620:119:53::53",
    "94.140.14.14", "94.140.15.15",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
}

DNS_CURRENT_SERVER_MARKER = "Current DNS Server:"
DNS_SERVERS_MARKER = "DNS Servers:"
DNS_GLOBAL_SECTION_MARKER = "Global"
DNS_LINK_SECTION_MARKER = "Link "

IPINFO_URL = "https://ipinfo.io/json"
IPINFO_IPv6_URL = "https://v6.ipinfo.io/json"

DEVICE_NAME_CLEANUP = [
    "co.", "company", "corp.", "corporation", "inc.", "incorporated",
    "limited", "ltd.", "tech", "technologies", "technology",
    "adapter", "controller", "ethernet", "lan", "network", "wireless",
    "express", "pci", "pcie",
    "10base-t", "100base-t", "1000base-t", "2.5gbase-t", "5gbase-t",
    "10gbase-t", "nbase-t/ieee",
    "gen2", "gen3", "gen4",
    "802.3", "802.3an", "ieee",
    "802.11a", "802.11b", "802.11g", "802.11n", "802.11ac", "802.11ax",
]

TIMEOUT_SECONDS = 10
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_FACTOR = 1.0
MAX_WORKERS = 4
CACHE_SIZE = 128

TABLE_COLUMNS = [
    ("INTERFACE", 15),
    ("TYPE", 10),
    ("DEVICE", 20),
    ("INTERNAL_IPv4", 15),
    ("INTERNAL_IPv6", 25),
    ("DNS_SERVER", 20),
    ("EXTERNAL_IPv4", 15),
    ("EXTERNAL_IPv6", 25),
    ("ISP", 15),
    ("COUNTRY", 10),
    ("GATEWAY", 15),
    ("METRIC", 10),
]


class Colors:
    """
    Terminal color codes for interface status visualization.
    
    Color scheme:
        GREEN: VPN tunnel endpoint (encrypted, secure) or DNS OK
        CYAN: Physical interface carrying VPN traffic (underlay)
        RED: Direct internet connection (unencrypted)
        YELLOW: DNS leak detected or warning condition
        RESET: Reset to terminal default colors
    """
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'


COLUMN_SEPARATOR = "   "
