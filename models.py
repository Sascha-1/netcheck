"""
Data structure definitions.

Type-safe data models for network interface and egress information.

IMPROVED: Uses enum types directly instead of string conversions.
"""

from dataclasses import dataclass
from typing import Optional
from enums import InterfaceType, DnsLeakStatus, DataMarker


@dataclass
class InterfaceInfo:
    """
    Complete information about a network interface.

    Attributes:
        name: Interface name (e.g., eth0, wlp8s0)
        interface_type: Type classification (enum or string value)
        device: Hardware device name or DataMarker.NOT_AVAILABLE
        internal_ipv4: Local IPv4 address or DataMarker.NOT_AVAILABLE
        internal_ipv6: Local IPv6 address or DataMarker.NOT_AVAILABLE
        dns_servers: List of all DNS servers configured for this interface
        current_dns: The DNS server currently being used (or None)
        dns_leak_status: DNS leak detection status (enum or string value)
        external_ipv4: Public IPv4 address or DataMarker.NOT_APPLICABLE
        external_ipv6: Public IPv6 address or DataMarker.NOT_APPLICABLE
        egress_isp: ISP name for egress traffic or DataMarker.NOT_APPLICABLE
        egress_country: Country code or DataMarker.NOT_APPLICABLE
        default_gateway: Gateway IP or DataMarker.NONE_VALUE
        metric: Route metric or DataMarker.NONE_VALUE/DEFAULT
        vpn_server_ip: For VPN interfaces, the remote VPN server endpoint IP
        carries_vpn: For physical interfaces, True if carrying VPN tunnel traffic

    IMPROVED: Accepts both enum types and strings for backward compatibility.
    """

    name: str
    interface_type: InterfaceType | str
    device: str
    internal_ipv4: str
    internal_ipv6: str
    dns_servers: list[str]
    current_dns: Optional[str]
    dns_leak_status: DnsLeakStatus | str
    external_ipv4: str
    external_ipv6: str
    egress_isp: str
    egress_country: str
    default_gateway: str
    metric: str
    vpn_server_ip: Optional[str] = None
    carries_vpn: bool = False

    @classmethod
    def create_empty(cls, name: str) -> "InterfaceInfo":
        """
        Create an InterfaceInfo with default placeholder values.

        Uses DataMarker and DnsLeakStatus enums directly.

        Args:
            name: Interface name

        Returns:
            InterfaceInfo with all fields set to default markers
        """
        return cls(
            name=name,
            interface_type=DataMarker.NOT_AVAILABLE,
            device=DataMarker.NOT_AVAILABLE,
            internal_ipv4=DataMarker.NOT_AVAILABLE,
            internal_ipv6=DataMarker.NOT_AVAILABLE,
            dns_servers=[],
            current_dns=None,
            dns_leak_status=DnsLeakStatus.NOT_APPLICABLE,
            external_ipv4=DataMarker.NOT_APPLICABLE,
            external_ipv6=DataMarker.NOT_APPLICABLE,
            egress_isp=DataMarker.NOT_APPLICABLE,
            egress_country=DataMarker.NOT_APPLICABLE,
            default_gateway=DataMarker.NONE_VALUE,
            metric=DataMarker.NONE_VALUE,
            vpn_server_ip=None,
            carries_vpn=False
        )


@dataclass
class EgressInfo:
    """
    Egress connection information from external API.

    Attributes:
        external_ip: Public IPv4 address
        external_ipv6: Public IPv6 address (or DataMarker if unavailable)
        isp: Internet Service Provider name
        country: Country code (ISO 3166-1 alpha-2)
    """

    external_ip: str
    external_ipv6: str
    isp: str
    country: str

    @classmethod
    def create_error(cls) -> "EgressInfo":
        """
        Create an EgressInfo indicating an error occurred.

        Returns:
            EgressInfo with all fields set to DataMarker.ERROR
        """
        return cls(
            external_ip=DataMarker.ERROR,
            external_ipv6=DataMarker.ERROR,
            isp=DataMarker.ERROR,
            country=DataMarker.ERROR
        )
