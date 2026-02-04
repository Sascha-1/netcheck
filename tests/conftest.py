"""
Pytest configuration and shared fixtures.

Provides comprehensive fixtures for mocking system components and creating
test data throughout the test suite.
"""

import pytest
from pathlib import Path
from typing import Generator, List
from unittest.mock import Mock, patch, MagicMock
import logging

# Type imports for fixtures
from _pytest.logging import LogCaptureFixture
from _pytest.config import Config
from models import InterfaceInfo, EgressInfo


# ============================================================================
# Logging Fixtures
# ============================================================================

@pytest.fixture
def disable_logging() -> Generator[None, None, None]:
    """Disable logging during tests to reduce noise."""
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


@pytest.fixture
def caplog_debug(caplog: LogCaptureFixture) -> LogCaptureFixture:
    """Capture DEBUG level logs in tests."""
    caplog.set_level(logging.DEBUG)
    return caplog


# ============================================================================
# Sysfs Mocking Fixtures
# ============================================================================

@pytest.fixture
def mock_sysfs_base(tmp_path: Path) -> Path:
    """
    Create base mock sysfs filesystem structure.

    Creates /sys/class/net directory structure for testing.

    Returns:
        Path to mock /sys/class/net directory
    """
    sysfs_net = tmp_path / "sys" / "class" / "net"
    sysfs_net.mkdir(parents=True)
    return sysfs_net


@pytest.fixture
def mock_sysfs_ethernet(mock_sysfs_base: Path, tmp_path: Path) -> Path:
    """
    Create mock Ethernet interface (eth0) with PCI device.

    Returns:
        Path to eth0 interface directory
    """
    # Create eth0 interface
    eth0 = mock_sysfs_base / "eth0"
    eth0.mkdir()

    # Create mock PCI device
    pci_device = tmp_path / "sys" / "devices" / "pci0000:00" / "0000:00:1f.6"
    pci_device.mkdir(parents=True)
    (pci_device / "vendor").write_text("0x8086\n")
    (pci_device / "device").write_text("0x15d7\n")

    # Link interface to device
    (eth0 / "device").symlink_to(pci_device)

    # Create type file
    (eth0 / "type").write_text("1\n")  # Ethernet type

    return eth0


@pytest.fixture
def mock_sysfs_wireless(mock_sysfs_base: Path, tmp_path: Path) -> Path:
    """
    Create mock wireless interface (wlan0) with PCI device and phy80211.

    Returns:
        Path to wlan0 interface directory
    """
    # Create wlan0 interface
    wlan0 = mock_sysfs_base / "wlan0"
    wlan0.mkdir()

    # Create mock PCI device
    pci_device = tmp_path / "sys" / "devices" / "pci0000:00" / "0000:00:14.3"
    pci_device.mkdir(parents=True)
    (pci_device / "vendor").write_text("0x8086\n")
    (pci_device / "device").write_text("0x2723\n")

    # Link interface to device
    (wlan0 / "device").symlink_to(pci_device)

    # Create phy80211 marker
    (wlan0 / "phy80211").mkdir()

    return wlan0


@pytest.fixture
def mock_sysfs_usb_tether(mock_sysfs_base: Path, tmp_path: Path) -> Path:
    """
    Create mock USB tethered device (usb0).

    Returns:
        Path to usb0 interface directory
    """
    # Create usb0 interface
    usb0 = mock_sysfs_base / "usb0"
    usb0.mkdir()

    # Create mock USB device path
    usb_device = tmp_path / "sys" / "devices" / "pci0000:00" / "0000:00:14.0" / "usb3" / "3-1"
    usb_device.mkdir(parents=True)

    # USB IDs
    (usb_device / "idVendor").write_text("18d1\n")
    (usb_device / "idProduct").write_text("4eeb\n")
    (usb_device / "manufacturer").write_text("Google Inc.\n")
    (usb_device / "product").write_text("Pixel 9a\n")

    # Create driver link
    driver_path = usb_device / "driver"
    driver_target = tmp_path / "sys" / "bus" / "usb" / "drivers" / "rndis_host"
    driver_target.mkdir(parents=True)
    driver_path.symlink_to(driver_target)

    # Link interface to USB device
    (usb0 / "device").symlink_to(usb_device)

    return usb0


@pytest.fixture
def mock_sysfs_vpn(mock_sysfs_base: Path) -> Path:
    """
    Create mock VPN interface (tun0) - virtual, no device.

    Returns:
        Path to tun0 interface directory
    """
    tun0 = mock_sysfs_base / "tun0"
    tun0.mkdir()
    # VPN interfaces have no device symlink
    return tun0


@pytest.fixture
def mock_sysfs_loopback(mock_sysfs_base: Path) -> Path:
    """
    Create mock loopback interface (lo).

    Returns:
        Path to lo interface directory
    """
    lo = mock_sysfs_base / "lo"
    lo.mkdir()
    (lo / "type").write_text("772\n")  # Loopback type
    return lo


# ============================================================================
# Command Output Fixtures
# ============================================================================

@pytest.fixture
def mock_ip_link_output() -> str:
    """Sample output from 'ip -o link show' command."""
    return """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
3: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000"""


@pytest.fixture
def mock_ip_addr_ipv4_output() -> str:
    """Sample output from 'ip -4 addr show eth0' command."""
    return """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86395sec preferred_lft 86395sec"""


@pytest.fixture
def mock_ip_addr_ipv6_output() -> str:
    """Sample output from 'ip -6 addr show eth0' command."""
    return """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet6 2001:db8::1/64 scope global dynamic
       valid_lft 86395sec preferred_lft 86395sec
    inet6 fe80::211:22ff:fe33:4455/64 scope link
       valid_lft forever preferred_lft forever"""


@pytest.fixture
def mock_ip_route_output() -> str:
    """Sample output from 'ip route show dev eth0' command."""
    return """default via 192.168.1.1 proto dhcp src 192.168.1.100 metric 100
192.168.1.0/24 proto kernel scope link src 192.168.1.100 metric 100"""


@pytest.fixture
def mock_lspci_output() -> str:
    """Sample output from 'lspci -d vendor:device' command."""
    return "00:1f.6 Ethernet controller: Intel Corporation Ethernet Connection (2) I219-V"


@pytest.fixture
def mock_lsusb_output() -> str:
    """Sample output from 'lsusb -d vendor:product' command."""
    return "Bus 003 Device 005: ID 18d1:4eeb Google Inc. Pixel 9a"


@pytest.fixture
def mock_resolvectl_output() -> str:
    """Sample output from 'resolvectl status eth0' command."""
    return """Link 2 (eth0)
    Current Scopes: DNS
     DefaultRoute setting: yes
      LLMNR setting: yes
MulticastDNS setting: no
  DNSOverTLS setting: no
      DNSSEC setting: no
    DNSSEC supported: no
  Current DNS Server: 8.8.8.8
         DNS Servers: 8.8.8.8
                      8.8.4.4
          DNS Domain: ~."""


@pytest.fixture
def mock_ss_output() -> str:
    """Sample output from 'ss -tun' command showing DNS connections."""
    return """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   ESTAB  0      0      192.168.1.100:54321 8.8.8.8:53
udp   ESTAB  0      0      10.2.0.2:54322      10.2.0.1:53"""


# ============================================================================
# Mock Function Fixtures
# ============================================================================

@pytest.fixture
def mock_run_command() -> Generator[Mock, None, None]:
    """
    Mock the run_command function from utils.system.

    Usage in tests:
        def test_something(mock_run_command):
            mock_run_command.return_value = "output"
            # test code here

    Yields:
        Mock object for run_command
    """
    with patch('utils.system.run_command') as mock:
        yield mock


@pytest.fixture
def mock_requests_get() -> Generator[Mock, None, None]:
    """
    Mock requests.get for API testing.

    Yields:
        Mock object for requests.get
    """
    with patch('requests.get') as mock:
        yield mock


@pytest.fixture
def mock_subprocess_run() -> Generator[Mock, None, None]:
    """
    Mock subprocess.run for testing command execution.

    Yields:
        Mock object for subprocess.run
    """
    with patch('subprocess.run') as mock:
        yield mock


# ============================================================================
# Data Model Fixtures
# ============================================================================

@pytest.fixture
def sample_interface_info() -> InterfaceInfo:
    """
    Create a sample InterfaceInfo object for testing.

    Returns:
        InterfaceInfo with realistic sample data
    """
    return InterfaceInfo(
        name="eth0",
        interface_type="ethernet",
        device="Intel Corporation I219-V",
        internal_ipv4="192.168.1.100",
        internal_ipv6="2001:db8::1",
        dns_servers=["8.8.8.8", "8.8.4.4"],
        current_dns="8.8.8.8",
        dns_leak_status="--",
        external_ipv4="1.2.3.4",
        external_ipv6="2001:db8:100::1",
        egress_isp="AS12345 Example ISP",
        egress_country="US",
        default_gateway="192.168.1.1",
        metric="100"
    )


@pytest.fixture
def sample_vpn_interface_info() -> InterfaceInfo:
    """
    Create a sample VPN InterfaceInfo object.

    Returns:
        InterfaceInfo for a VPN interface
    """
    return InterfaceInfo(
        name="tun0",
        interface_type="vpn",
        device="N/A",
        internal_ipv4="10.2.0.2",
        internal_ipv6="2a07:b944::2:2",
        dns_servers=["10.2.0.1"],
        current_dns="10.2.0.1",
        dns_leak_status="OK",
        external_ipv4="159.26.108.89",
        external_ipv6="2a07:b944::100",
        egress_isp="AS12345 VPN Provider",
        egress_country="SE",
        default_gateway="NONE",
        metric="NONE"
    )


@pytest.fixture
def sample_egress_info() -> EgressInfo:
    """
    Create a sample EgressInfo object.

    Returns:
        EgressInfo with realistic data
    """
    return EgressInfo(
        external_ip="1.2.3.4",
        external_ipv6="2001:db8:100::1",
        isp="AS12345 Example ISP",
        country="US"
    )


@pytest.fixture
def sample_interface_list() -> List[InterfaceInfo]:
    """
    Create a list of sample InterfaceInfo objects.

    Returns:
        List of InterfaceInfo objects representing typical system
    """
    return [
        InterfaceInfo.create_empty("lo"),
        InterfaceInfo(
            name="eth0",
            interface_type="ethernet",
            device="Intel I219-V",
            internal_ipv4="192.168.1.100",
            internal_ipv6="N/A",
            dns_servers=["192.168.1.1"],
            current_dns="192.168.1.1",
            dns_leak_status="--",
            external_ipv4="--",
            external_ipv6="--",
            egress_isp="--",
            egress_country="--",
            default_gateway="192.168.1.1",
            metric="100"
        ),
        InterfaceInfo(
            name="tun0",
            interface_type="vpn",
            device="N/A",
            internal_ipv4="10.2.0.2",
            internal_ipv6="N/A",
            dns_servers=["10.2.0.1"],
            current_dns="10.2.0.1",
            dns_leak_status="OK",
            external_ipv4="159.26.108.89",
            external_ipv6="--",
            egress_isp="VPN Provider",
            egress_country="SE",
            default_gateway="NONE",
            metric="NONE"
        )
    ]


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config: Config) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_root: marks tests that require root privileges"
    )
