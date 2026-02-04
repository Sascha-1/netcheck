"""
Tests for network interface detection and hardware identification.

Updated to match MEDIUM priority refactoring:
- SysfsInterface class removed, replaced with simple functions
- Tests now test the functions directly
- Added cache clearing for USB optimization tests
- Added type annotations for mypy strict compliance
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from typing import Generator

from network.detection import (
    get_interface_list,
    is_usb_tethered_device,
    detect_interface_type,
    get_pci_device_name,
    get_usb_device_name,
    get_device_name,
    _get_sysfs_base_path,
    _get_device_path,
    _is_usb_device,
    _is_wireless,
    _get_usb_driver,
    _get_pci_ids,
    _get_usb_ids,
    _get_usb_info,
)
from enums import InterfaceType, DataMarker


@pytest.fixture(autouse=True)
def clear_usb_cache() -> Generator[None, None, None]:
    """Clear USB info cache before each test to ensure fresh state."""
    _get_usb_info.cache_clear()
    yield
    _get_usb_info.cache_clear()


class TestSysfsHelperFunctions:
    """Tests for sysfs helper functions (replacing SysfsInterface tests)."""

    def test_get_sysfs_base_path(self) -> None:
        """Test getting sysfs base path."""
        path = _get_sysfs_base_path("eth0")
        assert path == Path("/sys/class/net/eth0")

    @patch('network.detection.Path.exists')
    @patch('network.detection.Path.resolve')
    def test_get_device_path_exists(self, mock_resolve: MagicMock, mock_exists: MagicMock) -> None:
        """Test getting device path when it exists."""
        mock_exists.return_value = True
        mock_resolve.return_value = Path("/sys/devices/pci0000:00/0000:00:1f.6")

        result = _get_device_path("eth0")
        assert result == Path("/sys/devices/pci0000:00/0000:00:1f.6")

    @patch('network.detection.Path.exists')
    def test_get_device_path_not_exists(self, mock_exists: MagicMock) -> None:
        """Test getting device path when it doesn't exist (virtual interface)."""
        mock_exists.return_value = False

        result = _get_device_path("lo")
        assert result is None

    @patch('network.detection._get_device_path')
    def test_is_usb_device_true(self, mock_get_device_path: MagicMock) -> None:
        """Test USB device detection."""
        mock_get_device_path.return_value = Path("/sys/devices/pci0000:00/usb1/1-1")

        assert _is_usb_device("eth0") is True

    @patch('network.detection._get_device_path')
    def test_is_usb_device_false(self, mock_get_device_path: MagicMock) -> None:
        """Test non-USB device."""
        mock_get_device_path.return_value = Path("/sys/devices/pci0000:00/0000:00:1f.6")
        assert _is_usb_device("eth0") is False

    @patch('network.detection._get_device_path')
    def test_is_usb_device_no_path(self, mock_get_device_path: MagicMock) -> None:
        """Test virtual interface (no device path)."""
        mock_get_device_path.return_value = None

        assert _is_usb_device("lo") is False

    @patch('network.detection.Path.exists')
    def test_is_wireless_true(self, mock_exists: MagicMock) -> None:
        """Test wireless interface detection."""
        mock_exists.return_value = True

        assert _is_wireless("wlan0") is True

    @patch('network.detection.Path.exists')
    def test_is_wireless_false(self, mock_exists: MagicMock) -> None:
        """Test non-wireless interface."""
        mock_exists.return_value = False

        assert _is_wireless("eth0") is False


class TestGetInterfaceList:
    """Tests for get_interface_list function."""

    @patch('network.detection.run_command')
    def test_get_interface_list_success(self, mock_run_command: MagicMock) -> None:
        """Test successful interface list retrieval."""
        mock_run_command.return_value = (
            "1: lo: <LOOPBACK,UP,LOWER_UP>\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
            "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>"
        )

        result = get_interface_list()
        assert result == ["lo", "eth0", "wlan0"]

    @patch('network.detection.run_command')
    def test_get_interface_list_empty(self, mock_run_command: MagicMock) -> None:
        """Test when no interfaces are found."""
        mock_run_command.return_value = None

        result = get_interface_list()
        assert result == []


class TestIsUsbTetheredDevice:
    """Tests for is_usb_tethered_device function."""

    @patch('network.detection._get_usb_driver')
    @patch('network.detection._is_usb_device')
    def test_usb_tether_detected(self, mock_is_usb: MagicMock, mock_get_driver: MagicMock) -> None:
        """Test detection of USB tethered device."""
        mock_is_usb.return_value = True
        mock_get_driver.return_value = "cdc_ether"

        assert is_usb_tethered_device("usb0") is True

    @patch('network.detection._is_usb_device')
    def test_not_usb_device(self, mock_is_usb: MagicMock) -> None:
        """Test non-USB device."""
        mock_is_usb.return_value = False

        assert is_usb_tethered_device("eth0") is False

    @patch('network.detection._get_usb_driver')
    @patch('network.detection._is_usb_device')
    def test_usb_but_not_tether(self, mock_is_usb: MagicMock, mock_get_driver: MagicMock) -> None:
        """Test USB device that's not a tether."""
        mock_is_usb.return_value = True
        mock_get_driver.return_value = "usbhid"

        assert is_usb_tethered_device("usb0") is False


class TestDetectInterfaceType:
    """Tests for detect_interface_type function."""

    def test_detect_loopback(self) -> None:
        """Test loopback interface detection."""
        assert detect_interface_type("lo") == InterfaceType.LOOPBACK

    @patch('network.detection.is_usb_tethered_device')
    def test_detect_tether(self, mock_is_tether: MagicMock) -> None:
        """Test USB tether detection."""
        mock_is_tether.return_value = True

        assert detect_interface_type("usb0") == InterfaceType.TETHER

    def test_detect_vpn_by_name(self) -> None:
        """Test VPN detection by interface name."""
        assert detect_interface_type("vpn0") == InterfaceType.VPN
        assert detect_interface_type("tun0") == InterfaceType.VPN

    @patch('network.detection._is_wireless')
    @patch('network.detection.is_usb_tethered_device')
    def test_detect_wireless(self, mock_is_tether: MagicMock, mock_is_wireless: MagicMock) -> None:
        """Test wireless interface detection."""
        mock_is_tether.return_value = False
        mock_is_wireless.return_value = True

        assert detect_interface_type("wlan0") == InterfaceType.WIRELESS

    @patch('network.detection.run_command')
    @patch('network.detection._is_wireless')
    @patch('network.detection.is_usb_tethered_device')
    def test_detect_ethernet_by_prefix(self, mock_is_tether: MagicMock, mock_is_wireless: MagicMock, mock_run_command: MagicMock) -> None:
        """Test ethernet detection by name prefix."""
        mock_is_tether.return_value = False
        mock_is_wireless.return_value = False
        mock_run_command.return_value = ""

        assert detect_interface_type("eth0") == InterfaceType.ETHERNET


class TestGetPciDeviceName:
    """Tests for get_pci_device_name function."""

    @patch('network.detection.run_command')
    @patch('network.detection._get_pci_ids')
    def test_get_pci_device_name_success(self, mock_get_ids: MagicMock, mock_run_command: MagicMock) -> None:
        """Test successful PCI device name retrieval."""
        mock_get_ids.return_value = ("8086", "15f3")
        mock_run_command.return_value = "00:1f.6 Ethernet controller: Intel Corporation Device 15f3"

        result = get_pci_device_name("eth0")
        assert result == "Intel Corporation Device 15f3"

    @patch('network.detection._get_pci_ids')
    def test_get_pci_device_name_no_ids(self, mock_get_ids: MagicMock) -> None:
        """Test when PCI IDs cannot be read."""
        mock_get_ids.return_value = None

        result = get_pci_device_name("lo")
        assert result is None


class TestGetUsbDeviceName:
    """Tests for get_usb_device_name function."""

    @patch('network.detection.run_command')
    @patch('network.detection._get_usb_ids')
    @patch('network.detection._is_usb_device')
    def test_get_usb_device_name_success(self, mock_is_usb: MagicMock, mock_get_ids: MagicMock, mock_run_command: MagicMock) -> None:
        """Test successful USB device name retrieval."""
        mock_is_usb.return_value = True
        mock_get_ids.return_value = ("0bda", "8153")
        mock_run_command.return_value = "Bus 001 Device 003: ID 0bda:8153 Realtek USB 10/100/1000 LAN"

        result = get_usb_device_name("usb0")
        assert result == "Realtek USB 10/100/1000 LAN"

    @patch('network.detection._is_usb_device')
    def test_get_usb_device_name_not_usb(self, mock_is_usb: MagicMock) -> None:
        """Test non-USB device."""
        mock_is_usb.return_value = False

        result = get_usb_device_name("eth0")
        assert result is None


class TestGetDeviceName:
    """Tests for get_device_name function."""

    def test_get_device_name_loopback(self) -> None:
        """Test device name for loopback interface."""
        result = get_device_name("lo", InterfaceType.LOOPBACK)
        assert result == DataMarker.NOT_AVAILABLE

    @patch('network.detection.get_usb_device_name')
    def test_get_device_name_tether(self, mock_get_usb: MagicMock) -> None:
        """Test device name for USB tether."""
        mock_get_usb.return_value = "Google Pixel"

        result = get_device_name("usb0", InterfaceType.TETHER)
        assert result == "Google Pixel"

    @patch('network.detection.get_usb_device_name')
    def test_get_device_name_tether_fallback(self, mock_get_usb: MagicMock) -> None:
        """Test device name for USB tether with fallback."""
        mock_get_usb.return_value = None

        result = get_device_name("usb0", InterfaceType.TETHER)
        assert result == "USB Tethered Device"

    @patch('network.detection.get_pci_device_name')
    def test_get_device_name_ethernet(self, mock_get_pci: MagicMock) -> None:
        """Test device name for ethernet."""
        mock_get_pci.return_value = "Intel I225-V"

        result = get_device_name("eth0", InterfaceType.ETHERNET)
        assert result == "Intel I225-V"

    def test_get_device_name_vpn(self) -> None:
        """Test device name for VPN."""
        result = get_device_name("tun0", InterfaceType.VPN)
        assert result == DataMarker.NOT_AVAILABLE
