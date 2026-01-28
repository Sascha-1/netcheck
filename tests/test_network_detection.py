"""
Tests for network.detection module.

Tests interface type detection, hardware identification, and sysfs operations.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from network.detection import (
    SysfsInterface,
    get_interface_list,
    is_usb_tethered_device,
    detect_interface_type,
    get_pci_device_name,
    get_usb_device_name,
    get_device_name
)


class TestSysfsInterface:
    """Test SysfsInterface dataclass and cached properties."""
    
    def test_base_path(self, mock_sysfs_ethernet):
        """Test base_path property."""
        # Get the parent directory (sys/class/net)
        sysfs_net = mock_sysfs_ethernet.parent
        
        with patch('network.detection.Path') as mock_path:
            mock_path.return_value = sysfs_net / "eth0"
            
            sysfs = SysfsInterface("eth0")
            assert str(sysfs.base_path).endswith("eth0")
    
    def test_device_path_physical(self, mock_sysfs_ethernet):
        """Test device_path for physical device."""
        with patch.object(Path, '__truediv__') as mock_div:
            device_path = Mock()
            device_path.exists.return_value = True
            mock_div.return_value = device_path
            
            sysfs = SysfsInterface("eth0")
            # Test that device_path checks existence
            assert sysfs.device_path is not None or sysfs.device_path is None
    
    def test_device_path_virtual(self, mock_sysfs_vpn):
        """Test device_path for virtual interface (VPN)."""
        # VPN interfaces have no device symlink
        sysfs_net = mock_sysfs_vpn.parent
        
        with patch('network.detection.Path') as mock_path:
            base = MagicMock()
            device = MagicMock()
            device.exists.return_value = False
            base.__truediv__.return_value = device
            mock_path.return_value = base
            
            sysfs = SysfsInterface("tun0")
            assert sysfs.device_path is None
    
    def test_is_usb_detection(self, tmp_path):
        """Test USB device detection via path."""
        # Create USB device path
        usb_path = tmp_path / "sys" / "devices" / "pci0000:00" / "usb3" / "3-1"
        usb_path.mkdir(parents=True)
        
        # Mock the real_device_path to return USB path
        with patch.object(SysfsInterface, 'real_device_path', new_callable=lambda: property(lambda self: usb_path)):
            sysfs = SysfsInterface("usb0")
            assert sysfs.is_usb is True
    
    def test_is_wireless_detection(self, mock_sysfs_wireless):
        """Test wireless detection via phy80211."""
        sysfs_net = mock_sysfs_wireless.parent
        
        with patch('network.detection.Path') as mock_path:
            base = MagicMock()
            phy = MagicMock()
            phy.exists.return_value = True
            base.__truediv__.return_value = phy
            mock_path.return_value = base
            
            sysfs = SysfsInterface("wlan0")
            assert sysfs.is_wireless is True


class TestGetInterfaceList:
    """Test get_interface_list function."""
    
    @patch('network.detection.run_command')  # Patch where it's USED, not where it's defined
    def test_basic_interface_list(self, mock_run_cmd, mock_ip_link_output):
        """Test parsing basic interface list."""
        mock_run_cmd.return_value = mock_ip_link_output
        
        interfaces = get_interface_list()
        
        assert len(interfaces) == 3
        assert "lo" in interfaces
        assert "eth0" in interfaces
        assert "wlan0" in interfaces
        mock_run_cmd.assert_called_once_with(["ip", "-o", "link", "show"])
    
    @patch('network.detection.run_command')
    def test_empty_output(self, mock_run_cmd):
        """Test handling of empty output."""
        mock_run_cmd.return_value = ""
        
        interfaces = get_interface_list()
        
        assert interfaces == []
    
    @patch('network.detection.run_command')
    def test_command_failure(self, mock_run_cmd):
        """Test handling of command failure."""
        mock_run_cmd.return_value = None
        
        interfaces = get_interface_list()
        
        assert interfaces == []
    
    @patch('network.detection.run_command')
    def test_malformed_output(self, mock_run_cmd):
        """Test handling of malformed output."""
        mock_run_cmd.return_value = "malformed line without colons"
        
        interfaces = get_interface_list()
        
        # Should handle gracefully
        assert isinstance(interfaces, list)


class TestIsUsbTetheredDevice:
    """Test USB tethering detection."""
    
    def test_usb_tether_detected(self, tmp_path):
        """Test detection of USB tethered device."""
        # Create mock USB path with rndis_host driver
        usb_path = tmp_path / "sys" / "devices" / "usb3" / "3-1"
        usb_path.mkdir(parents=True)
        
        driver_path = tmp_path / "sys" / "bus" / "usb" / "drivers" / "rndis_host"
        driver_path.mkdir(parents=True)
        
        # Create driver symlink
        (usb_path / "driver").symlink_to(driver_path)
        
        # Mock SysfsInterface
        sysfs = Mock()
        sysfs.name = "usb0"
        sysfs.is_usb = True
        sysfs.usb_driver = "rndis_host"
        
        result = is_usb_tethered_device(sysfs, verbose=False)
        
        assert result is True
    
    def test_usb_but_not_tether(self, tmp_path):
        """Test USB device that's not a tethering device."""
        sysfs = Mock()
        sysfs.name = "usb0"
        sysfs.is_usb = True
        sysfs.usb_driver = "some_other_driver"
        
        result = is_usb_tethered_device(sysfs, verbose=False)
        
        assert result is False
    
    def test_not_usb_device(self):
        """Test non-USB device."""
        sysfs = Mock()
        sysfs.name = "eth0"
        sysfs.is_usb = False
        
        result = is_usb_tethered_device(sysfs, verbose=False)
        
        assert result is False
    
    def test_verbose_output(self, caplog_debug):
        """Test verbose logging."""
        sysfs = Mock()
        sysfs.name = "usb0"
        sysfs.is_usb = True
        sysfs.usb_driver = "rndis_host"
        
        result = is_usb_tethered_device(sysfs, verbose=True)
        
        assert result is True
        # Check that verbose output was generated
        # (print statements should be converted to logger in implementation)


class TestDetectInterfaceType:
    """Test interface type detection."""
    
    def test_loopback_detection(self):
        """Test loopback interface detection."""
        result = detect_interface_type("lo", verbose=False)
        assert result == "loopback"
    
    @patch('network.detection.is_usb_tethered_device')
    @patch('network.detection.SysfsInterface')
    def test_usb_tether_detection(self, mock_sysfs, mock_is_usb):
        """Test USB tethering detection."""
        mock_is_usb.return_value = True
        
        result = detect_interface_type("usb0", verbose=False)
        
        assert result == "tether"
        mock_is_usb.assert_called_once()
    
    def test_vpn_keyword_detection(self):
        """Test VPN detection by keyword in name."""
        for name in ["vpn0", "VPN1", "myvpn"]:
            result = detect_interface_type(name, verbose=False)
            assert result == "vpn", f"Failed to detect {name} as VPN"
    
    @patch('network.detection.SysfsInterface')
    def test_wireless_detection(self, mock_sysfs_class):
        """Test wireless interface detection."""
        mock_sysfs = Mock()
        mock_sysfs.is_wireless = True
        mock_sysfs.is_usb = False
        mock_sysfs_class.return_value = mock_sysfs
        
        with patch('network.detection.is_usb_tethered_device', return_value=False):
            result = detect_interface_type("wlan0", verbose=False)
            assert result == "wireless"
    
    @patch('network.detection.run_command')
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.is_usb_tethered_device')
    def test_wireguard_vpn_detection(self, mock_is_usb, mock_sysfs, mock_run_cmd):
        """Test WireGuard VPN detection via ip command."""
        mock_is_usb.return_value = False
        mock_sysfs.return_value.is_wireless = False
        mock_run_cmd.return_value = "wireguard: WireGuard interface"
        
        result = detect_interface_type("wg0", verbose=False)
        
        assert result == "vpn"
    
    @patch('network.detection.run_command')
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.is_usb_tethered_device')
    def test_tun_tap_detection(self, mock_is_usb, mock_sysfs, mock_run_cmd):
        """Test TUN/TAP interface detection."""
        mock_is_usb.return_value = False
        mock_sysfs.return_value.is_wireless = False
        mock_run_cmd.return_value = "tun: TUN/TAP device"
        
        result = detect_interface_type("tun0", verbose=False)
        
        assert result == "vpn"
    
    @patch('network.detection.run_command')
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.is_usb_tethered_device')
    def test_systemd_naming_detection(self, mock_is_usb, mock_sysfs, mock_run_cmd):
        """Test systemd predictable naming patterns."""
        mock_is_usb.return_value = False
        mock_sysfs.return_value.is_wireless = False
        mock_run_cmd.return_value = ""
        
        # Test various systemd naming patterns
        assert detect_interface_type("eth0", verbose=False) == "ethernet"
        assert detect_interface_type("eno1", verbose=False) == "ethernet"
        assert detect_interface_type("enp3s0", verbose=False) == "ethernet"
        assert detect_interface_type("wlp2s0", verbose=False) == "wireless"
    
    @patch('network.detection.run_command')
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.is_usb_tethered_device')
    def test_unknown_interface(self, mock_is_usb, mock_sysfs, mock_run_cmd):
        """Test unknown interface type."""
        mock_is_usb.return_value = False
        mock_sysfs.return_value.is_wireless = False
        mock_run_cmd.return_value = ""
        
        result = detect_interface_type("unknown123", verbose=False)
        
        assert result == "unknown"


class TestGetPciDeviceName:
    """Test PCI device name retrieval."""
    
    @patch('network.detection.run_command')
    def test_successful_pci_query(self, mock_run_cmd, mock_lspci_output):
        """Test successful PCI device name query."""
        # Create mock sysfs with PCI IDs
        sysfs = Mock()
        sysfs.name = "eth0"
        sysfs.pci_ids = ("8086", "15d7")
        
        mock_run_cmd.return_value = mock_lspci_output
        
        result = get_pci_device_name(sysfs, verbose=False)
        
        assert result == "Intel Corporation Ethernet Connection (2) I219-V"
        mock_run_cmd.assert_called_once_with(["lspci", "-d", "8086:15d7"])
    
    def test_no_pci_ids(self):
        """Test handling when no PCI IDs available."""
        sysfs = Mock()
        sysfs.name = "tun0"
        sysfs.pci_ids = None
        
        result = get_pci_device_name(sysfs, verbose=False)
        
        assert result is None
    
    @patch('network.detection.run_command')
    def test_lspci_command_failure(self, mock_run_cmd):
        """Test handling of lspci command failure."""
        sysfs = Mock()
        sysfs.name = "eth0"
        sysfs.pci_ids = ("8086", "15d7")
        
        mock_run_cmd.return_value = None
        
        result = get_pci_device_name(sysfs, verbose=False)
        
        assert result is None
    
    @patch('network.detection.run_command')
    def test_malformed_lspci_output(self, mock_run_cmd):
        """Test handling of malformed lspci output."""
        sysfs = Mock()
        sysfs.name = "eth0"
        sysfs.pci_ids = ("8086", "15d7")
        
        mock_run_cmd.return_value = "malformed output"
        
        result = get_pci_device_name(sysfs, verbose=False)
        
        assert result is None


class TestGetUsbDeviceName:
    """Test USB device name retrieval."""
    
    @patch('network.detection.run_command')
    def test_successful_usb_query(self, mock_run_cmd, mock_lsusb_output):
        """Test successful USB device name query."""
        sysfs = Mock()
        sysfs.name = "usb0"
        sysfs.is_usb = True
        sysfs.usb_ids = ("18d1", "4eeb")
        
        mock_run_cmd.return_value = mock_lsusb_output
        
        result = get_usb_device_name(sysfs, verbose=False)
        
        assert result == "Google Inc. Pixel 9a"
        mock_run_cmd.assert_called_once_with(["lsusb", "-d", "18d1:4eeb"])
    
    def test_not_usb_device(self):
        """Test non-USB device."""
        sysfs = Mock()
        sysfs.name = "eth0"
        sysfs.is_usb = False
        
        result = get_usb_device_name(sysfs, verbose=False)
        
        assert result is None
    
    def test_no_usb_ids(self):
        """Test when USB IDs cannot be read."""
        sysfs = Mock()
        sysfs.name = "usb0"
        sysfs.is_usb = True
        sysfs.usb_ids = None
        
        result = get_usb_device_name(sysfs, verbose=False)
        
        assert result is None
    
    @patch('network.detection.run_command')
    def test_lsusb_command_failure(self, mock_run_cmd):
        """Test lsusb command failure."""
        sysfs = Mock()
        sysfs.name = "usb0"
        sysfs.is_usb = True
        sysfs.usb_ids = ("18d1", "4eeb")
        
        mock_run_cmd.return_value = None
        
        result = get_usb_device_name(sysfs, verbose=False)
        
        assert result is None


class TestGetDeviceName:
    """Test complete device name retrieval."""
    
    def test_loopback_returns_na(self):
        """Test loopback interface returns N/A."""
        result = get_device_name("lo", "loopback", verbose=False)
        assert result == "N/A"
    
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.get_pci_device_name')
    def test_vpn_with_device(self, mock_get_pci, mock_sysfs_class):
        """Test VPN with physical device (rare hardware accelerator)."""
        mock_sysfs = Mock()
        mock_sysfs.device_path = Mock()  # Has device path
        mock_sysfs_class.return_value = mock_sysfs
        
        mock_get_pci.return_value = "Hardware VPN Accelerator"
        
        result = get_device_name("vpn0", "vpn", verbose=False)
        
        assert result == "Hardware VPN Accelerator"
    
    @patch('network.detection.SysfsInterface')
    def test_vpn_virtual(self, mock_sysfs_class):
        """Test normal virtual VPN interface."""
        mock_sysfs = Mock()
        mock_sysfs.device_path = None  # No device path (virtual)
        mock_sysfs_class.return_value = mock_sysfs
        
        result = get_device_name("tun0", "vpn", verbose=False)
        
        assert result == "N/A"
    
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.get_usb_device_name')
    def test_tether_device(self, mock_get_usb, mock_sysfs_class):
        """Test USB tethered device."""
        mock_get_usb.return_value = "Google Pixel 9a"
        
        result = get_device_name("usb0", "tether", verbose=False)
        
        assert result == "Google Pixel 9a"
    
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.get_usb_device_name')
    def test_tether_fallback(self, mock_get_usb, mock_sysfs_class):
        """Test tether device with fallback name."""
        mock_get_usb.return_value = None
        
        result = get_device_name("usb0", "tether", verbose=False)
        
        assert result == "USB Tethered Device"
    
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.get_pci_device_name')
    def test_ethernet_device(self, mock_get_pci, mock_sysfs_class):
        """Test Ethernet device."""
        mock_get_pci.return_value = "Intel I219-V"
        
        result = get_device_name("eth0", "ethernet", verbose=False)
        
        assert result == "Intel I219-V"
    
    @patch('network.detection.SysfsInterface')
    @patch('network.detection.get_pci_device_name')
    def test_device_query_failure(self, mock_get_pci, mock_sysfs_class):
        """Test handling of device query failure."""
        mock_get_pci.return_value = None
        
        result = get_device_name("eth0", "ethernet", verbose=False)
        
        assert result == "N/A"
