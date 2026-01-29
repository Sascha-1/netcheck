"""
Interface and hardware detection module.

Consolidates interface type detection and hardware identification.

DESIGN PRINCIPLE: Consistent deterministic querying
- PCI devices: Read vendor:device from sysfs → Query lspci database
- USB devices: Read vendor:product from sysfs → Query lsusb database
- Return raw data from databases - cleaning happens at display time
"""

import sys
from pathlib import Path
from functools import cached_property
from dataclasses import dataclass

from logging_config import get_logger
from utils.system import run_command
from config import INTERFACE_TYPE_PATTERNS, USB_TETHER_DRIVERS
from enums import InterfaceType, DataMarker

logger = get_logger(__name__)


@dataclass
class SysfsInterface:
    """
    Encapsulates sysfs operations for a network interface.
    
    Provides cached properties for expensive filesystem operations.
    All hardware ID queries use consistent pattern: read from sysfs, query database.
    """
    name: str
    
    @cached_property
    def base_path(self) -> Path:
        """Base sysfs path for this interface."""
        return Path(f"/sys/class/net/{self.name}")
    
    @cached_property
    def device_path(self) -> Path | None:
        """Physical device path, or None if virtual interface."""
        path = self.base_path / "device"
        return path if path.exists() else None
    
    @cached_property
    def real_device_path(self) -> Path | None:
        """Resolved real path to device, or None if virtual."""
        return self.device_path.resolve() if self.device_path else None
    
    @cached_property
    def is_usb(self) -> bool:
        """True if device is on USB bus."""
        return bool(self.real_device_path and '/usb' in str(self.real_device_path))
    
    @cached_property
    def is_wireless(self) -> bool:
        """True if device is wireless (has phy80211)."""
        return (self.base_path / "phy80211").exists()
    
    @cached_property
    def usb_driver(self) -> str | None:
        """USB driver name, or None if not USB device."""
        if not self.real_device_path:
            return None
        
        driver_path = self.real_device_path / "driver"
        if driver_path.exists():
            return driver_path.resolve().name
        return None
    
    @cached_property
    def pci_ids(self) -> tuple[str, str] | None:
        """
        PCI vendor:device IDs from sysfs.
        
        Returns tuple of (vendor_id, device_id) or None.
        """
        if not self.real_device_path:
            return None
        
        vendor_file = self.real_device_path / "vendor"
        device_file = self.real_device_path / "device"
        
        if not (vendor_file.exists() and device_file.exists()):
            return None
        
        try:
            vendor_id = vendor_file.read_text().strip().replace('0x', '')
            device_id = device_file.read_text().strip().replace('0x', '')
            return (vendor_id, device_id)
        except Exception as e:
            logger.warning(f"Failed to read PCI IDs for {self.name}: {e}")
            return None
    
    @cached_property
    def usb_ids(self) -> tuple[str, str] | None:
        """
        USB vendor:product IDs from sysfs.
        
        Navigates USB device tree to find idVendor and idProduct files.
        Returns tuple of (vendor_id, product_id) or None.
        """
        if not self.real_device_path:
            return None
        
        current_path = self.real_device_path
        
        while current_path and current_path != Path('/'):
            vendor_file = current_path / "idVendor"
            product_file = current_path / "idProduct"
            
            if vendor_file.exists() and product_file.exists():
                try:
                    vendor_id = vendor_file.read_text().strip()
                    product_id = product_file.read_text().strip()
                    return (vendor_id, product_id)
                except Exception as e:
                    logger.warning(f"Failed to read USB IDs for {self.name}: {e}")
                    break
            
            current_path = current_path.parent
        
        return None


def get_interface_list() -> list[str]:
    """
    Get list of all network interfaces from kernel.
    
    Returns:
        List of interface names
    """
    logger.debug("Querying network interfaces via 'ip -o link show'")
    
    if not (output := run_command(["ip", "-o", "link", "show"])):
        logger.warning("Failed to get interface list from 'ip' command")
        return []
    
    interfaces = []
    for line in output.split("\n"):
        if line and len(parts := line.split(":", 2)) >= 2:
            interfaces.append(parts[1].strip())
    
    logger.debug(f"Found {len(interfaces)} interfaces: {', '.join(interfaces)}")
    return interfaces


def is_usb_tethered_device(sysfs: SysfsInterface, verbose: bool = False) -> bool:
    """
    Determine if interface is a USB-tethered device.
    
    Checks driver name against known USB tethering drivers.
    Deterministic on kernel 6.12+ with modern hardware.
    
    Args:
        sysfs: SysfsInterface object
        verbose: If True, use debug logging (legacy parameter)
    
    Returns:
        True if USB tethering device
    """
    if not sysfs.is_usb:
        return False
    
    logger.debug(f"[{sysfs.name}] Device is on USB bus")
    
    if driver := sysfs.usb_driver:
        logger.debug(f"[{sysfs.name}] USB driver: {driver}")
        
        if driver in USB_TETHER_DRIVERS:
            logger.debug(f"[{sysfs.name}] Matched tethering driver: {driver}")
            return True
        
        logger.debug(f"[{sysfs.name}] Driver '{driver}' is not a tethering driver")
    
    return False


def detect_interface_type(iface_name: str, verbose: bool = False) -> str:
    """
    Detect network interface type.
    
    Priority (most to least deterministic):
    1. Explicit loopback check
    2. USB tethering via sysfs driver
    3. VPN keyword in name
    4. Wireless via phy80211
    5. Kernel link type
    6. Name prefix patterns
    
    Args:
        iface_name: Interface name
        verbose: If True, use debug logging (legacy parameter)
    
    Returns:
        Interface type string (InterfaceType enum value)
    """
    if iface_name == "lo":
        logger.debug(f"[{iface_name}] Detected as loopback")
        return str(InterfaceType.LOOPBACK)
    
    sysfs = SysfsInterface(iface_name)
    
    if is_usb_tethered_device(sysfs, verbose):
        logger.debug(f"[{iface_name}] Detected as tether (USB)")
        return str(InterfaceType.TETHER)
    
    if "vpn" in iface_name.lower():
        logger.debug(f"[{iface_name}] Detected as VPN (keyword in name)")
        return str(InterfaceType.VPN)
    
    if sysfs.is_wireless:
        logger.debug(f"[{iface_name}] Detected as wireless (phy80211 present)")
        return str(InterfaceType.WIRELESS)
    
    if output := run_command(["ip", "-d", "link", "show", iface_name]):
        output_lower = output.lower()
        
        if "wireguard" in output_lower:
            logger.debug(f"[{iface_name}] Detected as VPN (WireGuard)")
            return str(InterfaceType.VPN)
        
        if "tun" in output_lower or "tap" in output_lower:
            logger.debug(f"[{iface_name}] Detected as VPN (TUN/TAP)")
            return str(InterfaceType.VPN)
        
        if "veth" in output_lower:
            logger.debug(f"[{iface_name}] Detected as virtual (veth)")
            return str(InterfaceType.VIRTUAL)
        
        if "bridge" in output_lower:
            logger.debug(f"[{iface_name}] Detected as bridge")
            return str(InterfaceType.BRIDGE)
    
    for prefix, iface_type in INTERFACE_TYPE_PATTERNS.items():
        if iface_name.startswith(prefix):
            logger.debug(f"[{iface_name}] Detected as {iface_type} (systemd prefix '{prefix}')")
            return iface_type
    
    logger.warning(f"[{iface_name}] Type unknown (no detection method matched)")
    return str(InterfaceType.UNKNOWN)


def get_pci_device_name(sysfs: SysfsInterface, verbose: bool = False) -> str | None:
    """
    Get PCI device name from hardware database.
    
    Consistent query pattern:
    1. Read vendor:device IDs from sysfs
    2. Query lspci database with those IDs
    3. Return raw device name
    
    Args:
        sysfs: SysfsInterface object
        verbose: If True, use debug logging (legacy parameter)
        
    Returns:
        Raw device name or None
    """
    if not (pci_ids := sysfs.pci_ids):
        logger.debug(f"[{sysfs.name}] No PCI IDs found")
        return None
    
    vendor_id, device_id = pci_ids
    
    logger.debug(f"[{sysfs.name}] PCI ID: {vendor_id}:{device_id}")
    
    if not (lspci_output := run_command(["lspci", "-d", f"{vendor_id}:{device_id}"])):
        logger.error(f"lspci query failed for {sysfs.name} ({vendor_id}:{device_id})")
        return None
    
    if not (lines := lspci_output.strip().split('\n')):
        logger.warning(f"Empty lspci output for {sysfs.name}")
        return None
    
    if len(parts := lines[0].split(':', 2)) >= 3:
        device_name = parts[2].strip()
        logger.debug(f"[{sysfs.name}] Device: {device_name}")
        return device_name
    
    logger.warning(f"Failed to parse lspci output for {sysfs.name}")
    return None


def get_usb_device_name(sysfs: SysfsInterface, verbose: bool = False) -> str | None:
    """
    Get USB device name from hardware database.
    
    Consistent query pattern (same as PCI):
    1. Read vendor:product IDs from sysfs
    2. Query lsusb database with those IDs
    3. Return raw device name
    
    Args:
        sysfs: SysfsInterface object
        verbose: If True, use debug logging (legacy parameter)
        
    Returns:
        Raw device name or None
    """
    if not sysfs.is_usb:
        return None
    
    logger.debug(f"[{sysfs.name}] USB device detected, querying lsusb...")
    
    if not (usb_ids := sysfs.usb_ids):
        logger.error(f"Could not read USB IDs from sysfs for {sysfs.name}")
        return None
    
    vendor_id, product_id = usb_ids
    
    logger.debug(f"[{sysfs.name}] USB ID: {vendor_id}:{product_id}")
    
    if not (lsusb_output := run_command(["lsusb", "-d", f"{vendor_id}:{product_id}"])):
        logger.error(f"lsusb query failed for {sysfs.name} ({vendor_id}:{product_id})")
        return None
    
    if not (lines := lsusb_output.strip().split('\n')):
        logger.warning(f"Empty lsusb output for {sysfs.name}")
        return None
    
    # Parse format: "Bus 005 Device 013: ID 18d1:4eeb Google Inc. Pixel 9a"
    line = lines[0]
    
    if "ID " not in line:
        logger.error(f"Unexpected lsusb format for {sysfs.name}")
        return None
    
    # Split on "ID " and take the second part
    id_part = line.split("ID ", 1)[1]
    
    # Now we have "18d1:4eeb Google Inc. Pixel 9a"
    # Split on whitespace and skip first element (the vendor:product ID)
    parts = id_part.split(None, 1)
    
    if len(parts) < 2:
        logger.error(f"No device name in lsusb output for {sysfs.name}")
        return None
    
    device_name = parts[1]
    logger.debug(f"[{sysfs.name}] Device: {device_name}")
    return device_name


def get_device_name(iface_name: str, iface_type: str, verbose: bool = False) -> str:
    """
    Get hardware device name for network interface.
    
    Consistent approach:
    - Virtual interfaces (loopback, VPN): Return DataMarker.NOT_AVAILABLE
    - PCI devices: Query lspci database
    - USB devices: Query lsusb database
    
    All names returned raw - cleaning at display time.
    
    Args:
        iface_name: Interface name
        iface_type: Interface type (InterfaceType enum value)
        verbose: If True, use debug logging (legacy parameter)
        
    Returns:
        Raw device name or DataMarker.NOT_AVAILABLE
    """
    match iface_type:
        case str(InterfaceType.LOOPBACK) | InterfaceType.LOOPBACK.value:
            return str(DataMarker.NOT_AVAILABLE)
        
        case str(InterfaceType.VPN) | InterfaceType.VPN.value:
            sysfs = SysfsInterface(iface_name)
            
            if sysfs.device_path:
                # Rare: hardware VPN accelerator
                if device_name := get_pci_device_name(sysfs, verbose):
                    logger.debug(f"[{iface_name}] VPN has hardware device: {device_name}")
                    return device_name
            else:
                # Normal: virtual VPN interface
                logger.debug(f"[{iface_name}] Virtual VPN interface")
                if output := run_command(["ip", "-d", "link", "show", iface_name]):
                    if "wireguard" in output.lower():
                        logger.debug(f"[{iface_name}] VPN protocol: WireGuard")
                    else:
                        logger.debug(f"[{iface_name}] VPN protocol: Generic")
            
            return str(DataMarker.NOT_AVAILABLE)
        
        case str(InterfaceType.TETHER) | InterfaceType.TETHER.value:
            sysfs = SysfsInterface(iface_name)
            return get_usb_device_name(sysfs, verbose) or "USB Tethered Device"
        
        case _:
            # Physical PCI/PCIe devices
            sysfs = SysfsInterface(iface_name)
            return get_pci_device_name(sysfs, verbose) or str(DataMarker.NOT_AVAILABLE)
