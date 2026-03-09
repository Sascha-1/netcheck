"""Hardware detection and identification for netcheck.

Provides ModemManager integration, PCI device lookup, and USB device
detection.  All functions accept injectable protocol instances so the hardware
layer is fully testable without spawning subprocesses or requiring physical
hardware.

Exported names
--------------
From ``modem``:
    ``get_all_modem_data``    -- Query ModemManager; returns one record per modem.
    ``get_modem_interfaces``  -- Set of interface names owned by ModemManager.
    ``build_modem_info``      -- Build a ``ModemInfo`` for a specific interface.
    ``parse_modem_indices``   -- Parse modem indices from ``mmcli -L`` output.
    ``parse_modem_record``    -- Parse one modem's ``mmcli -m N -K`` output.

From ``pci``:
    ``get_pci_device_name``   -- Raw PCI device name via ``lspci``, or ``None``.
    ``read_pci_ids``          -- Read vendor/device IDs from sysfs.
    ``lookup_pci_name``       -- Resolve PCI IDs to a name via ``lspci``.

From ``usb``:
    ``USB_TETHER_DRIVERS``    -- Frozenset of driver names used by tethered phones.
    ``is_usb_interface``      -- ``True`` if the interface is USB-backed.
    ``is_usb_tether``         -- ``True`` if the interface uses a tether driver.
    ``get_usb_device_name``   -- Raw USB device name via ``lsusb``, or ``None``.
    ``get_usb_driver``        -- Kernel driver name for a USB interface, or ``None``.
    ``find_usb_ids``          -- Walk sysfs tree to find idVendor/idProduct.
    ``lookup_usb_name``       -- Resolve USB IDs to a name via ``lsusb``.
"""

from netcheck.hardware.modem import (
    build_modem_info,
    get_all_modem_data,
    get_modem_interfaces,
    parse_modem_indices,
    parse_modem_record,
)
from netcheck.hardware.pci import get_pci_device_name, lookup_pci_name, read_pci_ids
from netcheck.hardware.usb import (
    USB_TETHER_DRIVERS,
    find_usb_ids,
    get_usb_device_name,
    get_usb_driver,
    is_usb_interface,
    is_usb_tether,
    lookup_usb_name,
)

__all__ = [
    # Modem
    "get_all_modem_data",
    "get_modem_interfaces",
    "build_modem_info",
    "parse_modem_indices",
    "parse_modem_record",
    # PCI
    "get_pci_device_name",
    "read_pci_ids",
    "lookup_pci_name",
    # USB
    "USB_TETHER_DRIVERS",
    "is_usb_interface",
    "is_usb_tether",
    "get_usb_device_name",
    "get_usb_driver",
    "find_usb_ids",
    "lookup_usb_name",
]
