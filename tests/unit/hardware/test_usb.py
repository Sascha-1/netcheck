"""Unit tests for netcheck.hardware.usb.

All sysfs interactions use ``FakeSysfsReader``; all subprocess calls use
``FakeCommandRunner``.  No ``unittest.mock``, no ``patch``, no ``MagicMock``,
no ``_FakePath``, no ``# type: ignore``.

Test groups
-----------
``TestIsUsbInterface``
    Verifies USB detection via sysfs path content.

``TestGetUsbDriver``
    Verifies driver name extraction via sysfs link.

``TestIsUsbTether``
    Verifies tether classification against the known driver set.

``TestFindUsbIds``
    Verifies the sysfs tree walk that finds idVendor/idProduct.

``TestLookupUsbName``
    Verifies lsusb output parsing.

``TestGetUsbDeviceName``
    End-to-end tests of the public function.

``TestUsbTetherDrivers``
    Contract tests on the USB_TETHER_DRIVERS constant.
"""

from pathlib import Path

import pytest

from netcheck.hardware.usb import (
    USB_TETHER_DRIVERS,
    find_usb_ids,
    get_usb_device_name,
    get_usb_driver,
    is_usb_interface,
    is_usb_tether,
    lookup_usb_name,
)
from tests.fakes import FakeCommandRunner, FakeSysfsReader

_FIXTURES: Path = Path(__file__).parent.parent.parent / "fixtures" / "lsusb"

# Sysfs paths used across tests
_USB_IFACE_PATH = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0"
_USB_DEVICE_PATH = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2"
_PCI_PATH = "/sys/devices/pci0000:00/0000:00:1f.6"
_IFACE = "enx8615d34feca4"


def _read(filename: str) -> str:
    return (_FIXTURES / filename).read_text().strip()


class TestIsUsbInterface:
    """Tests for is_usb_interface."""

    def test_usb_path_returns_true(self) -> None:
        """An interface whose sysfs path contains '/usb' is a USB device."""
        reader = FakeSysfsReader(device_paths={_IFACE: _USB_IFACE_PATH})
        assert is_usb_interface(_IFACE, reader) is True

    def test_pci_path_returns_false(self) -> None:
        """An interface whose sysfs path does not contain '/usb' is not USB."""
        reader = FakeSysfsReader(device_paths={"eth0": _PCI_PATH})
        assert is_usb_interface("eth0", reader) is False

    def test_no_device_path_returns_false(self) -> None:
        """An interface with no sysfs device path is not USB."""
        reader = FakeSysfsReader()
        assert is_usb_interface("eth0", reader) is False


class TestGetUsbDriver:
    """Tests for get_usb_driver."""

    def test_driver_name_returned(self) -> None:
        """The kernel driver name must be extracted from the sysfs link."""
        reader = FakeSysfsReader(
            device_paths={_IFACE: _USB_IFACE_PATH},
            link_names={(_USB_IFACE_PATH, "driver"): "cdc_ether"},
        )
        assert get_usb_driver(_IFACE, reader) == "cdc_ether"

    def test_pci_interface_returns_none(self) -> None:
        """A non-USB interface must return None."""
        reader = FakeSysfsReader(device_paths={"eth0": _PCI_PATH})
        assert get_usb_driver("eth0", reader) is None

    def test_no_device_path_returns_none(self) -> None:
        """An interface with no device path must return None."""
        reader = FakeSysfsReader()
        assert get_usb_driver("eth0", reader) is None

    def test_no_driver_link_returns_none(self) -> None:
        """A USB interface with no driver symlink must return None."""
        reader = FakeSysfsReader(
            device_paths={_IFACE: _USB_IFACE_PATH},
            # no link_names configured -- driver symlink absent
        )
        assert get_usb_driver(_IFACE, reader) is None


class TestIsUsbTether:
    """Tests for is_usb_tether."""

    @pytest.mark.parametrize("driver", sorted(USB_TETHER_DRIVERS))
    def test_tether_drivers_recognised(self, driver: str) -> None:
        """Every driver in USB_TETHER_DRIVERS must be classified as tether."""
        reader = FakeSysfsReader(
            device_paths={_IFACE: _USB_IFACE_PATH},
            link_names={(_USB_IFACE_PATH, "driver"): driver},
        )
        assert is_usb_tether(_IFACE, reader) is True

    def test_unknown_driver_returns_false(self) -> None:
        """An unrecognised driver must not be classified as tether."""
        reader = FakeSysfsReader(
            device_paths={_IFACE: _USB_IFACE_PATH},
            link_names={(_USB_IFACE_PATH, "driver"): "qmi_wwan"},
        )
        assert is_usb_tether(_IFACE, reader) is False

    def test_no_driver_returns_false(self) -> None:
        """An interface with no driver must not be classified as tether."""
        reader = FakeSysfsReader()
        assert is_usb_tether("eth0", reader) is False


class TestFindUsbIds:
    """Tests for find_usb_ids."""

    def test_ids_found_at_start_path(self) -> None:
        """IDs directly on the start path must be returned immediately."""
        reader = FakeSysfsReader(
            files={
                (_USB_IFACE_PATH, "idVendor"): "18d1",
                (_USB_IFACE_PATH, "idProduct"): "4eeb",
            }
        )
        assert find_usb_ids(_USB_IFACE_PATH, reader) == ("18d1", "4eeb")

    def test_ids_found_at_parent_path(self) -> None:
        """IDs one level up from the interface path must be found via parent walk."""
        reader = FakeSysfsReader(
            files={
                (_USB_DEVICE_PATH, "idVendor"): "18d1",
                (_USB_DEVICE_PATH, "idProduct"): "4eeb",
            }
        )
        # Start at _USB_IFACE_PATH -- no IDs there, walk up to _USB_DEVICE_PATH
        assert find_usb_ids(_USB_IFACE_PATH, reader) == ("18d1", "4eeb")

    def test_returns_none_when_no_ids_found(self) -> None:
        """A path tree with no ID files must return None."""
        reader = FakeSysfsReader()  # no files configured
        assert find_usb_ids(_USB_IFACE_PATH, reader) is None

    def test_partial_ids_not_returned(self) -> None:
        """If only one of idVendor/idProduct exists, keep walking."""
        reader = FakeSysfsReader(
            files={
                # Only vendor at iface level -- must not return a partial result
                (_USB_IFACE_PATH, "idVendor"): "18d1",
                # IDs at parent level
                (_USB_DEVICE_PATH, "idVendor"): "18d1",
                (_USB_DEVICE_PATH, "idProduct"): "4eeb",
            }
        )
        assert find_usb_ids(_USB_IFACE_PATH, reader) == ("18d1", "4eeb")


class TestLookupUsbName:
    """Tests for lookup_usb_name."""

    def test_pixel_name_extracted(self) -> None:
        """Google Pixel USB device name must be extracted from lsusb output."""
        runner = FakeCommandRunner(
            {("lsusb", "-d", "18d1:4eeb"): _read("pixel_tether.txt")}
        )
        assert lookup_usb_name("18d1", "4eeb", runner) == "Google LLC Pixel 9a"

    def test_quectel_name_extracted(self) -> None:
        """Quectel modem name must be extracted from lsusb output."""
        runner = FakeCommandRunner(
            {("lsusb", "-d", "2c7c:0311"): _read("quectel_modem.txt")}
        )
        result = lookup_usb_name("2c7c", "0311", runner)
        assert result == "Quectel Wireless Solutions Co., Ltd. EM05-G"

    def test_lsusb_failure_returns_none(self) -> None:
        """If lsusb returns None, return None."""
        runner = FakeCommandRunner({("lsusb", "-d", "18d1:4eeb"): None})
        assert lookup_usb_name("18d1", "4eeb", runner) is None

    def test_unparseable_output_returns_none(self) -> None:
        """lsusb output without the expected format must return None."""
        runner = FakeCommandRunner({("lsusb", "-d", "18d1:4eeb"): "garbled output"})
        assert lookup_usb_name("18d1", "4eeb", runner) is None


class TestGetUsbDeviceName:
    """End-to-end tests for get_usb_device_name."""

    def test_pixel_name_returned(self) -> None:
        """Full pipeline must return the Pixel device name."""
        reader = FakeSysfsReader(
            device_paths={_IFACE: _USB_IFACE_PATH},
            files={
                (_USB_IFACE_PATH, "idVendor"): "18d1",
                (_USB_IFACE_PATH, "idProduct"): "4eeb",
            },
        )
        runner = FakeCommandRunner(
            {("lsusb", "-d", "18d1:4eeb"): _read("pixel_tether.txt")}
        )
        assert get_usb_device_name(_IFACE, reader, runner) == "Google LLC Pixel 9a"

    def test_non_usb_returns_none_without_lsusb_call(self) -> None:
        """A non-USB interface must return None without calling lsusb."""
        reader = FakeSysfsReader(device_paths={"eth0": _PCI_PATH})
        runner = FakeCommandRunner({})
        assert get_usb_device_name("eth0", reader, runner) is None
        assert not runner.calls

    def test_no_device_path_returns_none(self) -> None:
        """An interface with no sysfs path must return None."""
        reader = FakeSysfsReader()
        runner = FakeCommandRunner({})
        assert get_usb_device_name("eth0", reader, runner) is None

    def test_lsusb_failure_returns_none(self) -> None:
        """lsusb failure must return None."""
        reader = FakeSysfsReader(
            device_paths={_IFACE: _USB_IFACE_PATH},
            files={
                (_USB_IFACE_PATH, "idVendor"): "18d1",
                (_USB_IFACE_PATH, "idProduct"): "4eeb",
            },
        )
        runner = FakeCommandRunner({("lsusb", "-d", "18d1:4eeb"): None})
        assert get_usb_device_name(_IFACE, reader, runner) is None


class TestUsbTetherDrivers:
    """Contract tests for the USB_TETHER_DRIVERS constant."""

    def test_is_frozenset(self) -> None:
        """USB_TETHER_DRIVERS must be a frozenset."""
        assert isinstance(USB_TETHER_DRIVERS, frozenset)

    def test_contains_cdc_ether(self) -> None:
        """cdc_ether is the most common Android tether driver."""
        assert "cdc_ether" in USB_TETHER_DRIVERS

    def test_contains_ipheth(self) -> None:
        """ipheth is the iOS tether driver."""
        assert "ipheth" in USB_TETHER_DRIVERS

    def test_does_not_contain_qmi_wwan(self) -> None:
        """qmi_wwan is a cellular modem driver, not a tether driver."""
        assert "qmi_wwan" not in USB_TETHER_DRIVERS
