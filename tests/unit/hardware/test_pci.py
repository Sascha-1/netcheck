"""Unit tests for netcheck.hardware.pci.

All sysfs interactions use ``FakeSysfsReader``; all subprocess calls use
``FakeCommandRunner``.  No ``unittest.mock``, no ``patch``, no ``MagicMock``.

Test groups
-----------
``TestReadPciIds``
    Tests the sysfs ID reader via FakeSysfsReader.

``TestLookupPciName``
    Tests the lspci name extractor via FakeCommandRunner.

``TestGetPciDeviceName``
    End-to-end tests combining both steps.
"""

from pathlib import Path

from netcheck.hardware.pci import get_pci_device_name, lookup_pci_name, read_pci_ids
from tests.fakes import FakeCommandRunner, FakeSysfsReader

_FIXTURES: Path = Path(__file__).parent.parent.parent / "fixtures" / "lspci"

# Sysfs path used across tests (any valid PCI path -- content is fake anyway)
_PCI_PATH = "/sys/devices/pci0000:00/0000:00:1f.6"


def _read(filename: str) -> str:
    return (_FIXTURES / filename).read_text().strip()


class TestReadPciIds:
    """Tests for read_pci_ids via FakeSysfsReader."""

    def test_valid_pci_ids_returned(self) -> None:
        """Valid vendor and device files must return a (vendor, device) tuple."""
        reader = FakeSysfsReader(
            device_paths={"eth0": _PCI_PATH},
            files={
                (_PCI_PATH, "vendor"): "8086",
                (_PCI_PATH, "device"): "15bc",
            },
        )
        assert read_pci_ids("eth0", reader) == ("8086", "15bc")

    def test_0x_prefix_stripped(self) -> None:
        """The '0x' prefix from sysfs hex values must be removed."""
        reader = FakeSysfsReader(
            device_paths={"eth0": _PCI_PATH},
            files={
                (_PCI_PATH, "vendor"): "0x8086",
                (_PCI_PATH, "device"): "0x15bc",
            },
        )
        assert read_pci_ids("eth0", reader) == ("8086", "15bc")

    def test_no_device_path_returns_none(self) -> None:
        """An interface with no sysfs device path must return None."""
        reader = FakeSysfsReader()  # no device_paths configured
        assert read_pci_ids("eth0", reader) is None

    def test_missing_vendor_file_returns_none(self) -> None:
        """If the vendor file is absent, return None."""
        reader = FakeSysfsReader(
            device_paths={"eth0": _PCI_PATH},
            files={(_PCI_PATH, "device"): "15bc"},  # no vendor
        )
        assert read_pci_ids("eth0", reader) is None

    def test_missing_device_file_returns_none(self) -> None:
        """If the device file is absent, return None."""
        reader = FakeSysfsReader(
            device_paths={"eth0": _PCI_PATH},
            files={(_PCI_PATH, "vendor"): "8086"},  # no device
        )
        assert read_pci_ids("eth0", reader) is None


class TestLookupPciName:
    """Tests for lookup_pci_name using FakeCommandRunner."""

    def test_name_extracted_from_lspci_output(self) -> None:
        """The device name after 'controller:' must be returned."""
        runner = FakeCommandRunner(
            {("lspci", "-d", "8086:15bc"): _read("eth_controller.txt")}
        )
        result = lookup_pci_name("8086", "15bc", runner)
        assert result == "Intel Corporation Ethernet Controller I219-V (rev 03)"

    def test_lspci_failure_returns_none(self) -> None:
        """If lspci returns None, return None."""
        runner = FakeCommandRunner({("lspci", "-d", "8086:15bc"): None})
        assert lookup_pci_name("8086", "15bc", runner) is None

    def test_only_first_line_used(self) -> None:
        """If lspci returns multiple lines, only the first is used."""
        multi = (
            "00:1f.6 Ethernet controller: Intel Corporation I219-V\n"
            "01:00.0 Ethernet controller: Some Other Device\n"
        )
        runner = FakeCommandRunner({("lspci", "-d", "8086:15bc"): multi})
        result = lookup_pci_name("8086", "15bc", runner)
        assert result is not None
        assert "Some Other Device" not in result

    def test_output_without_colon_returns_none(self) -> None:
        """Unparseable lspci output must return None."""
        runner = FakeCommandRunner({("lspci", "-d", "8086:15bc"): "no colon here"})
        assert lookup_pci_name("8086", "15bc", runner) is None

    def test_whitespace_only_name_returns_none(self) -> None:
        """Pattern matches but captured name strips to empty -> None.

        The regex ``[^:]+:\\s+(.+)$`` allows whitespace-only text after the
        class label colon: ``\\s+`` consumes the first space, ``(.+)`` captures
        any remaining whitespace, and ``.strip()`` produces an empty string.
        ``"" or None`` then evaluates to ``None``.

        This covers the ``or None`` branch in ``lookup_pci_name`` -- the
        defensive fallback for malformed lspci output where the device name
        field is blank.
        """
        # One space before end of string: \s+ eats it, (.+) captures nothing
        # unless there is a second space.  Two trailing spaces: \s+ takes one,
        # (.+) captures the other, .strip() -> "", or None -> None.
        runner = FakeCommandRunner(
            {("lspci", "-d", "8086:15bc"): "00:1f.6 Ethernet controller:  "}
        )
        assert lookup_pci_name("8086", "15bc", runner) is None


class TestGetPciDeviceName:
    """End-to-end tests for get_pci_device_name."""

    def test_full_pipeline_returns_name(self) -> None:
        """Valid sysfs + lspci must return the device name."""
        reader = FakeSysfsReader(
            device_paths={"eth0": _PCI_PATH},
            files={
                (_PCI_PATH, "vendor"): "8086",
                (_PCI_PATH, "device"): "15bc",
            },
        )
        runner = FakeCommandRunner(
            {("lspci", "-d", "8086:15bc"): _read("eth_controller.txt")}
        )
        result = get_pci_device_name("eth0", reader, runner)
        assert result == "Intel Corporation Ethernet Controller I219-V (rev 03)"

    def test_no_pci_device_returns_none(self) -> None:
        """An interface without a sysfs device path must return None."""
        reader = FakeSysfsReader()
        runner = FakeCommandRunner({})
        assert get_pci_device_name("eth0", reader, runner) is None

    def test_lspci_failure_returns_none(self) -> None:
        """If lspci fails despite valid sysfs IDs, return None."""
        reader = FakeSysfsReader(
            device_paths={"eth0": _PCI_PATH},
            files={
                (_PCI_PATH, "vendor"): "8086",
                (_PCI_PATH, "device"): "15bc",
            },
        )
        runner = FakeCommandRunner({("lspci", "-d", "8086:15bc"): None})
        assert get_pci_device_name("eth0", reader, runner) is None

    def test_no_lspci_calls_when_no_sysfs_device(self) -> None:
        """lspci must not be called if read_pci_ids returns None."""
        reader = FakeSysfsReader()
        runner = FakeCommandRunner({})
        get_pci_device_name("eth0", reader, runner)
        assert not runner.calls
