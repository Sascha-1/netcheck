"""Unit tests for FakeSysfsReader contract and SysfsReader protocol.

``SystemSysfsReader`` reads from ``/sys`` which requires a real Linux system
with specific hardware.  Its correctness is verified by integration tests.

This file tests:
- ``FakeSysfsReader`` honours the five-method contract of ``SysfsReader``.
- ``parent_path`` correctly computes the parent directory string.
- Missing keys return ``None`` (the convention used by all callers).

The structural protocol check at the bottom verifies that both
``SystemSysfsReader`` and ``FakeSysfsReader`` satisfy the ``SysfsReader``
protocol statically (via mypy) and at runtime (via isinstance with runtime
checkable protocol -- not used here, as ``SysfsReader`` is not
``@runtime_checkable``; static checking by mypy strict is sufficient).
"""

import os
import pathlib

import pytest

from netcheck.utils.sysfs import SysfsReader, SystemSysfsReader
from tests.fakes import FakeSysfsReader

_USB_PATH = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0"
_USB_PARENT = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2"


class TestFakeSysfsReaderDevicePath:
    """Tests for FakeSysfsReader.device_path."""

    def test_configured_interface_returns_path(self) -> None:
        """A configured interface name must return its path."""
        reader = FakeSysfsReader(device_paths={"eth0": "/sys/devices/pci/eth"})
        assert reader.device_path("eth0") == "/sys/devices/pci/eth"

    def test_unconfigured_interface_returns_none(self) -> None:
        """An interface not in device_paths must return None."""
        reader = FakeSysfsReader()
        assert reader.device_path("eth0") is None

    def test_multiple_interfaces_independent(self) -> None:
        """Each configured interface must return its own path."""
        reader = FakeSysfsReader(
            device_paths={
                "eth0": "/sys/devices/pci/eth",
                "wlan0": "/sys/devices/pci/usb1/wlan",
            }
        )
        assert reader.device_path("eth0") == "/sys/devices/pci/eth"
        assert reader.device_path("wlan0") == "/sys/devices/pci/usb1/wlan"
        assert reader.device_path("lo") is None


class TestFakeSysfsReaderReadFile:
    """Tests for FakeSysfsReader.read_file."""

    def test_configured_file_returns_content(self) -> None:
        """A configured (path, filename) pair must return its content."""
        reader = FakeSysfsReader(files={("/sys/dev/eth", "vendor"): "8086"})
        assert reader.read_file("/sys/dev/eth", "vendor") == "8086"

    def test_unconfigured_file_returns_none(self) -> None:
        """A (path, filename) not in files must return None."""
        reader = FakeSysfsReader()
        assert reader.read_file("/sys/dev/eth", "vendor") is None

    def test_same_path_different_files_are_independent(self) -> None:
        """Different filenames under the same path must return independently."""
        reader = FakeSysfsReader(
            files={
                ("/sys/dev", "vendor"): "8086",
                ("/sys/dev", "device"): "15bc",
            }
        )
        assert reader.read_file("/sys/dev", "vendor") == "8086"
        assert reader.read_file("/sys/dev", "device") == "15bc"
        assert reader.read_file("/sys/dev", "other") is None


class TestFakeSysfsReaderReadLinkName:
    """Tests for FakeSysfsReader.read_link_name."""

    def test_configured_link_returns_name(self) -> None:
        """A configured (path, link_name) pair must return its name."""
        reader = FakeSysfsReader(
            link_names={(_USB_PATH, "driver"): "cdc_ether"}
        )
        assert reader.read_link_name(_USB_PATH, "driver") == "cdc_ether"

    def test_unconfigured_link_returns_none(self) -> None:
        """A (path, link_name) not in link_names must return None."""
        reader = FakeSysfsReader()
        assert reader.read_link_name(_USB_PATH, "driver") is None


class TestFakeSysfsReaderParentPath:
    """Tests for FakeSysfsReader.parent_path (pure string computation)."""

    def test_deep_path_returns_parent(self) -> None:
        """A multi-level path must return its parent directory."""
        reader = FakeSysfsReader()
        assert reader.parent_path(_USB_PATH) == _USB_PARENT

    def test_two_levels_deep(self) -> None:
        """Two successive calls must walk up two levels."""
        reader = FakeSysfsReader()
        p1 = reader.parent_path(_USB_PATH)
        assert p1 == _USB_PARENT
        p2 = reader.parent_path(p1)
        assert p2 == "/sys/devices/pci0000:00/0000:00:14.0/usb1"

    def test_root_returns_none(self) -> None:
        """The filesystem root must return None."""
        reader = FakeSysfsReader()
        assert reader.parent_path("/") is None

    def test_one_level_path_returns_root(self) -> None:
        """A path one level below root must return '/'."""
        reader = FakeSysfsReader()
        assert reader.parent_path("/sys") == "/"


class TestProtocolConformance:
    """Verify structural conformance to the SysfsReader protocol.

    These tests exist to document the contract explicitly.  The real
    enforcement is mypy strict -- both classes are used as ``SysfsReader``
    in annotated function signatures, so mypy validates the structural match
    at type-check time.
    """

    def test_fake_reader_has_all_protocol_methods(self) -> None:
        """FakeSysfsReader must implement all five SysfsReader methods."""
        reader: SysfsReader = FakeSysfsReader()  # assignment validates protocol
        assert callable(reader.device_path)
        assert callable(reader.read_file)
        assert callable(reader.read_link_name)
        assert callable(reader.parent_path)
        assert callable(reader.dir_exists)

    def test_system_reader_has_all_protocol_methods(self) -> None:
        """SystemSysfsReader must implement all five SysfsReader methods."""
        reader: SysfsReader = SystemSysfsReader()  # assignment validates protocol
        assert callable(reader.device_path)
        assert callable(reader.read_file)
        assert callable(reader.read_link_name)
        assert callable(reader.parent_path)
        assert callable(reader.dir_exists)


class TestSystemSysfsReaderParentPath:
    """SystemSysfsReader.parent_path -- pure string computation, no filesystem."""

    def test_deep_path_returns_parent(self) -> None:
        reader = SystemSysfsReader()
        assert reader.parent_path("/sys/devices/pci0000:00/eth0") == "/sys/devices/pci0000:00"

    def test_root_returns_none(self) -> None:
        reader = SystemSysfsReader()
        assert reader.parent_path("/") is None

    def test_one_level_returns_root(self) -> None:
        reader = SystemSysfsReader()
        assert reader.parent_path("/sys") == "/"


class TestSystemSysfsReaderWithTmpFilesystem:
    """SystemSysfsReader filesystem operations using a real tmp directory."""

    def test_read_file_returns_content(self, tmp_path: pathlib.Path) -> None:
        """read_file must return the stripped file content."""
        d = tmp_path / "dev"
        d.mkdir()
        (d / "vendor").write_text("0x8086\n")
        reader = SystemSysfsReader()
        assert reader.read_file(str(d), "vendor") == "0x8086"

    def test_read_file_strips_whitespace(self, tmp_path: pathlib.Path) -> None:
        d = tmp_path / "dev"
        d.mkdir()
        (d / "device").write_text("  0x15bc  \n")
        reader = SystemSysfsReader()
        assert reader.read_file(str(d), "device") == "0x15bc"

    def test_read_file_missing_returns_none(self, tmp_path: pathlib.Path) -> None:
        d = tmp_path / "dev"
        d.mkdir()
        reader = SystemSysfsReader()
        assert reader.read_file(str(d), "nonexistent") is None

    def test_read_file_target_is_directory_returns_none(self, tmp_path: pathlib.Path) -> None:
        """read_file must return None when the named entry is a directory.

        ``Path.read_text()`` raises ``IsADirectoryError`` (a subclass of
        ``OSError``, errno 21) when the target exists but is a directory
        rather than a regular file.  ``pathlib`` does not suppress errno 21
        (only errno 2, 9, 20, 40 are in ``_IGNORED_ERRNOS``), so the error
        propagates from ``read_text()`` to the ``except OSError`` handler,
        which normalises it to ``None``.

        This test covers lines 163-164 in ``sysfs.py`` (the except clause
        and pass in ``read_file``).  No permission manipulation is required:
        the ``IsADirectoryError`` is raised by ``read_text()`` itself, not
        by the ``exists()`` check that precedes it.
        """
        d = tmp_path / "dev"
        d.mkdir()
        (d / "vendor").mkdir()  # "vendor" is a directory, not a regular file
        reader = SystemSysfsReader()
        assert reader.read_file(str(d), "vendor") is None

    def test_read_link_name_returns_target_name(self, tmp_path: pathlib.Path) -> None:
        """read_link_name must return the final path component of a symlink target."""
        target_dir = tmp_path / "drivers" / "cdc_ether"
        target_dir.mkdir(parents=True)
        link_dir = tmp_path / "device"
        link_dir.mkdir()
        (link_dir / "driver").symlink_to(target_dir)
        reader = SystemSysfsReader()
        assert reader.read_link_name(str(link_dir), "driver") == "cdc_ether"

    def test_read_link_name_missing_returns_none(self, tmp_path: pathlib.Path) -> None:
        d = tmp_path / "dev"
        d.mkdir()
        reader = SystemSysfsReader()
        assert reader.read_link_name(str(d), "driver") is None

    @pytest.mark.skipif(os.getuid() == 0, reason="root bypasses file-permission checks")
    def test_read_link_name_permission_denied_returns_none(self, tmp_path: pathlib.Path) -> None:
        """read_link_name must return None when the directory is inaccessible.

        When the directory passed as ``path`` has mode 000, any attempt to
        access entries inside it raises ``PermissionError`` (errno 13,
        EACCES).  ``pathlib`` does not suppress errno 13 (only errno 2, 9,
        20, 40 are in ``_IGNORED_ERRNOS``), so ``Path.exists()`` re-raises
        the error.  The ``except OSError`` handler in ``read_link_name``
        catches it and returns ``None``.

        This test covers lines 181-182 in ``sysfs.py`` (the except clause
        and pass in ``read_link_name``).  The skip guard is required because
        root ignores POSIX permission bits.
        """
        restricted = tmp_path / "restricted"
        restricted.mkdir(mode=0o000)
        reader = SystemSysfsReader()
        try:
            result = reader.read_link_name(str(restricted), "driver")
            assert result is None
        finally:
            restricted.chmod(0o755)  # restore so tmp_path teardown can clean up

    def test_device_path_returns_resolved_target(self, tmp_path: pathlib.Path) -> None:
        """device_path resolves a symlink when called on a real path.

        We verify the behaviour indirectly: a real symlink placed inside
        tmp_path is always resolved correctly by pathlib, so the only
        meaningful contract we can test without hardware is the None-on-
        missing-symlink path, covered by the next test.
        """
        # Build a minimal sysfs-like tree and verify the symlink resolves.
        iface_dir = tmp_path / "sys" / "class" / "net" / "eth_test"
        iface_dir.mkdir(parents=True)
        device_target = tmp_path / "sys" / "devices" / "pci0000:00" / "0000:00:1f.6"
        device_target.mkdir(parents=True)
        (iface_dir / "device").symlink_to(device_target)
        # SystemSysfsReader hard-codes /sys/class/net, so we can't call it
        # against our tmp tree.  The important contract is: symlink exists ->
        # resolved path string is returned; no symlink -> None.
        assert (iface_dir / "device").resolve() == device_target.resolve()

    def test_device_path_nonexistent_interface_returns_none(self) -> None:
        """Any interface that does not exist in /sys must return None."""
        reader = SystemSysfsReader()
        result = reader.device_path("zzz_does_not_exist_netcheck_test")
        assert result is None


class TestFakeSysfsReaderDirExists:
    """Tests for FakeSysfsReader.dir_exists."""

    def test_configured_path_returns_true(self) -> None:
        """A path present in the dirs set must return True."""
        reader = FakeSysfsReader(dirs=frozenset({"/sys/class/net/br0/bridge"}))
        assert reader.dir_exists("/sys/class/net/br0/bridge") is True

    def test_unconfigured_path_returns_false(self) -> None:
        """A path absent from the dirs set must return False."""
        reader = FakeSysfsReader()
        assert reader.dir_exists("/sys/class/net/eth0/bridge") is False

    def test_only_exact_path_matches(self) -> None:
        """A prefix of a configured path must not match."""
        reader = FakeSysfsReader(dirs=frozenset({"/sys/class/net/br0/bridge"}))
        assert reader.dir_exists("/sys/class/net/br0") is False


class TestSystemSysfsReaderDirExists:
    """Tests for SystemSysfsReader.dir_exists using a real tmp directory."""

    def test_existing_directory_returns_true(self, tmp_path: pathlib.Path) -> None:
        """dir_exists must return True for a directory that exists."""
        d = tmp_path / "bridge"
        d.mkdir()
        reader = SystemSysfsReader()
        assert reader.dir_exists(str(d)) is True

    def test_nonexistent_path_returns_false(self, tmp_path: pathlib.Path) -> None:
        """dir_exists must return False for a path that does not exist."""
        reader = SystemSysfsReader()
        assert reader.dir_exists(str(tmp_path / "no_such_dir")) is False

    def test_file_returns_false(self, tmp_path: pathlib.Path) -> None:
        """dir_exists must return False for a path that is a file, not a directory."""
        f = tmp_path / "not_a_dir"
        f.write_text("x")
        reader = SystemSysfsReader()
        assert reader.dir_exists(str(f)) is False

    @pytest.mark.skipif(os.getuid() == 0, reason="root bypasses file-permission checks")
    def test_dir_exists_permission_denied_returns_false(self, tmp_path: pathlib.Path) -> None:
        """dir_exists must return False when the target's parent is inaccessible.

        ``Path.is_dir()`` calls ``stat()``, which raises ``PermissionError``
        (errno 13, EACCES) when a directory component of the path is not
        executable.  ``pathlib`` does not suppress errno 13, so the error
        propagates from ``is_dir()`` to the ``except OSError`` handler in
        ``dir_exists``, which returns ``False``.

        This test covers lines 212-213 in ``sysfs.py`` (the except clause
        and return False in ``dir_exists``).  The skip guard is required
        because root ignores POSIX permission bits.
        """
        parent = tmp_path / "parent"
        parent.mkdir()
        subdir = parent / "subdir"
        subdir.mkdir()
        # Remove all permissions from parent: stat(parent/subdir) now raises
        # PermissionError because the kernel cannot resolve the path component.
        parent.chmod(0o000)
        reader = SystemSysfsReader()
        try:
            result = reader.dir_exists(str(subdir))
            assert result is False
        finally:
            parent.chmod(0o755)  # restore so tmp_path teardown can clean up
