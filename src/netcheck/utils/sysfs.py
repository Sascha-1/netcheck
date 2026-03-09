"""Sysfs filesystem reader for netcheck.

Provides:
- ``SysfsReader``: Protocol for injectable sysfs access.  Every hardware
  module that reads ``/sys`` receives a ``SysfsReader`` instance rather than
  calling ``pathlib.Path`` directly.
- ``SystemSysfsReader``: Production implementation backed by ``pathlib``.

Rationale
---------
Patching ``pathlib.Path`` at the test boundary (Option C) is the same
architectural shortcut as patching ``requests.get`` for HTTP.  It keeps the
production code implicitly dependent on the filesystem with no explicit seam.

A ``SysfsReader`` protocol makes the dependency visible in every function
signature, enables test doubles with correct types, eliminates
``# type: ignore`` comments, and removes ``MagicMock`` / ``patch`` from
hardware unit tests entirely.

Operations
----------
Four primitive operations cover all sysfs access patterns used in the hardware
layer:

``device_path``
    Resolve the ``/sys/class/net/<iface>/device`` symlink and return the
    absolute target path as a string.  Returns ``None`` if the symlink does
    not exist or cannot be resolved.

``read_file``
    Read a text file at ``<path>/<filename>`` and return its stripped content.
    Returns ``None`` if the file does not exist or an OS error occurs.

``read_link_name``
    Return the ``name`` component of the resolved target of a symlink at
    ``<path>/<link_name>`` (e.g. reading ``driver`` -> ``"cdc_ether"``).
    Returns ``None`` if the symlink does not exist or an OS error occurs.

``parent_path``
    Return the parent directory of ``path`` as a string, or ``None`` if
    ``path`` is the filesystem root.  Used by ``find_usb_ids`` to walk up the
    sysfs tree from USB interface to USB device node.

``dir_exists``
    Return ``True`` if ``path`` exists and is a directory, ``False``
    otherwise.  Used by bridge detection to test for the presence of
    ``/sys/class/net/<iface>/bridge/``.
"""

from pathlib import Path
from typing import Protocol


class SysfsReader(Protocol):
    """Protocol for reading Linux sysfs pseudo-filesystem entries.

    Any object whose methods match these signatures satisfies the protocol.
    Production code uses ``SystemSysfsReader``; hardware unit tests substitute
    ``FakeSysfsReader`` (defined in ``tests/fakes.py``).
    """

    def device_path(self, iface: str) -> str | None:
        """Return the resolved sysfs device path for ``iface``, or ``None``.

        Follows the symlink at ``/sys/class/net/<iface>/device`` to its real
        target.  Returns ``None`` if the symlink is absent or cannot be
        resolved.

        Args:
            iface: Network interface name (e.g. ``"eth0"``).

        Returns:
            Absolute path string (e.g.
            ``"/sys/devices/pci0000:00/0000:00:1f.6"``), or ``None``.
        """

    def read_file(self, path: str, filename: str) -> str | None:
        """Return the stripped content of ``<path>/<filename>``, or ``None``.

        Args:
            path: Absolute directory path.
            filename: File name within that directory.

        Returns:
            Stripped file content string, or ``None`` if the file does not
            exist or an OS error occurs.
        """

    def read_link_name(self, path: str, link_name: str) -> str | None:
        """Return the ``name`` of the resolved target of a symlink, or ``None``.

        Resolves ``<path>/<link_name>`` as a symlink and returns the final
        path component of its target.  Useful for reading kernel driver names
        from ``/sys/.../driver``.

        Args:
            path: Absolute directory path containing the symlink.
            link_name: Name of the symlink within that directory.

        Returns:
            The ``name`` component of the resolved symlink target
            (e.g. ``"cdc_ether"``), or ``None`` if the symlink does not exist
            or an OS error occurs.
        """

    def parent_path(self, path: str) -> str | None:
        """Return the parent directory of ``path``, or ``None`` at root.

        Used by ``find_usb_ids`` in ``netcheck.hardware.usb`` to walk upward
        through the sysfs device tree from USB interface to USB device node.

        Args:
            path: Absolute path string.

        Returns:
            Parent path string, or ``None`` if ``path`` is already the
            filesystem root (``"/"``).
        """

    def dir_exists(self, path: str) -> bool:
        """Return True if ``path`` exists and is a directory, False otherwise."""


class SystemSysfsReader:
    """Production ``SysfsReader`` backed by ``pathlib``.

    All four operations read directly from ``/sys``.  OS errors are caught and
    normalised to ``None`` so that callers need not handle filesystem
    exceptions.
    """

    def device_path(self, iface: str) -> str | None:
        """Resolve ``/sys/class/net/<iface>/device`` and return its target path.

        Args:
            iface: Network interface name.

        Returns:
            Resolved absolute path string, or ``None`` on failure.
        """
        link = Path(f"/sys/class/net/{iface}/device")
        try:
            if link.exists() and link.is_symlink():
                return str(link.resolve())
        except OSError:
            pass
        return None

    def read_file(self, path: str, filename: str) -> str | None:
        """Read and return the stripped content of ``<path>/<filename>``.

        Args:
            path: Absolute directory path.
            filename: File name within that directory.

        Returns:
            Stripped content string, or ``None`` on failure.
        """
        try:
            target = Path(path) / filename
            if target.exists():
                return target.read_text().strip()
        except OSError:
            pass
        return None

    def read_link_name(self, path: str, link_name: str) -> str | None:
        """Resolve ``<path>/<link_name>`` and return the final name component.

        Args:
            path: Absolute directory path.
            link_name: Symlink name within that directory.

        Returns:
            Name component of the resolved target, or ``None`` on failure.
        """
        try:
            link = Path(path) / link_name
            if link.exists() and link.is_symlink():
                return link.resolve().name
        except OSError:
            pass
        return None

    def parent_path(self, path: str) -> str | None:
        """Return the parent directory of ``path``, or ``None`` at root.

        Args:
            path: Absolute path string.

        Returns:
            Parent path string, or ``None`` if ``path`` is the root.
        """
        p = Path(path)
        parent = p.parent
        parent_str = str(parent)
        if parent_str == path:
            return None
        return parent_str

    def dir_exists(self, path: str) -> bool:
        """Return True if ``path`` exists and is a directory, False otherwise.

        Args:
            path: Absolute path string.

        Returns:
            ``True`` if the path is an existing directory, ``False`` otherwise.
        """
        try:
            return Path(path).is_dir()
        except OSError:
            return False
