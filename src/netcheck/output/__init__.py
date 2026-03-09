"""Output layer for netcheck.

Renderers for ``list[InterfaceInfo]``:

``format_table``
    Writes a color-coded table to a file-like object (default: stdout).

``format_json``
    Serialises the interface list to a JSON string with metadata.

Both functions are pure in the sense that they do not modify the input list
and have no side-effects beyond writing to the given file handle.

Format-agnostic display helpers (usable by any renderer):

``clean_device``  -- strip vendor jargon from raw lspci/lsusb hardware names.
``clean_isp``     -- strip AS numbers and corporate suffixes from ISP strings.
``truncate``      -- truncate a string to a maximum column width with ``...``.
"""

from netcheck.output.export import format_json
from netcheck.output.formatters import clean_device, clean_isp, truncate
from netcheck.output.table import format_table

__all__ = [
    "clean_device",
    "clean_isp",
    "format_json",
    "format_table",
    "truncate",
]
