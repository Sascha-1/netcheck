"""Display-layer formatting helpers for netcheck.

Format-agnostic utilities for cleaning hardware names, ISP strings, and
truncating text for fixed-width columns.  Any renderer (table, HTML, CSV)
can import these without pulling in table-specific concerns.

``clean_device``  -- strip vendor jargon from raw ``lspci``/``lsusb`` names.
``clean_isp``     -- strip AS numbers and corporate suffixes from ipinfo.io
                     ``org`` field values.
``truncate``      -- truncate a string to a maximum column width with an
                     ellipsis marker.

The raw hardware names come from ``netcheck/hardware/pci.py`` and
``netcheck/hardware/usb.py``; ISP strings come from ``netcheck/network/egress.py``.
No domain-model objects are imported here and none are modified.
"""

import re
from typing import Final

# ---------------------------------------------------------------------------
# Corporate / technical terms stripped from device and ISP names (display only)
# ---------------------------------------------------------------------------
# Sorted longest-first so that multi-word phrases match before substrings.
_CLEANUP_TERMS: Final[tuple[str, ...]] = tuple(
    sorted(
        [
            # Full legal forms
            "Corporation",
            "Incorporated",
            "Communications",
            "Technologies",
            "Technology",
            "Solutions",
            "Systems",
            "Devices",
            "Limited",
            # Abbreviations with period
            "Corp.",
            "Inc.",
            "Ltd.",
            "Co.",
            # Abbreviations without period
            "Corp",
            "Inc",
            "Ltd",
            "LLC",
            "GmbH",
            "AG",
            # Device-specific technical terms
            "Controller",
            "Adapter",
            "Network",
            "Ethernet",
            "Wireless",
            "Gigabit",
            "Express",
        ],
        key=len,
        reverse=True,
    )
)


def clean_device(device: str | None) -> str:
    """Return a cleaned hardware name suitable for display.

    Strips PCI/USB address prefixes, corporate and technical jargon from
    device names such as ``"Intel Corporation Ethernet Controller I219-V"``.

    Args:
        device: Raw device name or ``None``.

    Returns:
        Cleaned name, or ``"--"`` when *device* is ``None`` or reduces to
        empty after cleaning.
    """
    if device is None:
        return "--"

    text = device

    # Remove PCI address prefix: "00:1f.6 " or "00.0 "
    text = re.sub(r"^\d+[:.]\S+\s+", "", text)
    # Remove USB bus prefix: "Bus 001 Device 003: "
    text = re.sub(r"^Bus\s+\d+\s+Device\s+\d+:\s+", "", text, flags=re.IGNORECASE)
    # Remove USB ID inline: "ID 18d1:4eeb "
    text = re.sub(r"\bID\s+[0-9a-f]{4}:[0-9a-f]{4}\s+", "", text, flags=re.IGNORECASE)
    # Remove parenthesised and bracketed content
    text = re.sub(r"\([^)]*\)", "", text)
    text = re.sub(r"\[[^\]]*\]", "", text)

    for term in _CLEANUP_TERMS:
        text = re.sub(
            r"\b" + re.escape(term) + r"(?=\s|[.,:\-]|$)",
            "",
            text,
            flags=re.IGNORECASE,
        )

    # Clean stray punctuation
    text = re.sub(r"\s*,\s*,", ",", text)
    text = re.sub(r",\s*$", "", text)
    text = re.sub(r",\s+", " ", text)
    text = re.sub(r":\s*", " ", text)

    # Remove duplicate consecutive words ("Quectel Quectel" -> "Quectel")
    text = re.sub(r"\b(\w+)\s+\1\b", r"\1", text, flags=re.IGNORECASE)

    text = " ".join(text.split()).strip(" ,.:-")
    return text if text else (device or "--")


def clean_isp(isp: str | None) -> str:
    """Return a cleaned ISP name suitable for display.

    Strips the AS number prefix (``AS12345``) and common corporate suffixes
    from raw ipinfo.io ``org`` field values.

    Args:
        isp: Raw ISP string (e.g. ``"AS3320 Deutsche Telekom AG"``), or ``None``.

    Returns:
        Cleaned name, or ``"--"`` when *isp* is ``None``.
    """
    if isp is None:
        return "--"

    text = re.sub(r"^AS\d+\s+", "", isp)

    for term in _CLEANUP_TERMS:
        text = re.sub(
            r"\b" + re.escape(term) + r"(?=\s|[.,\-]|$)",
            "",
            text,
            flags=re.IGNORECASE,
        )

    text = " ".join(text.split()).strip(" ,.:-")
    return text if text else isp


def truncate(text: str, max_len: int) -> str:
    """Truncate *text* to *max_len* characters, adding ``"..."`` when shortened.

    Tries to break at the last space within the available width.

    Args:
        text: Text to truncate.
        max_len: Maximum character count including the ellipsis marker.

    Returns:
        Original string if it fits, otherwise truncated string ending in
        ``"..."`` (3 characters reserved for the marker).
    """
    if len(text) <= max_len:
        return text
    # Reserve three characters for the ellipsis marker
    candidate = text[: max_len - 3]
    space = candidate.rfind(" ")
    if space > max_len * 0.6:
        return candidate[:space] + "..."
    return candidate + "..."
