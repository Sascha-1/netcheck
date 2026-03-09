"""Unit tests for netcheck.output.formatters.

Tests ``clean_device``, ``clean_isp``, and ``truncate`` directly against
the public API in ``formatters.py``.  These functions are format-agnostic
display helpers shared across all renderers; testing them here keeps the
test file for ``table.py`` focused on table-specific rendering logic.
"""

from netcheck.output.formatters import clean_device, clean_isp, truncate


class TestCleanDevice:
    """clean_device: exact output for canonical inputs."""

    def test_intel_pci_full_string(self) -> None:
        """Corporate junk, controller category, and parenthesised revision stripped."""
        raw = "Intel Corporation Ethernet Controller I219-V"
        assert clean_device(raw) == "Intel I219-V"

    def test_intel_pci_with_revision(self) -> None:
        """Parenthesised revision block removed; model number preserved."""
        raw = "Intel Corporation Ethernet Controller I219-V (rev 03)"
        assert clean_device(raw) == "Intel I219-V"

    def test_none_returns_dash(self) -> None:
        assert clean_device(None) == "--"


class TestCleanIsp:
    """clean_isp: exact output for canonical inputs."""

    def test_telekom_as_prefix_and_ag_suffix_stripped(self) -> None:
        """AS number prefix and AG corporate suffix both removed."""
        assert clean_isp("AS3320 Deutsche Telekom AG") == "Deutsche Telekom"

    def test_post_luxembourg_as_prefix_stripped(self) -> None:
        assert clean_isp("AS6661 POST Luxembourg") == "POST Luxembourg"

    def test_m247_srl_as_prefix_stripped(self) -> None:
        """SRL is not in the cleanup list; only the AS prefix is removed."""
        assert clean_isp("AS9009 M247 Europe SRL") == "M247 Europe SRL"

    def test_none_returns_dash(self) -> None:
        assert clean_isp(None) == "--"


class TestTruncate:
    """truncate: column text truncation."""

    def test_short_text_unchanged(self) -> None:
        assert truncate("hello", 10) == "hello"

    def test_long_text_truncated_with_ellipsis(self) -> None:
        result = truncate("hello world foo bar", 10)
        assert len(result) <= 10
        assert result.endswith("...")

    def test_empty_string_unchanged(self) -> None:
        assert truncate("", 10) == ""


class TestCleanDeviceExtended:
    """clean_device: exact output for edge-case hardware name patterns."""

    def test_intel_pci_corporation_stripped(self) -> None:
        assert clean_device("Intel Corporation I219-V") == "Intel I219-V"

    def test_intel_pci_with_revision_stripped(self) -> None:
        assert clean_device("Intel I219-V (rev 03)") == "Intel I219-V"

    def test_usb_bus_and_id_prefix_stripped(self) -> None:
        raw = "Bus 001 Device 003: ID 18d1:4eeb Google LLC Pixel 9a"
        assert clean_device(raw) == "Google Pixel 9a"

    def test_id_prefix_only_stripped(self) -> None:
        assert clean_device("ID 18d1:4eeb Google LLC Pixel 9a") == "Google Pixel 9a"

    def test_quectel_duplicate_brand_deduplicated(self) -> None:
        assert clean_device("Quectel Quectel EM05-G") == "Quectel EM05-G"

    def test_none_returns_dash(self) -> None:
        assert clean_device(None) == "--"

    def test_empty_string_falls_back_to_dash(self) -> None:
        """A string that reduces to empty after cleaning returns '--'."""
        assert clean_device("") == "--"


class TestCleanIspExtended:
    """clean_isp: exact output for edge-case ISP name patterns."""

    def test_telekom_full_cleanup(self) -> None:
        """AS prefix and AG corporate suffix both removed; core name preserved."""
        assert clean_isp("AS3320 Deutsche Telekom AG") == "Deutsche Telekom"

    def test_m247_srl_as_prefix_only(self) -> None:
        """SRL is not in the cleanup list; only the AS prefix is removed."""
        assert clean_isp("AS9009 M247 Europe SRL") == "M247 Europe SRL"

    def test_no_as_prefix_passes_through_unchanged(self) -> None:
        assert clean_isp("M247 Europe") == "M247 Europe"

    def test_none_returns_dash(self) -> None:
        assert clean_isp(None) == "--"


class TestTruncateExtended:
    """truncate: edge cases around ellipsis placement."""

    def test_short_text_unchanged(self) -> None:
        assert truncate("hello", 20) == "hello"

    def test_exact_length_unchanged(self) -> None:
        assert truncate("hello", 5) == "hello"

    def test_long_text_truncated(self) -> None:
        result = truncate("a" * 30, 15)
        assert len(result) <= 15
        assert result.endswith("...")

    def test_space_break_preferred(self) -> None:
        text = "Intel Ethernet Controller I219-V"
        result = truncate(text, 20)
        assert "..." in result

    def test_no_space_breaks_at_max(self) -> None:
        text = "a" * 30
        result = truncate(text, 10)
        assert result == "aaaaaaa..."
