"""
Tests for export functionality (JSON and CSV).

Tests the export module's ability to convert InterfaceInfo objects
to JSON and CSV formats.
"""

from typing import Any, Dict, List, Optional, Generator
from pathlib import Path
from unittest.mock import MagicMock
from _pytest.logging import LogCaptureFixture
from _pytest.capture import CaptureFixture
from _pytest.config import Config
from _pytest.monkeypatch import MonkeyPatch


import pytest
import json
import csv
from io import StringIO
from pathlib import Path

from export import (
    export_to_json,
    export_to_csv,
    save_json,
    save_csv,
    _interface_to_dict,
)
from models import InterfaceInfo


class TestInterfaceToDict:
    """Test InterfaceInfo to dictionary conversion."""

    def test_empty_interface(self) -> None:
        """Test converting empty interface to dict."""
        interface = InterfaceInfo.create_empty("eth0")
        result = _interface_to_dict(interface)

        assert result["name"] == "eth0"
        assert result["interface_type"] == "N/A"
        assert result["dns_servers"] == []
        assert result["carries_vpn"] is False

    def test_full_interface(self, sample_interface_info: InterfaceInfo) -> None:
        """Test converting populated interface to dict."""
        result = _interface_to_dict(sample_interface_info)

        assert result["name"] == "eth0"
        assert result["interface_type"] == "ethernet"
        assert result["device"] == "Intel Corporation I219-V"
        assert result["internal_ipv4"] == "192.168.1.100"
        assert result["dns_servers"] == ["8.8.8.8", "8.8.4.4"]
        assert result["current_dns"] == "8.8.8.8"

    def test_vpn_interface(self, sample_vpn_interface_info: InterfaceInfo) -> None:
        """Test converting VPN interface to dict."""
        result = _interface_to_dict(sample_vpn_interface_info)

        assert result["name"] == "tun0"
        assert result["interface_type"] == "vpn"
        assert result["dns_leak_status"] == "OK"


class TestExportToJson:
    """Test JSON export functionality."""

    def test_empty_list(self) -> None:
        """Test exporting empty interface list."""
        json_str = export_to_json([])
        data = json.loads(json_str)

        assert data["interfaces"] == []
        assert data["metadata"]["interface_count"] == 0

    def test_single_interface(self, sample_interface_info: InterfaceInfo) -> None:
        """Test exporting single interface."""
        json_str = export_to_json([sample_interface_info])
        data = json.loads(json_str)

        assert len(data["interfaces"]) == 1
        assert data["interfaces"][0]["name"] == "eth0"
        assert data["metadata"]["interface_count"] == 1

    def test_multiple_interfaces(self, sample_interface_list: list[InterfaceInfo]) -> None:
        """Test exporting multiple interfaces."""
        json_str = export_to_json(sample_interface_list)
        data = json.loads(json_str)

        assert len(data["interfaces"]) == 3
        assert data["metadata"]["interface_count"] == 3

    def test_metadata_included(self, sample_interface_info: InterfaceInfo) -> None:
        """Test that metadata is included by default."""
        json_str = export_to_json([sample_interface_info])
        data = json.loads(json_str)

        assert "metadata" in data
        assert "timestamp" in data["metadata"]
        assert "interface_count" in data["metadata"]
        assert "summary" in data["metadata"]

    def test_metadata_excluded(self, sample_interface_info: InterfaceInfo) -> None:
        """Test excluding metadata."""
        json_str = export_to_json([sample_interface_info], include_metadata=False)
        data = json.loads(json_str)

        assert "metadata" not in data
        assert "interfaces" in data

    def test_vpn_detection_in_summary(self, sample_vpn_interface_info: InterfaceInfo) -> None:
        """Test VPN detection in metadata summary."""
        json_str = export_to_json([sample_vpn_interface_info])
        data = json.loads(json_str)

        assert data["metadata"]["summary"]["vpn_active"] is True
        assert data["metadata"]["summary"]["vpn_interfaces"] == 1

    def test_leak_detection_in_summary(self, sample_interface_info: InterfaceInfo) -> None:
        """Test DNS leak detection in metadata summary."""
        # Create interface with leak
        interface = InterfaceInfo.create_empty("eth0")
        interface.dns_leak_status = "LEAK"

        json_str = export_to_json([interface])
        data = json.loads(json_str)

        assert data["metadata"]["summary"]["dns_leak_detected"] is True

    def test_custom_indent(self, sample_interface_info: InterfaceInfo) -> None:
        """Test custom JSON indentation."""
        json_str = export_to_json([sample_interface_info], indent=4)

        # Check that indentation is applied
        assert "    " in json_str  # 4 spaces

    def test_json_valid_format(self, sample_interface_list: list[InterfaceInfo]) -> None:
        """Test that output is valid JSON."""
        json_str = export_to_json(sample_interface_list)

        # Should not raise exception
        data = json.loads(json_str)
        assert isinstance(data, dict)

    def test_unicode_handling(self) -> None:
        """Test Unicode characters in device names."""
        interface = InterfaceInfo.create_empty("eth0")
        interface.device = "Realtek® RTL8111/8168/8411"

        json_str = export_to_json([interface])
        data = json.loads(json_str)

        assert "®" in data["interfaces"][0]["device"]

    def test_dns_servers_list_preserved(self, sample_interface_info: InterfaceInfo) -> None:
        """Test that DNS servers list is preserved as array."""
        json_str = export_to_json([sample_interface_info])
        data = json.loads(json_str)

        dns_servers = data["interfaces"][0]["dns_servers"]
        assert isinstance(dns_servers, list)
        assert dns_servers == ["8.8.8.8", "8.8.4.4"]


class TestExportToCsv:
    """Test CSV export functionality."""

    def test_empty_list(self) -> None:
        """Test exporting empty interface list."""
        csv_str = export_to_csv([])
        lines = csv_str.strip().split("\n")

        assert len(lines) == 1  # Only header

    def test_single_interface(self, sample_interface_info: InterfaceInfo) -> None:
        """Test exporting single interface."""
        csv_str = export_to_csv([sample_interface_info])
        lines = csv_str.strip().split("\n")

        assert len(lines) == 2  # Header + 1 data row

    def test_multiple_interfaces(self, sample_interface_list: list[InterfaceInfo]) -> None:
        """Test exporting multiple interfaces."""
        csv_str = export_to_csv(sample_interface_list)
        lines = csv_str.strip().split("\n")

        assert len(lines) == 4  # Header + 3 data rows

    def test_header_included(self, sample_interface_info: InterfaceInfo) -> None:
        """Test that header is included by default."""
        csv_str = export_to_csv([sample_interface_info])
        lines = csv_str.strip().split("\n")

        header = lines[0]
        assert "name" in header
        assert "interface_type" in header
        assert "dns_leak_status" in header

    def test_header_excluded(self, sample_interface_info: InterfaceInfo) -> None:
        """Test excluding header."""
        csv_str = export_to_csv([sample_interface_info], include_header=False)
        lines = csv_str.strip().split("\n")

        # First line should be data, not header
        assert lines[0].startswith("eth0,")

    def test_dns_servers_joined(self, sample_interface_info: InterfaceInfo) -> None:
        """Test that DNS servers are joined with semicolons."""
        csv_str = export_to_csv([sample_interface_info])

        # Parse CSV
        reader = csv.DictReader(StringIO(csv_str))
        row = next(reader)

        assert row["dns_servers"] == "8.8.8.8;8.8.4.4"

    def test_empty_dns_servers(self) -> None:
        """Test interface with no DNS servers."""
        interface = InterfaceInfo.create_empty("eth0")
        csv_str = export_to_csv([interface])

        reader = csv.DictReader(StringIO(csv_str))
        row = next(reader)

        assert row["dns_servers"] == ""

    def test_boolean_converted(self, sample_vpn_interface_info: InterfaceInfo) -> None:
        """Test that boolean values are converted to strings."""
        sample_vpn_interface_info.carries_vpn = True
        csv_str = export_to_csv([sample_vpn_interface_info])

        reader = csv.DictReader(StringIO(csv_str))
        row = next(reader)

        assert row["carries_vpn"] in ["true", "false"]

    def test_none_values_handled(self) -> None:
        """Test that None values are converted to empty strings."""
        interface = InterfaceInfo.create_empty("eth0")
        interface.current_dns = None
        interface.vpn_server_ip = None

        csv_str = export_to_csv([interface])

        reader = csv.DictReader(StringIO(csv_str))
        row = next(reader)

        assert row["current_dns"] == ""
        assert row["vpn_server_ip"] == ""

    def test_custom_delimiter(self, sample_interface_info: InterfaceInfo) -> None:
        """Test custom CSV delimiter."""
        csv_str = export_to_csv([sample_interface_info], delimiter=";")

        assert ";" in csv_str
        assert csv_str.count(";") > 10  # Many semicolons as delimiter

    def test_csv_valid_format(self, sample_interface_list: list[InterfaceInfo]) -> None:
        """Test that output is valid CSV."""
        csv_str = export_to_csv(sample_interface_list)

        # Should parse without exception
        reader = csv.DictReader(StringIO(csv_str))
        rows = list(reader)

        assert len(rows) == 3

    def test_special_characters_escaped(self) -> None:
        """Test that special characters (commas, quotes) are escaped."""
        interface = InterfaceInfo.create_empty("eth0")
        interface.device = 'Test "Device", Inc.'

        csv_str = export_to_csv([interface])

        # Should parse correctly despite special characters
        reader = csv.DictReader(StringIO(csv_str))
        row = next(reader)

        assert row["device"] == 'Test "Device", Inc.'


class TestSaveJson:
    """Test JSON file saving."""

    def test_save_to_file(
        self,
        tmp_path: Path,
        sample_interface_list: list[InterfaceInfo]
    ) -> None:
        """Test saving JSON to file."""
        output_file = tmp_path / "test.json"

        save_json(sample_interface_list, str(output_file))

        assert output_file.exists()

        # Verify content
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["interfaces"]) == 3

    def test_file_overwrite(
        self,
        tmp_path: Path,
        sample_interface_info: InterfaceInfo
    ) -> None:
        """Test that saving overwrites existing file."""
        output_file = tmp_path / "test.json"

        # Write initial file
        save_json([sample_interface_info], str(output_file))

        # Overwrite
        empty_interface = InterfaceInfo.create_empty("lo")
        save_json([empty_interface], str(output_file))

        # Verify overwrite
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["interfaces"][0]["name"] == "lo"


class TestSaveCsv:
    """Test CSV file saving."""

    def test_save_to_file(
        self,
        tmp_path: Path,
        sample_interface_list: list[InterfaceInfo]
    ) -> None:
        """Test saving CSV to file."""
        output_file = tmp_path / "test.csv"

        save_csv(sample_interface_list, str(output_file))

        assert output_file.exists()

        # Verify content
        with open(output_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3

    def test_file_encoding(
        self,
        tmp_path: Path,
        sample_interface_info: InterfaceInfo
    ) -> None:
        """Test that file is saved with UTF-8 encoding."""
        output_file = tmp_path / "test.csv"

        sample_interface_info.device = "Device® with Unicode™"
        save_csv([sample_interface_info], str(output_file))

        # Read back and verify Unicode preserved
        with open(output_file, "r", encoding="utf-8") as f:
            content = f.read()

        assert "®" in content
        assert "™" in content


class TestIntegration:
    """Integration tests for export functionality."""

    def test_json_csv_consistency(
        self,
        sample_interface_list: list[InterfaceInfo]
    ) -> None:
        """Test that JSON and CSV contain same data."""
        json_str = export_to_json(sample_interface_list, include_metadata=False)
        csv_str = export_to_csv(sample_interface_list)

        # Parse both
        json_data = json.loads(json_str)
        csv_reader = csv.DictReader(StringIO(csv_str))
        csv_rows = list(csv_reader)

        # Should have same number of interfaces
        assert len(json_data["interfaces"]) == len(csv_rows)

        # Check first interface name matches
        assert json_data["interfaces"][0]["name"] == csv_rows[0]["name"]

    def test_round_trip_json(
        self,
        tmp_path: Path,
        sample_interface_list: list[InterfaceInfo]
    ) -> None:
        """Test saving and loading JSON preserves data."""
        output_file = tmp_path / "test.json"

        # Save
        save_json(sample_interface_list, str(output_file))

        # Load
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Verify
        original_names = [i.name for i in sample_interface_list]
        loaded_names = [i["name"] for i in data["interfaces"]]

        assert original_names == loaded_names
