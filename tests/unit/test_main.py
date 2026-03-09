"""Tests for netcheck.__main__ (CLI entry point).

Tests ``parse_args`` in isolation using sys.argv overrides.
Tests ``main()`` by monkeypatching ``collect_network_data`` with a fake
that returns a pre-built interface list, exercising all output paths
and exit-code logic without any real subprocess calls or network requests.

Test groups
-----------
``TestParseArgs``
    Default flags, --verbose, --export json, -o/--output, combined flags.

``TestMain``
    Returns 1 when no interfaces found.
    Returns 0 with default table output.
    Returns 0 with --export json to stdout.
    Returns 0 with --export json -o <file>.
    Returns 1 when the output file cannot be written.
    --verbose sets up logging (smoke test: no crash).

    All ``TestMain`` tests bypass the pre-flight check via an ``autouse``
    fixture so they do not depend on which system commands happen to be
    installed in the test environment.

``TestMainPreflight``
    Returns 1 when one or more required commands are absent.
    Missing commands are reported on stderr.
    All commands present -> collection proceeds normally.
"""

import argparse
import json
import sys
from pathlib import Path

import pytest

import netcheck.__main__ as main_module
from netcheck.config import VERSION
from netcheck.core.enums import InterfaceType
from netcheck.core.models import InterfaceInfo
from netcheck.preflight import MissingCommand
from netcheck.utils.command import CommandRunner
from netcheck.utils.http import HttpClient
from netcheck.utils.sysfs import SysfsReader
from tests.helpers import IfaceSpec, make_output_iface


def _fake_collect(
    _runner: CommandRunner,
    _reader: SysfsReader,
    _client: HttpClient,
) -> list[InterfaceInfo]:
    """Return a minimal single-interface list as a stand-in for collect_network_data."""
    return [make_output_iface(IfaceSpec(name="eth0", interface_type=InterfaceType.ETHERNET))]


def _fake_collect_empty(
    _runner: CommandRunner,
    _reader: SysfsReader,
    _client: HttpClient,
) -> list[InterfaceInfo]:
    return []


class TestParseArgs:
    """parse_args: argparse configuration."""

    def _parse(self, argv: list[str]) -> argparse.Namespace:
        saved = sys.argv
        try:
            sys.argv = ["netcheck"] + argv
            return main_module.parse_args()
        finally:
            sys.argv = saved

    def test_no_args_defaults(self) -> None:
        args = self._parse([])
        assert args.export is None
        assert args.output is None
        assert args.verbose is False

    def test_verbose_flag(self) -> None:
        args = self._parse(["-v"])
        assert args.verbose is True

    def test_verbose_long_flag(self) -> None:
        args = self._parse(["--verbose"])
        assert args.verbose is True

    def test_export_json(self) -> None:
        args = self._parse(["--export", "json"])
        assert args.export == "json"

    def test_output_path(self) -> None:
        args = self._parse(["--export", "json", "-o", "/tmp/out.json"])
        assert args.output == Path("/tmp/out.json")

    def test_output_long_flag(self) -> None:
        args = self._parse(["--export", "json", "--output", "/tmp/out.json"])
        assert args.output == Path("/tmp/out.json")

    def test_invalid_export_format_exits(self) -> None:
        with pytest.raises(SystemExit):
            self._parse(["--export", "xml"])

    def test_version_flag_exits_zero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            self._parse(["--version"])
        assert exc_info.value.code == 0

    def test_version_flag_output_contains_version(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit):
            self._parse(["--version"])
        captured = capsys.readouterr()
        assert VERSION in captured.out


class TestMain:
    """main(): exit codes and output routing.

    All tests in this class bypass the pre-flight check via the
    ``bypass_preflight`` autouse fixture.  The pre-flight check is tested
    independently in ``TestMainPreflight``.
    """

    @pytest.fixture(autouse=True)
    def bypass_preflight(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Replace check_required_commands with a no-op for all TestMain tests.

        This fixture ensures that TestMain tests are not affected by the
        availability of system commands (ip, resolvectl, mmcli, lspci, lsusb)
        in the test environment.  The pre-flight check itself is tested in
        TestMainPreflight using an injectable checker callable.
        """
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands",
            lambda: [],
        )

    def test_returns_one_when_no_interfaces(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect_empty)
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        assert main_module.main() == 1

    def test_returns_zero_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect)
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        assert main_module.main() == 0

    def test_table_output_goes_to_stdout(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect)
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        captured = capsys.readouterr()
        assert "INTERFACE" in captured.out

    def test_export_json_prints_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect)
        monkeypatch.setattr(sys, "argv", ["netcheck", "--export", "json"])
        rc = main_module.main()
        captured = capsys.readouterr()
        assert rc == 0
        parsed = json.loads(captured.out)
        # format_json returns {"metadata": ..., "interfaces": [...]}
        assert "interfaces" in parsed
        assert isinstance(parsed["interfaces"], list)

    def test_export_json_to_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect)
        out_file = tmp_path / "report.json"
        monkeypatch.setattr(
            sys, "argv", ["netcheck", "--export", "json", "-o", str(out_file)]
        )
        rc = main_module.main()
        assert rc == 0
        assert out_file.exists()
        content = json.loads(out_file.read_text(encoding="utf-8"))
        assert "interfaces" in content
        assert isinstance(content["interfaces"], list)

    def test_export_json_to_unwritable_path_returns_one(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect)
        bad_path = tmp_path / "nonexistent_dir" / "report.json"
        monkeypatch.setattr(
            sys, "argv", ["netcheck", "--export", "json", "-o", str(bad_path)]
        )
        rc = main_module.main()
        assert rc == 1

    def test_verbose_does_not_crash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--verbose configures logging; smoke test that nothing raises."""
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect)
        monkeypatch.setattr(sys, "argv", ["netcheck", "--verbose"])
        rc = main_module.main()
        assert rc == 0

    def test_no_interfaces_prints_to_stderr(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect_empty)
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        captured = capsys.readouterr()
        assert "netcheck:" in captured.err


class TestMainPreflight:
    """main(): pre-flight check integration with the CLI entry point.

    Tests the interaction between main() and check_required_commands().
    The checker callable is injected via monkeypatch so no real shutil.which
    calls are made and the tests are independent of the test environment.
    """

    def test_missing_command_returns_exit_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() must return 1 when at least one required command is absent."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: missing
        )
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        assert main_module.main() == 1

    def test_missing_command_message_on_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The missing command name must appear in the stderr output."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: missing
        )
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        captured = capsys.readouterr()
        assert "lspci" in captured.err

    def test_missing_package_name_on_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The Debian package name must appear in the stderr output."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: missing
        )
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        captured = capsys.readouterr()
        assert "pciutils" in captured.err

    def test_install_hint_on_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An apt install hint must appear in the stderr output."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: missing
        )
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        captured = capsys.readouterr()
        assert "sudo apt install" in captured.err

    def test_collection_not_called_when_commands_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """collect_network_data must not be called if the pre-flight check fails.

        Running collection with absent tools would produce misleading
        DataStatus.ERROR results rather than a clear error message.
        """
        call_count = 0

        def counting_collect(*_args: object) -> list[InterfaceInfo]:
            nonlocal call_count
            call_count += 1
            return []

        missing = [MissingCommand(name="ip", package="iproute2")]
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: missing
        )
        monkeypatch.setattr("netcheck.__main__.collect_network_data", counting_collect)
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        assert call_count == 0

    def test_all_present_proceeds_to_collection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When check_required_commands returns [], collection must proceed."""
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: []
        )
        monkeypatch.setattr("netcheck.__main__.collect_network_data", _fake_collect)
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        assert main_module.main() == 0

    def test_multiple_missing_all_names_on_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """All missing command names must appear in stderr when multiple absent."""
        missing = [
            MissingCommand(name="lspci", package="pciutils"),
            MissingCommand(name="lsusb", package="usbutils"),
        ]
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: missing
        )
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        captured = capsys.readouterr()
        assert "lspci" in captured.err
        assert "lsusb" in captured.err

    def test_missing_message_not_on_stdout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The pre-flight error message must go to stderr, not stdout."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        monkeypatch.setattr(
            "netcheck.__main__.check_required_commands", lambda: missing
        )
        monkeypatch.setattr(sys, "argv", ["netcheck"])
        main_module.main()
        captured = capsys.readouterr()
        assert "lspci" not in captured.out
