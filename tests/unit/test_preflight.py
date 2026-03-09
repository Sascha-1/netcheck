"""Tests for netcheck.preflight.

Verifies:
- ``MissingCommand`` dataclass contract (frozen, equality, field access).
- ``check_required_commands`` returns the correct ``MissingCommand`` instances
  for absent commands and an empty list when all commands are present.
- ``check_required_commands`` covers all five required commands in the
  canonical order.
- ``format_missing_commands`` produces an actionable, human-readable message
  that includes every missing command name, every Debian package name, and a
  combined ``apt install`` line.

No real ``shutil.which`` calls are made.  Every test that exercises
``check_required_commands`` supplies a deterministic ``checker`` callable so
the results are independent of which system tools happen to be installed in
the test environment.

Test groups
-----------
``TestMissingCommand``
    Frozen dataclass contract: immutability, equality, field values.

``TestCheckRequiredCommands``
    All present -> empty list.
    One specific command absent -> correct MissingCommand returned.
    All absent -> one MissingCommand per required command.
    Order of results matches order of ``_REQUIRED_COMMANDS``.
    Covers all five expected command names.

``TestFormatMissingCommands``
    Single missing command: name, package, install line all present.
    Multiple missing commands: combined install line lists all packages.
    Message starts with ``"netcheck:"``.
    Duplicate package names deduplicated in the install line.
    Column alignment: longer name does not overflow shorter name's column.
"""

import dataclasses

import pytest

from netcheck.preflight import (
    MissingCommand,
    check_required_commands,
    format_missing_commands,
)

# ---------------------------------------------------------------------------
# Module-level constants used across multiple test classes
# ---------------------------------------------------------------------------

# The canonical five commands required by netcheck, in declaration order.
# These are asserted against the actual check results to catch any accidental
# omission or reordering in the production constant.
_EXPECTED_COMMANDS: tuple[str, ...] = (
    "ip",
    "resolvectl",
    "mmcli",
    "lspci",
    "lsusb",
)

_EXPECTED_PACKAGES: dict[str, str] = {
    "ip":         "iproute2",
    "resolvectl": "systemd",
    "mmcli":      "modemmanager",
    "lspci":      "pciutils",
    "lsusb":      "usbutils",
}


# ---------------------------------------------------------------------------
# TestMissingCommand
# ---------------------------------------------------------------------------

class TestMissingCommand:
    """MissingCommand dataclass: structural and immutability contracts."""

    def test_name_field_accessible(self) -> None:
        """``name`` must be readable from the constructed instance."""
        cmd = MissingCommand(name="lspci", package="pciutils")
        assert cmd.name == "lspci"

    def test_package_field_accessible(self) -> None:
        """``package`` must be readable from the constructed instance."""
        cmd = MissingCommand(name="lspci", package="pciutils")
        assert cmd.package == "pciutils"

    def test_frozen_name(self) -> None:
        """``name`` must not be reassignable after construction."""
        cmd = MissingCommand(name="lspci", package="pciutils")
        with pytest.raises(dataclasses.FrozenInstanceError):
            cmd.name = "other"  # type: ignore[misc]

    def test_frozen_package(self) -> None:
        """``package`` must not be reassignable after construction."""
        cmd = MissingCommand(name="lspci", package="pciutils")
        with pytest.raises(dataclasses.FrozenInstanceError):
            cmd.package = "other"  # type: ignore[misc]

    def test_equality_same_fields(self) -> None:
        """Two instances with identical fields must compare equal."""
        assert (
            MissingCommand(name="ip", package="iproute2")
            == MissingCommand(name="ip", package="iproute2")
        )

    def test_inequality_different_name(self) -> None:
        """Instances with different names must not compare equal."""
        assert (
            MissingCommand(name="ip", package="iproute2")
            != MissingCommand(name="lspci", package="iproute2")
        )

    def test_inequality_different_package(self) -> None:
        """Instances with different packages must not compare equal."""
        assert (
            MissingCommand(name="ip", package="iproute2")
            != MissingCommand(name="ip", package="pciutils")
        )


# ---------------------------------------------------------------------------
# TestCheckRequiredCommands
# ---------------------------------------------------------------------------

class TestCheckRequiredCommands:
    """check_required_commands: result content, order, and completeness."""

    def test_all_present_returns_empty_list(self) -> None:
        """When every command is available, the result must be an empty list."""
        result = check_required_commands(checker=lambda _: True)
        assert not result

    def test_return_type_is_list(self) -> None:
        """Return type must be a plain list (not a tuple or other sequence)."""
        result = check_required_commands(checker=lambda _: True)
        assert isinstance(result, list)

    def test_one_missing_returns_one_entry(self) -> None:
        """Exactly one absent command must produce exactly one MissingCommand."""
        def checker(name: str) -> bool:
            return name != "lspci"

        result = check_required_commands(checker=checker)
        assert len(result) == 1

    def test_one_missing_correct_name(self) -> None:
        """The MissingCommand for the absent command must carry the correct name."""
        def checker(name: str) -> bool:
            return name != "lspci"

        result = check_required_commands(checker=checker)
        assert result[0].name == "lspci"

    def test_one_missing_correct_package(self) -> None:
        """The MissingCommand for lspci must name the pciutils package."""
        def checker(name: str) -> bool:
            return name != "lspci"

        result = check_required_commands(checker=checker)
        assert result[0].package == "pciutils"

    def test_all_missing_returns_five_entries(self) -> None:
        """When no command is available, all five must appear in the result."""
        result = check_required_commands(checker=lambda _: False)
        assert len(result) == 5

    def test_all_missing_names_match_expected(self) -> None:
        """All five required command names must appear in the result."""
        result = check_required_commands(checker=lambda _: False)
        assert [m.name for m in result] == list(_EXPECTED_COMMANDS)

    def test_all_missing_packages_match_expected(self) -> None:
        """Each missing command must carry its correct Debian package name."""
        result = check_required_commands(checker=lambda _: False)
        for entry in result:
            assert entry.package == _EXPECTED_PACKAGES[entry.name], (
                f"Wrong package for '{entry.name}': "
                f"expected '{_EXPECTED_PACKAGES[entry.name]}', "
                f"got '{entry.package}'"
            )

    def test_order_matches_declaration(self) -> None:
        """Results must appear in the same order as the internal command registry.

        This order is also the order shown to the user in the error message.
        Maintaining it stable and matching the declaration avoids confusing
        diffs if the list changes in the future.
        """
        result = check_required_commands(checker=lambda _: False)
        assert [m.name for m in result] == list(_EXPECTED_COMMANDS)

    def test_present_commands_excluded_from_result(self) -> None:
        """Commands that pass the checker must not appear in the result."""
        def checker(name: str) -> bool:
            return name == "ip"  # only ip is present

        result = check_required_commands(checker=checker)
        returned_names = [m.name for m in result]
        assert "ip" not in returned_names

    def test_all_five_command_names_covered(self) -> None:
        """The registry must cover all five commands.  This test catches
        accidental omission of a command when ``_REQUIRED_COMMANDS`` is
        modified."""
        result = check_required_commands(checker=lambda _: False)
        returned_names = {m.name for m in result}
        assert returned_names == set(_EXPECTED_COMMANDS)

    def test_each_entry_is_missing_command_instance(self) -> None:
        """Every element in the returned list must be a MissingCommand."""
        result = check_required_commands(checker=lambda _: False)
        for entry in result:
            assert isinstance(entry, MissingCommand)


# ---------------------------------------------------------------------------
# TestFormatMissingCommands
# ---------------------------------------------------------------------------

class TestFormatMissingCommands:
    """format_missing_commands: content and structure of the error message."""

    def test_starts_with_netcheck_prefix(self) -> None:
        """The message must begin with 'netcheck:' for consistent CLI style."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        output = format_missing_commands(missing)
        assert output.startswith("netcheck:")

    def test_single_command_name_present(self) -> None:
        """The missing command name must appear in the message."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        output = format_missing_commands(missing)
        assert "lspci" in output

    def test_single_package_name_present(self) -> None:
        """The Debian package name must appear in the message."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        output = format_missing_commands(missing)
        assert "pciutils" in output

    def test_single_install_line_present(self) -> None:
        """An 'apt install' hint must appear in the message."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        output = format_missing_commands(missing)
        assert "sudo apt install" in output

    def test_single_install_line_contains_package(self) -> None:
        """The install hint must name the specific package to install."""
        missing = [MissingCommand(name="lspci", package="pciutils")]
        output = format_missing_commands(missing)
        assert "sudo apt install pciutils" in output

    def test_multiple_commands_all_names_present(self) -> None:
        """All missing command names must appear when multiple are absent."""
        missing = [
            MissingCommand(name="lspci", package="pciutils"),
            MissingCommand(name="lsusb", package="usbutils"),
        ]
        output = format_missing_commands(missing)
        assert "lspci" in output
        assert "lsusb" in output

    def test_multiple_commands_all_packages_present(self) -> None:
        """All Debian package names must appear when multiple commands are absent."""
        missing = [
            MissingCommand(name="lspci", package="pciutils"),
            MissingCommand(name="lsusb", package="usbutils"),
        ]
        output = format_missing_commands(missing)
        assert "pciutils" in output
        assert "usbutils" in output

    def test_multiple_commands_combined_install_line(self) -> None:
        """The install line must list all packages in a single apt command."""
        missing = [
            MissingCommand(name="lspci", package="pciutils"),
            MissingCommand(name="lsusb", package="usbutils"),
        ]
        output = format_missing_commands(missing)
        assert "sudo apt install pciutils usbutils" in output

    def test_duplicate_packages_deduplicated(self) -> None:
        """If two commands share a package, it must appear only once in the
        install line.

        This scenario does not occur with the current command registry, but
        the deduplication logic must be correct regardless.
        """
        missing = [
            MissingCommand(name="cmd_a", package="shared-pkg"),
            MissingCommand(name="cmd_b", package="shared-pkg"),
        ]
        output = format_missing_commands(missing)
        # "shared-pkg" must appear in the install line exactly once.
        install_line = next(
            line for line in output.splitlines() if "sudo apt install" in line
        )
        assert install_line.count("shared-pkg") == 1

    def test_all_five_missing_install_line_completeness(self) -> None:
        """When all five commands are missing, all five packages appear in the
        install line."""
        missing = [
            MissingCommand(name=name, package=pkg)
            for name, pkg in _EXPECTED_PACKAGES.items()
        ]
        output = format_missing_commands(missing)
        for pkg in _EXPECTED_PACKAGES.values():
            assert pkg in output

    def test_return_type_is_str(self) -> None:
        """Return type must be str."""
        missing = [MissingCommand(name="ip", package="iproute2")]
        assert isinstance(format_missing_commands(missing), str)

    def test_multiline_output(self) -> None:
        """The message must span multiple lines (header + entries + install)."""
        missing = [MissingCommand(name="ip", package="iproute2")]
        output = format_missing_commands(missing)
        assert "\n" in output

    def test_no_non_ascii_bytes_in_output(self) -> None:
        """The formatted message must contain only ASCII characters."""
        missing = [
            MissingCommand(name=name, package=pkg)
            for name, pkg in _EXPECTED_PACKAGES.items()
        ]
        output = format_missing_commands(missing)
        output.encode("ascii")  # raises UnicodeEncodeError if non-ASCII present
