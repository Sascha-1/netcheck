"""Unit tests for netcheck.hardware.modem.

All tests use ``FakeCommandRunner`` -- no mmcli processes are spawned.
Fixture files in ``tests/fixtures/mmcli/`` contain real output captured
from the test machine's Quectel EM05-G modem.

Test groups
-----------
``TestParseModemIndices``
    Parses ``mmcli -L`` output to extract modem index strings.

``TestParseModemRecord``
    Parses ``mmcli -m 0 -K`` output into a ``ModemRecord``.  Uses both
    the normal (connected) and failed-state fixtures.

``TestGetAllModemData``
    Integration of the two parsing steps via ``FakeCommandRunner``.

``TestGetModemInterfaces``
    Aggregates net interfaces from a list of records.

``TestBuildModemInfo``
    Constructs ``ModemInfo`` from a record list for a given interface.
"""

from pathlib import Path

from netcheck.hardware.modem import (
    build_modem_info,
    get_all_modem_data,
    get_modem_interfaces,
    parse_modem_indices,
    parse_modem_record,
)
from tests.fakes import FakeCommandRunner

_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "mmcli"


def _read(filename: str) -> str:
    return (_FIXTURES / filename).read_text()


class TestParseModemIndices:
    """Tests for parse_modem_indices."""

    def test_single_modem(self) -> None:
        """A list with one modem entry must yield one index."""
        output = _read("list.txt")
        indices = parse_modem_indices(output)
        assert indices == ["0"]

    def test_multiple_modems(self) -> None:
        """Multiple modem entries must each produce an index."""
        output = (
            "    /org/freedesktop/ModemManager1/Modem/0 [Vendor] ModelA\n"
            "    /org/freedesktop/ModemManager1/Modem/1 [Vendor] ModelB\n"
        )
        assert parse_modem_indices(output) == ["0", "1"]

    def test_no_modems_returns_empty(self) -> None:
        """Output with no modem paths must return an empty list."""
        assert not parse_modem_indices("No modems were found.\n")

    def test_empty_string_returns_empty(self) -> None:
        """Empty string must return an empty list without raising."""
        assert not parse_modem_indices("")

    def test_high_index(self) -> None:
        """A modem at a high index (e.g. 12) must be parsed correctly."""
        output = "    /org/freedesktop/ModemManager1/Modem/12 [X] Y\n"
        assert parse_modem_indices(output) == ["12"]


class TestParseModemRecord:
    """Tests for parse_modem_record using fixture files."""

    def test_net_interface_extracted(self) -> None:
        """The (net) port must be identified as the network interface."""
        record = parse_modem_record("0", _read("modem0_kv.txt"))
        assert "wwp195s0f3u4" in record.interfaces

    def test_non_net_ports_excluded(self) -> None:
        """AT, qcdm, and qmi ports must not appear in interfaces."""
        record = parse_modem_record("0", _read("modem0_kv.txt"))
        for non_net in ("ttyUSB0", "ttyUSB1", "ttyUSB2", "ttyUSB3", "cdc-wdm0"):
            assert non_net not in record.interfaces

    def test_state_connected(self) -> None:
        """Connected modem state must be parsed correctly."""
        record = parse_modem_record("0", _read("modem0_kv.txt"))
        assert record.state == "connected"

    def test_state_reason_none_for_connected(self) -> None:
        """A state-failed-reason of 'none' must be normalised to None."""
        record = parse_modem_record("0", _read("modem0_kv.txt"))
        assert record.state_reason is None

    def test_failed_state(self) -> None:
        """Failed modem state must be parsed from the failed fixture."""
        record = parse_modem_record("0", _read("modem0_kv_failed.txt"))
        assert record.state == "failed"

    def test_failed_state_reason(self) -> None:
        """The failure reason must be captured when the modem has failed."""
        record = parse_modem_record("0", _read("modem0_kv_failed.txt"))
        assert record.state_reason == "sim-missing"

    def test_index_stored(self) -> None:
        """The modem index must be stored in the record."""
        record = parse_modem_record("0", _read("modem0_kv.txt"))
        assert record.index == "0"

    def test_interfaces_is_frozenset(self) -> None:
        """interfaces must be a frozenset."""
        record = parse_modem_record("0", _read("modem0_kv.txt"))
        assert isinstance(record.interfaces, frozenset)

    def test_empty_output_produces_empty_record(self) -> None:
        """Empty kv output must not raise and must produce empty fields."""
        record = parse_modem_record("0", "")
        assert not record.interfaces
        assert record.state is None
        assert record.state_reason is None


class TestParseModemRecordArrayFormat:
    """Tests for parse_modem_record using the per-line array format.

    Debian 12 (Bookworm) and later ship ModemManager >= 1.18, which emits
    one port per line with an array-indexed key::

        modem.generic.ports.value[1] : cdc-wdm1 (mbim)
        modem.generic.ports.value[2] : ttyUSB0 (at)
        modem.generic.ports.value[3] : wwp195s0f3u4 (net)

    The single-line format used by Debian 11 (Bullseye) and earlier must
    also continue to work; both formats are exercised here.
    """

    def test_net_interface_extracted(self) -> None:
        """The (net) port must be found in the per-line array format."""
        record = parse_modem_record("0", _read("modem0_kv_newformat.txt"))
        assert "wwp195s0f3u4" in record.interfaces

    def test_non_net_ports_excluded(self) -> None:
        """mbim and at ports must not appear in interfaces."""
        record = parse_modem_record("0", _read("modem0_kv_newformat.txt"))
        for non_net in ("cdc-wdm1", "ttyUSB0"):
            assert non_net not in record.interfaces

    def test_length_line_not_parsed_as_port(self) -> None:
        """The modem.generic.ports.length line must be ignored gracefully."""
        record = parse_modem_record("0", _read("modem0_kv_newformat.txt"))
        # length value is "3"; "3" should not appear as an interface name
        assert "3" not in record.interfaces

    def test_failed_state_parsed(self) -> None:
        """State must be parsed correctly in the per-line array format."""
        record = parse_modem_record("0", _read("modem0_kv_newformat.txt"))
        assert record.state == "failed"

    def test_failed_reason_parsed(self) -> None:
        """state_reason must be captured from the per-line array format fixture."""
        record = parse_modem_record("0", _read("modem0_kv_newformat.txt"))
        assert record.state_reason == "sim-missing"

    def test_interfaces_is_frozenset(self) -> None:
        """interfaces must be a frozenset regardless of format."""
        record = parse_modem_record("0", _read("modem0_kv_newformat.txt"))
        assert isinstance(record.interfaces, frozenset)

    def test_single_line_format_works(self) -> None:
        """The single-line format (Debian 11 and earlier) must continue to work."""
        record = parse_modem_record("0", _read("modem0_kv.txt"))
        assert "wwp195s0f3u4" in record.interfaces
        assert record.state == "connected"


class TestGetAllModemData:
    """Tests for get_all_modem_data using FakeCommandRunner."""

    def test_one_modem_returns_one_record(self) -> None:
        """A system with one modem must produce one record."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        assert len(records) == 1

    def test_correct_interface_in_record(self) -> None:
        """The net interface from modem 0 must appear in the record."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        assert "wwp195s0f3u4" in records[0].interfaces

    def test_mmcli_list_failure_returns_empty(self) -> None:
        """If mmcli -L fails, return an empty list without raising."""
        runner = FakeCommandRunner({("mmcli", "-L"): None})
        assert not get_all_modem_data(runner)

    def test_mmcli_kv_failure_skips_modem(self) -> None:
        """If mmcli -m 0 -K fails, that modem is silently skipped."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): None,
            }
        )
        assert not get_all_modem_data(runner)

    def test_no_modems_returns_empty(self) -> None:
        """mmcli -L with no modem paths must return an empty list."""
        runner = FakeCommandRunner(
            {("mmcli", "-L"): "No modems were found.\n"}
        )
        assert not get_all_modem_data(runner)

    def test_calls_list_once(self) -> None:
        """mmcli -L must be called exactly once."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        get_all_modem_data(runner)
        list_calls = [c for c in runner.calls if c == ["mmcli", "-L"]]
        assert len(list_calls) == 1

    def test_calls_kv_once_per_modem(self) -> None:
        """mmcli -m 0 -K must be called exactly once for modem 0."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        get_all_modem_data(runner)
        kv_calls = [c for c in runner.calls if c[:2] == ["mmcli", "-m"]]
        assert len(kv_calls) == 1


class TestGetModemInterfaces:
    """Tests for get_modem_interfaces."""

    def test_single_modem_interface(self) -> None:
        """One modem with one net port must return that interface."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        interfaces = get_modem_interfaces(records)
        assert "wwp195s0f3u4" in interfaces

    def test_returns_frozenset(self) -> None:
        """Result must be a frozenset."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        assert isinstance(get_modem_interfaces(records), frozenset)

    def test_empty_records_returns_empty_frozenset(self) -> None:
        """No modem records must produce an empty frozenset."""
        assert get_modem_interfaces([]) == frozenset()


class TestBuildModemInfo:
    """Tests for build_modem_info."""

    def test_known_interface_returns_modem_info(self) -> None:
        """build_modem_info must return ModemInfo for a managed interface."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        info = build_modem_info("wwp195s0f3u4", records)
        assert info is not None

    def test_state_populated(self) -> None:
        """ModemInfo must carry the modem state."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        info = build_modem_info("wwp195s0f3u4", records)
        assert info is not None
        assert info.state == "connected"

    def test_state_reason_none_for_healthy_modem(self) -> None:
        """state_reason must be None when the modem is not failed."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        info = build_modem_info("wwp195s0f3u4", records)
        assert info is not None
        assert info.state_reason is None

    def test_failed_modem_carries_reason(self) -> None:
        """ModemInfo must include state_reason when the modem has failed."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv_failed.txt"),
            }
        )
        records = get_all_modem_data(runner)
        info = build_modem_info("wwp195s0f3u4", records)
        assert info is not None
        assert info.state_reason == "sim-missing"

    def test_unknown_interface_returns_none(self) -> None:
        """An interface not managed by any modem must return None."""
        runner = FakeCommandRunner(
            {
                ("mmcli", "-L"): _read("list.txt"),
                ("mmcli", "-m", "0", "-K"): _read("modem0_kv.txt"),
            }
        )
        records = get_all_modem_data(runner)
        assert build_modem_info("eth0", records) is None

    def test_empty_records_returns_none(self) -> None:
        """No modem records means no ModemInfo for any interface."""
        assert build_modem_info("wwp195s0f3u4", []) is None
