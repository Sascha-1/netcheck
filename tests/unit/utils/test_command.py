"""Smoke tests for netcheck.utils.command.

Covers the public surface of the module:
- SystemCommandRunner.run  -- success, non-zero exit, missing executable
- command_exists           -- known and unknown commands
- FakeCommandRunner        -- response dispatch and call recording
"""

import subprocess

from pytest_mock import MockerFixture

from netcheck.utils.command import SystemCommandRunner, command_exists
from tests.fakes import FakeCommandRunner


class TestSystemCommandRunner:
    """Core behaviour of the production subprocess wrapper."""

    def test_successful_command_returns_stdout(self) -> None:
        """A zero-exit command must return its stripped stdout."""
        assert SystemCommandRunner().run(["echo", "hello"]) == "hello"

    def test_failed_command_returns_none(self) -> None:
        """A non-zero-exit command must return None."""
        assert SystemCommandRunner().run(["false"]) is None

    def test_missing_executable_returns_none(self) -> None:
        """An executable that does not exist must return None."""
        assert SystemCommandRunner().run(["netcheck_nonexistent_xyz"]) is None

    def test_output_is_stripped(self) -> None:
        """Leading and trailing whitespace must be removed from stdout."""
        assert SystemCommandRunner().run(["echo", "  hi  "]) == "hi"

    def test_timeout_returns_none(self, mocker: MockerFixture) -> None:
        """A command that exceeds the timeout must return None."""
        mocker.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=1),
        )
        assert SystemCommandRunner(timeout=1).run(["sleep", "99"]) is None

    def test_os_error_returns_none(self, mocker: MockerFixture) -> None:
        """An OS error during subprocess creation must return None."""
        mocker.patch("subprocess.run", side_effect=OSError("permission denied"))
        assert SystemCommandRunner().run(["ls"]) is None

    def test_shell_is_always_false(self, mocker: MockerFixture) -> None:
        """shell=False must always be passed to subprocess.run."""
        mock_run = mocker.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["echo"], returncode=0, stdout="ok\n", stderr=""
            ),
        )
        SystemCommandRunner().run(["echo", "ok"])
        assert mock_run.call_args[1]["shell"] is False


class TestCommandExists:
    """Smoke tests for command_exists."""

    def test_known_command_found(self) -> None:
        """ls must be present on any Linux system."""
        assert command_exists("ls") is True

    def test_unknown_command_not_found(self) -> None:
        """A made-up name must return False."""
        assert command_exists("netcheck_nonexistent_xyz_abc") is False

    def test_returns_bool(self) -> None:
        """Return type must be exactly bool."""
        assert isinstance(command_exists("ls"), bool)


class TestFakeCommandRunner:
    """Verify FakeCommandRunner honours its documented contract.

    The correctness of every other unit test depends on these behaviours.
    """

    def test_configured_response_returned(self) -> None:
        """A command with a configured response must return that response."""
        runner = FakeCommandRunner({("ip", "-o", "link", "show"): "1: lo:"})
        assert runner.run(["ip", "-o", "link", "show"]) == "1: lo:"

    def test_unconfigured_command_returns_none(self) -> None:
        """A command not in the map must return None."""
        assert FakeCommandRunner({}).run(["ip", "addr"]) is None

    def test_none_response_returned_as_none(self) -> None:
        """A command explicitly mapped to None must return None."""
        runner = FakeCommandRunner({("false",): None})
        assert runner.run(["false"]) is None

    def test_calls_recorded_in_order(self) -> None:
        """Every call must be appended to self.calls in order."""
        runner = FakeCommandRunner({})
        runner.run(["ip", "addr"])
        runner.run(["ip", "route"])
        assert runner.calls == [["ip", "addr"], ["ip", "route"]]

    def test_new_runner_has_empty_calls(self) -> None:
        """A freshly constructed runner must have no recorded calls."""
        assert not FakeCommandRunner({}).calls
