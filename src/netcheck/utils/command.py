"""Command execution infrastructure for netcheck.

Provides:
- ``CommandRunner``: Protocol for injectable command execution.  Every module
  that runs system commands receives a ``CommandRunner`` instance rather than
  calling ``subprocess`` directly, making the module fully testable without
  spawning processes.
- ``SystemCommandRunner``: Production implementation backed by ``subprocess``.
- ``command_exists``: Check whether a command is available in ``PATH``.

Security note
-------------
``SystemCommandRunner`` never uses ``shell=True``.  All commands are passed
as lists, preventing shell injection regardless of the content of individual
arguments.
"""

import logging
import shutil
import subprocess
from typing import Protocol

logger = logging.getLogger(__name__)


# Single-method design is intentional: the protocol defines exactly one
# operation.  Adding methods to satisfy pylint would pollute the interface.
class CommandRunner(Protocol):  # pylint: disable=too-few-public-methods
    """Protocol for running system commands.

    Any object with a ``run`` method matching this signature satisfies the
    protocol.  Production code uses ``SystemCommandRunner``; tests substitute
    a fake that returns fixture data without spawning processes.

    This protocol is the single seam that makes every network, hardware, and
    detection module independently testable.
    """

    def run(self, cmd: list[str]) -> str | None:
        """Execute a command and return its stdout, or ``None`` on failure.

        Args:
            cmd: Command and arguments as a list,
                 e.g. ``["ip", "addr", "show"]``.

        Returns:
            Stripped stdout string if the command exits with code 0,
            ``None`` for any other outcome (non-zero exit, timeout, missing
            executable, OS error).
        """


# Single public method by design: the adapter wraps exactly one subprocess
# operation.  The private _timeout attribute is an implementation detail.
class SystemCommandRunner:  # pylint: disable=too-few-public-methods
    """Production ``CommandRunner`` backed by ``subprocess``.

    Args:
        timeout: Maximum seconds to wait for any single command.
                 Defaults to 10.
    """

    def __init__(self, timeout: int = 10) -> None:
        self._timeout = timeout

    def run(self, cmd: list[str]) -> str | None:
        """Execute ``cmd`` as a subprocess and return stripped stdout or ``None``.

        The command is never run through a shell (``shell=False``).  A
        non-zero exit code and a subprocess error are treated identically:
        both return ``None``.  Callers that need to distinguish between these
        cases should wrap this method with their own error-handling logic.

        Args:
            cmd: Command and arguments as a list.

        Returns:
            Stripped stdout if exit code is 0, ``None`` otherwise.
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                shell=False,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None


def command_exists(name: str) -> bool:
    """Return ``True`` if *name* is an executable on ``PATH``.

    Uses ``shutil.which`` so the result reflects the same lookup that a shell
    would perform.

    Args:
        name: Command name to check (e.g. ``"lspci"``).

    Returns:
        ``True`` if the command is found on ``PATH``, ``False`` otherwise.
    """
    return shutil.which(name) is not None
