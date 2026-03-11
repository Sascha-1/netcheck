"""Shared test doubles for the netcheck test suite.


This module provides fake implementations of infrastructure interfaces.
Test modules import these directly and instantiate them with the specific
responses needed for each test case.

Using explicit fake objects rather than mocking frameworks keeps tests
readable: the data flowing through the system under test is visible at the
top of each test, not hidden in patch decorators or fixture chains.
"""

import os
from typing import Any


# Single public method by design: the fake mirrors the CommandRunner protocol
# which deliberately defines exactly one operation.
class FakeCommandRunner:  # pylint: disable=too-few-public-methods
    """Test double for ``netcheck.utils.command.CommandRunner``.

    Returns pre-configured responses for specific commands without spawning
    subprocesses.  Every call is recorded in ``calls`` for assertion.

    Structurally satisfies the ``CommandRunner`` protocol: its ``run`` method
    has an identical signature, so it can be passed wherever a
    ``CommandRunner`` is expected.

    Args:
        responses: Mapping of command tuples to return values.  A ``None``
                   value simulates a failed or absent command.
        strict: If ``True`` (the default), raise ``KeyError`` for any command
                not present in ``responses``.  This makes under-specified test
                fixtures immediately visible: a refactor that adds a new
                system call will fail loudly rather than silently receiving
                ``None`` for the unregistered command.

                Pass ``strict=False`` only when the test intentionally
                exercises non-strict behaviour, or when the production code
                under test is expected to call a command that is not in the
                response map (e.g. testing the ``calls`` list without caring
                about return values).

    Example::

        runner = FakeCommandRunner({
            ("ip", "-o", "link", "show"): "1: lo: <LOOPBACK>\\n2: eth0:",
            ("ip", "route", "show", "dev", "lo"): None,
        })
        assert runner.run(["ip", "-o", "link", "show"]) == "1: lo: <LOOPBACK>\\n2: eth0:"
        assert runner.run(["ip", "route", "show", "dev", "lo"]) is None
        assert runner.calls == [
            ["ip", "-o", "link", "show"],
            ["ip", "route", "show", "dev", "lo"],
        ]
    """

    def __init__(
        self,
        responses: dict[tuple[str, ...], str | None],
        strict: bool = True,
    ) -> None:
        self._responses = responses
        self._strict = strict
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str]) -> str | None:
        """Return the pre-configured response for ``cmd``.

        Records the call in ``self.calls`` regardless of whether a response
        is configured.  In strict mode (the default), raises ``KeyError`` for
        any command not in the response mapping, making misconfigured test
        fixtures immediately visible.  In non-strict mode, returns ``None``
        for unregistered commands, matching the behaviour of
        ``SystemCommandRunner`` when a command fails.

        Args:
            cmd: Command and arguments as a list.

        Returns:
            The pre-configured response string, or ``None`` if not configured
            (non-strict mode only).

        Raises:
            KeyError: If ``strict=True`` and ``cmd`` is not in the response
                mapping.
        """
        self.calls.append(cmd)
        key = tuple(cmd)
        if self._strict and key not in self._responses:
            raise KeyError(f"FakeCommandRunner (strict): unregistered command {cmd!r}")
        return self._responses.get(key)


# Four public methods by design: the fake mirrors the SysfsReader protocol
# which deliberately defines the minimum set of sysfs operations.
class FakeSysfsReader:
    """Test double for ``netcheck.utils.sysfs.SysfsReader``.

    Returns pre-configured responses for specific sysfs queries without
    touching ``/sys``.  Structurally satisfies the ``SysfsReader`` protocol.

    ``parent_path`` is implemented via ``os.path.dirname`` -- it is pure string
    computation, not sysfs I/O, so no faking is required.

    Args:
        device_paths: Mapping of interface name -> resolved device path string.
            If an interface is absent, ``device_path`` returns ``None``.
        files: Mapping of ``(path, filename)`` -> file content string.
            If a key is absent, ``read_file`` returns ``None``.
        link_names: Mapping of ``(path, link_name)`` -> resolved link name.
            If a key is absent, ``read_link_name`` returns ``None``.
        dirs: Collection of absolute path strings that should be treated as
            existing directories.  Accepts either a ``set`` or a ``frozenset``.
            If a path is absent, ``dir_exists`` returns ``False``.
    """

    def __init__(
        self,
        device_paths: dict[str, str] | None = None,
        files: dict[tuple[str, str], str] | None = None,
        link_names: dict[tuple[str, str], str] | None = None,
        dirs: frozenset[str] | set[str] | None = None,
    ) -> None:
        self._device_paths: dict[str, str] = device_paths or {}
        self._files: dict[tuple[str, str], str] = files or {}
        self._link_names: dict[tuple[str, str], str] = link_names or {}
        self._dirs: frozenset[str] | set[str] = dirs or frozenset()

    def device_path(self, iface: str) -> str | None:
        """Return the resolved sysfs device path for ``iface``, or ``None``."""
        return self._device_paths.get(iface)

    def read_file(self, path: str, filename: str) -> str | None:
        """Return the configured content for ``(path, filename)``, or ``None``."""
        return self._files.get((path, filename))

    def read_link_name(self, path: str, link_name: str) -> str | None:
        """Return the configured link target name, or ``None``."""
        return self._link_names.get((path, link_name))

    def parent_path(self, path: str) -> str | None:
        """Return the parent of ``path``, or ``None`` at root.

        Implemented via ``os.path.dirname`` -- pure string computation,
        not a sysfs operation, so no faking is required.
        """
        parent = os.path.dirname(path)
        if parent == path:
            return None
        return parent

    def dir_exists(self, path: str) -> bool:
        """Return ``True`` if ``path`` is in the configured dirs set."""
        return path in self._dirs


# Single public method by design: the fake mirrors the HttpResponse protocol
# which deliberately exposes only json().
class FakeHttpResponse:  # pylint: disable=too-few-public-methods
    """Test double for ``netcheck.utils.http.HttpResponse``.

    Wraps a pre-configured dict.  ``json()`` always returns that dict without
    raising, mirroring the contract of the real ``HttpResponse`` protocol
    (which is only returned after JSON parsing has already succeeded).

    Args:
        data: The dict to return from ``json()``.

    Example::

        response = FakeHttpResponse({"ip": "1.2.3.4", "org": "AS1 ISP", "country": "DE"})
        assert response.json()["ip"] == "1.2.3.4"
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def json(self) -> dict[str, Any]:
        """Return the pre-configured response dict.

        Returns:
            The dict passed at construction time.
        """
        return self._data


# Single public method by design: the fake mirrors the HttpClient protocol
# which deliberately exposes only get().
class FakeHttpClient:  # pylint: disable=too-few-public-methods
    """Test double for ``netcheck.utils.http.HttpClient``.

    Returns pre-configured ``FakeHttpResponse`` instances or ``None`` for
    specific URLs.  Every call is recorded in ``calls`` for assertion.

    Structurally satisfies the ``HttpClient`` protocol: its ``get`` method
    has an identical signature, so it can be passed wherever an ``HttpClient``
    is expected.

    Args:
        responses: Mapping of URL strings to ``FakeHttpResponse`` instances
                   or ``None``.  A ``None`` value simulates a failed request.

    Example::

        client = FakeHttpClient({
            "https://ipinfo.io/json": FakeHttpResponse(
                {"ip": "1.2.3.4", "org": "AS1 ISP", "country": "DE"}
            ),
            "https://v6.ipinfo.io/json": None,  # simulate IPv6 failure
        })
        assert client.get("https://ipinfo.io/json", 10) is not None
        assert client.get("https://v6.ipinfo.io/json", 10) is None
    """

    def __init__(
        self, responses: dict[str, "FakeHttpResponse | None"]
    ) -> None:
        self._responses = responses
        self.calls: list[tuple[str, int]] = []

    def get(self, url: str, timeout: int) -> "FakeHttpResponse | None":
        """Return the pre-configured response for ``url``, or ``None``.

        Records every call in ``self.calls`` regardless of whether a
        response is configured.

        Args:
            url: URL requested.
            timeout: Timeout value (recorded but not used by the fake).

        Returns:
            The pre-configured ``FakeHttpResponse``, or ``None``.
        """
        self.calls.append((url, timeout))
        return self._responses.get(url)
