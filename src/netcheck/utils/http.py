"""HTTP client protocol and production implementation for netcheck.

Provides:
- ``HttpResponse``: Protocol for a successfully parsed HTTP response.
  Callers receive this only when the request succeeded and the body was
  valid JSON.  Its sole operation is ``json()``, which always returns the
  parsed dict without raising.
- ``HttpClient``: Protocol for injectable HTTP access.  Returns
  ``HttpResponse | None`` where ``None`` represents any failure (network
  error, timeout, non-2xx status, or invalid JSON).  This mirrors the
  ``CommandRunner`` convention exactly.
- ``SystemHttpClient``: Production implementation backed by ``requests``.
  Retries with exponential backoff (configurable).  All error handling is
  internal; callers always receive a clean ``HttpResponse`` or ``None``.

Rationale
---------
Patching ``requests.get`` at the test boundary is the same architectural
shortcut as patching ``subprocess.run``.  An ``HttpClient`` protocol makes
the HTTP dependency explicit in every function signature, enables lightweight
``FakeHttpClient`` test doubles, and eliminates all ``unittest.mock`` usage
from the egress module tests.

``HttpResponse`` as a protocol
-------------------------------
``requests.Response`` has dozens of methods and properties; importing it in
the egress module's type annotations would couple the entire module to the
``requests`` library.  A minimal protocol with only ``json()`` decouples the
module from the library while keeping the type fully checkable.

``FakeHttpResponse`` in ``tests/fakes.py`` satisfies this protocol with a
plain dict wrapper -- no subclassing of ``requests.Response`` required.
"""

import time
from typing import Any, Protocol

import requests


# Single-method protocol by design: the contract exposes exactly one
# operation.  Callers depend only on json(); everything else is hidden.
class HttpResponse(Protocol):  # pylint: disable=too-few-public-methods
    """Protocol for a successfully parsed HTTP JSON response.

    Satisfied by any object that has a ``json()`` method returning a
    ``dict[str, object]``.  The method must not raise -- by the time an
    ``HttpResponse`` is returned to a caller, JSON parsing has already
    succeeded inside the client.
    """

    def json(self) -> dict[str, Any]:
        """Return the parsed JSON body as a dictionary.

        Returns:
            The response body deserialized as a ``dict``.  Never raises.
        """


# Single-method protocol by design: the contract exposes exactly one
# operation.  Retry logic and error handling are implementation details
# of the concrete class and must not leak into the protocol.
class HttpClient(Protocol):  # pylint: disable=too-few-public-methods
    """Protocol for making HTTP GET requests.

    Returns ``HttpResponse | None`` where ``None`` signals any failure.
    Callers never need to handle exceptions from this protocol.

    The retry policy, timeout behaviour, and error handling are
    implementation details of the concrete class; the protocol exposes
    only the observable result.
    """

    def get(self, url: str, timeout: int) -> "HttpResponse | None":
        """Perform an HTTP GET and return the response or ``None``.

        Args:
            url: URL to request.
            timeout: Maximum seconds to wait for a response.

        Returns:
            ``HttpResponse`` if the request succeeded (2xx status, valid
            JSON body), ``None`` for any other outcome.
        """


# Single public method by design: this adapter wraps a pre-parsed dict and
# exposes it via the HttpResponse protocol.  No other public surface needed.
class _RequestsResponse:  # pylint: disable=too-few-public-methods
    """Thin wrapper that adapts ``requests.Response`` to ``HttpResponse``.

    The ``json()`` call on this object will never raise because
    ``SystemHttpClient`` only constructs this wrapper after confirming that
    ``response.json()`` succeeded during the request attempt.

    The parsed dict is cached at construction time so that subsequent calls
    to ``json()`` return the same object without re-parsing.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def json(self) -> dict[str, Any]:
        """Return the cached parsed response body.

        Returns:
            The pre-parsed response dict.
        """
        return self._data


# Single public method by design: ``get`` is the entire public contract.
# ``_single_attempt`` is an internal decomposition detail.
class SystemHttpClient:  # pylint: disable=too-few-public-methods
    """Production ``HttpClient`` backed by ``requests``.

    Makes GET requests with configurable retry and exponential backoff.
    All failures (network errors, timeouts, non-2xx responses, invalid JSON)
    are caught internally and result in ``None`` being returned.

    Args:
        attempts: Maximum number of request attempts (default: 3).
        backoff: Backoff multiplier.  Sleep between attempt n and n+1
                 is ``backoff * 2**n`` seconds (default: 1.0).
    """

    def __init__(self, attempts: int = 3, backoff: float = 1.0) -> None:
        self._attempts = attempts
        self._backoff = backoff

    def get(self, url: str, timeout: int) -> HttpResponse | None:
        """Perform an HTTP GET with retry and exponential backoff.

        Args:
            url: URL to request.
            timeout: Maximum seconds to wait per attempt.

        Returns:
            ``HttpResponse`` with the parsed JSON body on success,
            ``None`` if all attempts fail or the response is not valid JSON.
        """
        for attempt in range(self._attempts):
            result = self._single_attempt(url, timeout)
            if result is not None:
                return result
            if attempt < self._attempts - 1:
                time.sleep(self._backoff * (2**attempt))
        return None

    def _single_attempt(self, url: str, timeout: int) -> HttpResponse | None:
        """Perform one HTTP GET attempt.

        Args:
            url: URL to request.
            timeout: Request timeout in seconds.

        Returns:
            ``HttpResponse`` on success, ``None`` on any failure.
        """
        try:
            with requests.get(url, timeout=timeout) as response:
                response.raise_for_status()
                data: dict[str, Any] = response.json()
                return _RequestsResponse(data)
        except requests.RequestException:
            return None
        except (ValueError, KeyError):
            # ValueError covers json.JSONDecodeError (subclass)
            return None
