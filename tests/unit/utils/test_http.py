"""Unit tests for netcheck.utils.http.

``SystemHttpClient`` calls ``requests.get`` directly.  We use
``unittest.mock.patch`` here -- it is the only module in the test suite that
does so, and only because ``SystemHttpClient`` is the thin production adapter
whose job is exactly to wrap ``requests``.

``_RequestsResponse`` wraps a pre-parsed dict and is tested directly.
``FakeHttpClient`` / ``FakeHttpResponse`` (in tests/fakes.py) are used
everywhere else -- they exist so that callers of ``HttpClient`` never need
mocking at all.

Test groups
-----------
TestRequestsResponse      -- _RequestsResponse.json() returns the cached dict.
TestSystemHttpClientGet   -- get() returns HttpResponse on success, None on failure.
TestSystemHttpClientRetry -- retry loop: returns on first success, exhausts attempts.
"""

from unittest.mock import MagicMock, patch

import requests

from netcheck.utils.http import SystemHttpClient, _RequestsResponse


# ---------------------------------------------------------------------------
# TestRequestsResponse
# ---------------------------------------------------------------------------


class TestRequestsResponse:
    """Tests for _RequestsResponse."""

    def test_json_returns_data(self) -> None:
        """json() must return the dict passed at construction."""
        data = {"ip": "1.2.3.4", "org": "AS1 Test", "country": "DE"}
        response = _RequestsResponse(data)
        assert response.json() == data

    def test_json_returns_same_object(self) -> None:
        """json() must return the identical dict object (no copy)."""
        data = {"ip": "1.2.3.4"}
        response = _RequestsResponse(data)
        assert response.json() is data

    def test_json_idempotent(self) -> None:
        """Calling json() twice must return equal results."""
        data = {"ip": "1.2.3.4"}
        response = _RequestsResponse(data)
        assert response.json() == response.json()


# ---------------------------------------------------------------------------
# TestSystemHttpClientGet
# ---------------------------------------------------------------------------


class TestSystemHttpClientGet:
    """Tests for SystemHttpClient.get() -- success and single-attempt failure."""

    def test_successful_request_returns_response(self) -> None:
        """A 200 response with valid JSON must return an HttpResponse."""
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.json.return_value = {"ip": "1.2.3.4", "org": "AS1", "country": "DE"}
        with patch("requests.get", return_value=mock_resp):
            client = SystemHttpClient(attempts=1)
            result = client.get("https://example.com", 10)
        assert result is not None
        assert result.json()["ip"] == "1.2.3.4"

    def test_network_error_returns_none(self) -> None:
        """A RequestException must return None."""
        with patch("requests.get", side_effect=requests.ConnectionError("down")):
            client = SystemHttpClient(attempts=1)
            result = client.get("https://example.com", 10)
        assert result is None

    def test_timeout_returns_none(self) -> None:
        """A Timeout must return None."""
        with patch("requests.get", side_effect=requests.Timeout("timeout")):
            client = SystemHttpClient(attempts=1)
            result = client.get("https://example.com", 10)
        assert result is None

    def test_http_error_status_returns_none(self) -> None:
        """A non-2xx HTTP response (raise_for_status raises) must return None."""
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.raise_for_status.side_effect = requests.HTTPError("404")
        with patch("requests.get", return_value=mock_resp):
            client = SystemHttpClient(attempts=1)
            result = client.get("https://example.com", 10)
        assert result is None

    def test_invalid_json_returns_none(self) -> None:
        """A response whose .json() raises ValueError must return None."""
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = ValueError("not JSON")
        with patch("requests.get", return_value=mock_resp):
            client = SystemHttpClient(attempts=1)
            result = client.get("https://example.com", 10)
        assert result is None

    def test_correct_url_and_timeout_passed(self) -> None:
        """requests.get must be called with the supplied url and timeout."""
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.json.return_value = {"ip": "1.2.3.4"}
        with patch("requests.get", return_value=mock_resp) as mock_get:
            client = SystemHttpClient(attempts=1)
            client.get("https://ipinfo.io/json", 10)
        mock_get.assert_called_once_with("https://ipinfo.io/json", timeout=10)


# ---------------------------------------------------------------------------
# TestSystemHttpClientRetry
# ---------------------------------------------------------------------------


class TestSystemHttpClientRetry:
    """Tests for SystemHttpClient retry logic."""

    def test_returns_on_first_success(self) -> None:
        """get() must return immediately on a successful first attempt."""
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.json.return_value = {"ip": "1.2.3.4"}
        with patch("requests.get", return_value=mock_resp) as mock_get:
            client = SystemHttpClient(attempts=3)
            result = client.get("https://example.com", 10)
        assert result is not None
        assert mock_get.call_count == 1

    def test_retries_on_failure_then_succeeds(self) -> None:
        """get() must retry and return on a later successful attempt."""
        fail = requests.ConnectionError("down")
        success = MagicMock()
        success.__enter__.return_value = success
        success.json.return_value = {"ip": "1.2.3.4"}
        with patch(
            "requests.get",
            side_effect=[fail, success],
        ) as mock_get:
            with patch("time.sleep"):  # don't actually sleep in tests
                client = SystemHttpClient(attempts=3, backoff=0.0)
                result = client.get("https://example.com", 10)
        assert result is not None
        assert mock_get.call_count == 2

    def test_exhausts_all_attempts_on_persistent_failure(self) -> None:
        """get() must return None after all attempts fail."""
        with patch(
            "requests.get",
            side_effect=requests.ConnectionError("down"),
        ) as mock_get:
            with patch("time.sleep"):
                client = SystemHttpClient(attempts=3, backoff=0.0)
                result = client.get("https://example.com", 10)
        assert result is None
        assert mock_get.call_count == 3

    def test_no_sleep_after_last_attempt(self) -> None:
        """time.sleep must not be called after the final failed attempt."""
        with patch("requests.get", side_effect=requests.ConnectionError("down")):
            with patch("time.sleep") as mock_sleep:
                client = SystemHttpClient(attempts=3, backoff=1.0)
                client.get("https://example.com", 10)
        # 3 attempts -> 2 sleeps (between attempt 1-2 and 2-3)
        assert mock_sleep.call_count == 2

    def test_custom_attempts_honoured(self) -> None:
        """The attempts parameter must control the exact number of tries."""
        with patch(
            "requests.get",
            side_effect=requests.ConnectionError("down"),
        ) as mock_get:
            with patch("time.sleep"):
                client = SystemHttpClient(attempts=5, backoff=0.0)
                client.get("https://example.com", 10)
        assert mock_get.call_count == 5
