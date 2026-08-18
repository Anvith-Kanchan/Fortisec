from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from fortisec.exceptions import HeaderScanError
from fortisec.headers import HeaderScanResult, scan_headers


class FakeResponse:
    def __init__(self, headers: dict[str, str]) -> None:
        message = Message()
        for key, value in headers.items():
            message[key] = value
        self.headers = message

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_header_scan_result_json_and_pretty() -> None:
    result = HeaderScanResult("https://example.com", 100, [], ["X"], {"X": "1"})
    assert '"score": 100' in result.to_json()
    assert "Score: 100/100" in result.pretty_print()


def test_scan_headers_scores_present_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        assert timeout == 10.0
        return FakeResponse(
            {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
            }
        )

    monkeypatch.setattr("fortisec.headers.urlopen", fake_urlopen)
    result = scan_headers("example.com")
    assert result.url == "https://example.com"
    assert result.score == 33
    assert "Strict-Transport-Security" in result.present
    assert "Permissions-Policy" in result.missing


def test_scan_headers_invalid_url() -> None:
    with pytest.raises(HeaderScanError):
        scan_headers("http://")


def test_scan_headers_empty_url() -> None:
    with pytest.raises(HeaderScanError):
        scan_headers("")


def test_scan_headers_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        raise URLError("boom")

    monkeypatch.setattr("fortisec.headers.urlopen", fake_urlopen)
    with pytest.raises(HeaderScanError):
        scan_headers("https://example.com")


def test_scan_headers_uses_http_error_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        message = Message()
        message["X-Content-Type-Options"] = "nosniff"
        raise HTTPError("https://example.com", 403, "Forbidden", message, None)

    monkeypatch.setattr("fortisec.headers.urlopen", fake_urlopen)
    result = scan_headers("https://example.com")
    assert result.score == 11
    assert result.headers["X-Content-Type-Options"] == "nosniff"


def test_scan_headers_http_error_without_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        raise HTTPError("https://example.com", 500, "Server Error", None, None)

    monkeypatch.setattr("fortisec.headers.urlopen", fake_urlopen)
    with pytest.raises(HeaderScanError):
        scan_headers("https://example.com")

