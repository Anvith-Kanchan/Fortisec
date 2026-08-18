"""HTTP security header scanner."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .constants import SECURITY_HEADERS
from .exceptions import HeaderScanError


@dataclass(frozen=True)
class HeaderScanResult:
    """Result returned by :func:`scan_headers`."""

    url: str
    score: int
    missing: list[str]
    present: list[str]
    headers: dict[str, str]

    def to_json(self) -> str:
        """Serialize the result to JSON.

        Args:
            None.

        Returns:
            JSON string for this scan result.

        Raises:
            TypeError: If serialization fails.

        Examples:
            >>> HeaderScanResult("https://e.test", 0, [], [], {}).to_json()
            '{"url": "https://e.test", "score": 0, "missing": [], "present": [], "headers": {}}'
        """
        return json.dumps(asdict(self))

    def pretty_print(self) -> str:
        """Return a human-readable scan summary.

        Args:
            None.

        Returns:
            Multi-line text summary.

        Raises:
            This method does not raise for invalid scan data.

        Examples:
            >>> "Score" in HeaderScanResult("u", 100, [], [], {}).pretty_print()
            True
        """
        present = ", ".join(self.present) if self.present else "None"
        missing = ", ".join(self.missing) if self.missing else "None"
        return f"URL: {self.url}\nScore: {self.score}/100\nPresent: {present}\nMissing: {missing}"


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
        parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HeaderScanError(f"invalid URL: {url}")
    return url


def scan_headers(url: str, *, timeout: float = 10.0) -> HeaderScanResult:
    """Download and evaluate HTTP security headers.

    Args:
        url: URL to scan. URLs without a scheme default to HTTPS.
        timeout: Network timeout in seconds.

    Returns:
        HeaderScanResult containing score, present headers, missing headers, and raw headers.

    Raises:
        HeaderScanError: If the URL is invalid or headers cannot be downloaded.

    Examples:
        >>> isinstance(HeaderScanResult("https://example.com", 0, [], [], {}), HeaderScanResult)
        True
    """
    if not isinstance(url, str) or not url.strip():
        raise HeaderScanError("url must be a non-empty string")
    normalized_url = _normalize_url(url.strip())
    request = Request(normalized_url, method="HEAD", headers={"User-Agent": "fortisec/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            headers = dict(response.headers.items())
    except HTTPError as exc:
        headers = dict(exc.headers.items()) if exc.headers else {}
        if not headers:
            raise HeaderScanError(f"failed to scan headers: {exc}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise HeaderScanError(f"failed to scan headers: {exc}") from exc

    lower_headers = {key.lower(): value for key, value in headers.items()}
    present = [name for name in SECURITY_HEADERS if name.lower() in lower_headers]
    missing = [name for name in SECURITY_HEADERS if name.lower() not in lower_headers]
    score = round((len(present) / len(SECURITY_HEADERS)) * 100)
    return HeaderScanResult(
        url=normalized_url,
        score=score,
        missing=missing,
        present=present,
        headers=headers,
    )

