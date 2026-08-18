import fortisec
from fortisec import (
    identify_hash,
    redact_logs,
    safe_join,
    scan_headers,
    shannon_entropy,
    validate_email,
)


def test_public_api_exports_selected_helpers() -> None:
    assert validate_email("admin@example.com")
    assert identify_hash("a" * 64) == ["SHA256"]
    assert redact_logs("email admin@example.com") == "email ********"
    assert shannon_entropy("aaaa") == 0.0
    assert callable(scan_headers)
    assert callable(safe_join)


def test_version_exists() -> None:
    assert fortisec.__version__ == "0.1.2"

