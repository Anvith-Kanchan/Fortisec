from fortisec.cli import main
from fortisec.headers import HeaderScanResult


def test_cli_validate_email_valid(capsys: object) -> None:
    assert main(["validate-email", "admin@example.com"]) == 0
    captured = capsys.readouterr()
    assert "Valid" in captured.out


def test_cli_validate_email_invalid(capsys: object) -> None:
    assert main(["validate-email", "bad"]) == 1
    captured = capsys.readouterr()
    assert "Invalid" in captured.out


def test_cli_validate_url_valid(capsys: object) -> None:
    assert main(["validate-url", "https://example.com"]) == 0
    captured = capsys.readouterr()
    assert "Valid" in captured.out


def test_cli_hash_known(capsys: object) -> None:
    assert main(["hash", "d41d8cd98f00b204e9800998ecf8427e"]) == 0
    captured = capsys.readouterr()
    assert "MD5" in captured.out


def test_cli_hash_unknown(capsys: object) -> None:
    assert main(["hash", "not-a-hash"]) == 1
    captured = capsys.readouterr()
    assert "Unknown" in captured.out


def test_cli_redact(capsys: object) -> None:
    assert main(["redact", "Authorization: Bearer token admin@example.com"]) == 0
    captured = capsys.readouterr()
    assert "Bearer ********" in captured.out
    assert "admin@example.com" not in captured.out


def test_cli_headers(monkeypatch: object, capsys: object) -> None:
    def fake_scan_headers(url: str, *, timeout: float) -> HeaderScanResult:
        assert url == "https://example.com"
        assert timeout == 1.0
        return HeaderScanResult(
            url=url,
            score=50,
            present=["Strict-Transport-Security"],
            missing=["Content-Security-Policy"],
            headers={},
        )

    monkeypatch.setattr("fortisec.cli.scan_headers", fake_scan_headers)
    assert main(["headers", "https://example.com", "--timeout", "1"]) == 0
    captured = capsys.readouterr()
    assert "Security Score: 50/100" in captured.out
    assert "Recommendation: Add a Content-Security-Policy header." in captured.out

