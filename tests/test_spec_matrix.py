import pytest

from fortisec.hashes import identify_hash
from fortisec.redact import redact_logs
from fortisec.validators import (
    validate_cidr,
    validate_domain,
    validate_email,
    validate_hostname,
    validate_ip,
    validate_ipv4,
    validate_ipv6,
    validate_port,
    validate_url,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("admin@example.com", True),
        ("security.engineer@example.io", True),
        ("dev+sec@example.co", True),
        ("x@y.dev", True),
        ("unicode-é@example.com", False),
        ("name@example", False),
        ("name@", False),
        ("@example.com", False),
        ("name example@example.com", False),
        ("name@example..com", False),
        ("name@.example.com", False),
        ("name@example.c", False),
    ],
)
def test_email_matrix(value: str, expected: bool) -> None:
    assert validate_email(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.1.1", True),
        ("8.8.8.8", True),
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("255.255.255.255", True),
        ("256.1.1.1", False),
        ("999.999.999.999", False),
        ("192.168.1.300", False),
        ("01.02.03.04", False),
        ("1.1.1", False),
        ("1.1.1.1.1", False),
        ("", False),
    ],
)
def test_ipv4_matrix(value: str, expected: bool) -> None:
    assert validate_ipv4(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("::1", True),
        ("2001:db8::1", True),
        ("fe80::1", True),
        ("::", True),
        ("2001:4860:4860::8888", True),
        ("2001:::1", False),
        ("gggg::1", False),
        ("1:2:3:4:5:6:7:8:9", False),
        ("192.168.1.1", False),
        ("", False),
    ],
)
def test_ipv6_matrix(value: str, expected: bool) -> None:
    assert validate_ipv6(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", True),
        ("sub.example.com", True),
        ("a-b.example.dev", True),
        ("example.org.", True),
        ("abc..com", False),
        ("localhost", False),
        ("-example.com", False),
        ("example-.com", False),
        ("example.com-", False),
        ("", False),
    ],
)
def test_domain_matrix(value: str, expected: bool) -> None:
    assert validate_domain(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("localhost", True),
        ("api", True),
        ("api-01", True),
        ("sub.example.com", True),
        ("host.", True),
        ("-host", False),
        ("host-", False),
        ("host..name", False),
        ("", False),
        ("bad_host", False),
    ],
)
def test_hostname_matrix(value: str, expected: bool) -> None:
    assert validate_hostname(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com", True),
        ("http://example.com/path?x=1", True),
        ("ftp://files.example.com/pub", True),
        ("https://localhost:8443", True),
        ("https://[::1]:443", True),
        ("http://", False),
        ("https://example.com:99999", False),
        ("javascript:alert(1)", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_url_matrix(value: str, expected: bool) -> None:
    assert validate_url(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.0/8", True),
        ("192.168.1.0/24", True),
        ("0.0.0.0/0", True),
        ("2001:db8::/32", True),
        ("::1/128", True),
        ("192.168.1.0/33", False),
        ("2001:db8::/129", False),
        ("999.1.1.1/24", False),
        ("192.168.1.1", False),
        ("", False),
    ],
)
def test_cidr_matrix(value: str, expected: bool) -> None:
    assert validate_cidr(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, True),
        (22, True),
        (80, True),
        (443, True),
        (65535, True),
        ("1", True),
        ("65535", True),
        (0, False),
        (65536, False),
        ("99999", False),
        ("abc", False),
        (True, False),
    ],
)
def test_port_matrix(value: int | str | bool, expected: bool) -> None:
    assert validate_port(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("2001:db8::1", True),
        ("8.8.8.8", True),
        ("999.999.999.999", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_ip_matrix(value: str, expected: bool) -> None:
    assert validate_ip(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a" * 8, ["CRC32"]),
        ("A" * 16, ["CRC64"]),
        ("f" * 32, ["MD5", "NTLM", "LM"]),
        ("0" * 40, ["SHA1", "RIPEMD160"]),
        ("1" * 56, ["SHA224"]),
        ("2" * 64, ["SHA256"]),
        ("3" * 96, ["SHA384"]),
        ("4" * 128, ["SHA512"]),
        ("x" * 64, []),
        ("", []),
    ],
)
def test_hash_matrix(value: str, expected: list[str]) -> None:
    assert identify_hash(value) == expected


@pytest.mark.parametrize(
    "text",
    [
        "admin@example.com",
        "Authorization: Bearer abcdef123456",
        "AKIAABCDEFGHIJKLMNOP",
        "ghp_" + ("A" * 36),
        "sk-" + ("a" * 30),
        "AIza" + ("A" * 35),
        "4111111111111111",
        "192.168.1.1",
        "2001:db8::1",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
    ],
)
def test_redaction_matrix(text: str) -> None:
    assert redact_logs(text) == "********" or "********" in redact_logs(text)

