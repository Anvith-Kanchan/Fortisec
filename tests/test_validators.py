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


def test_valid_emails() -> None:
    cases = [
        "admin@example.com",
        "first.last@example.co.uk",
        "name+tag@example.io",
        "a@b.co",
        "user_123@sub.example.org",
    ]
    assert all(validate_email(case) for case in cases)


def test_invalid_emails() -> None:
    cases = [
        "",
        "plain",
        "@example.com",
        "user@",
        "user@example",
        "user@example..com",
        "user@-example.com",
        "user@example-.com",
        "x" * 65 + "@example.com",
    ]
    assert not any(validate_email(case) for case in cases)


def test_valid_ipv4() -> None:
    cases = ["0.0.0.0", "1.2.3.4", "127.0.0.1", "192.168.1.1", "255.255.255.255"]
    assert all(validate_ipv4(case) for case in cases)


def test_invalid_ipv4() -> None:
    cases = [
        "",
        "999.999.999.999",
        "192.168.1.300",
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "abc.def.ghi.jkl",
        "2001:db8::1",
    ]
    assert not any(validate_ipv4(case) for case in cases)


def test_valid_ipv6() -> None:
    cases = ["::1", "2001:db8::1", "fe80::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"]
    assert all(validate_ipv6(case) for case in cases)


def test_invalid_ipv6() -> None:
    cases = ["", "127.0.0.1", "2001:::1", "gggg::1", "1:2:3:4:5:6:7:8:9"]
    assert not any(validate_ipv6(case) for case in cases)


def test_validate_ip_accepts_both_versions() -> None:
    assert validate_ip("192.168.0.1")
    assert validate_ip("2001:db8::1")
    assert not validate_ip("999.999.999.999")


def test_valid_domains() -> None:
    cases = ["example.com", "sub.example.co.uk", "xn--example.com", "a-b.example"]
    assert all(validate_domain(case) for case in cases)


def test_invalid_domains() -> None:
    cases = ["", "localhost", "abc..com", "-abc.com", "abc-.com", "abc.com-", "a" * 64 + ".com"]
    assert not any(validate_domain(case) for case in cases)


def test_valid_hostnames() -> None:
    cases = ["localhost", "api-01", "sub.example.com", "a"]
    assert all(validate_hostname(case) for case in cases)


def test_invalid_hostnames() -> None:
    cases = ["", "abc..com", "-host", "host-", "a" * 64]
    assert not any(validate_hostname(case) for case in cases)


def test_valid_urls() -> None:
    cases = [
        "https://example.com",
        "http://localhost:8080/path",
        "ftp://example.com/file",
        "https://127.0.0.1:443",
        "https://[2001:db8::1]/",
    ]
    assert all(validate_url(case) for case in cases)


def test_invalid_urls() -> None:
    cases = ["", "http://", "mailto:user@example.com", "https://example.com:99999", "example.com"]
    assert not any(validate_url(case) for case in cases)


def test_valid_cidrs() -> None:
    cases = ["192.168.0.0/24", "10.0.0.0/8", "2001:db8::/32", "127.0.0.1/32"]
    assert all(validate_cidr(case) for case in cases)


def test_invalid_cidrs() -> None:
    cases = ["", "192.168.0.0", "192.168.0.0/33", "2001:db8::/129", "999.1.1.1/24"]
    assert not any(validate_cidr(case) for case in cases)


def test_valid_ports() -> None:
    cases = [1, 80, 443, 65535, "8080"]
    assert all(validate_port(case) for case in cases)


def test_invalid_ports() -> None:
    cases = [0, -1, 65536, "99999", "abc", "", True]
    assert not any(validate_port(case) for case in cases)


def test_non_string_inputs_are_invalid() -> None:
    assert not validate_email(123)  # type: ignore[arg-type]
    assert not validate_ipv4(123)  # type: ignore[arg-type]
    assert not validate_ipv6(123)  # type: ignore[arg-type]
    assert not validate_domain(123)  # type: ignore[arg-type]
    assert not validate_hostname(123)  # type: ignore[arg-type]
    assert not validate_url(123)  # type: ignore[arg-type]
    assert not validate_cidr(123)  # type: ignore[arg-type]
    assert not validate_port(object())  # type: ignore[arg-type]


def test_url_rejects_invalid_port_value() -> None:
    assert not validate_url("https://example.com:bad")

