import re

from fortisec.redact import redact_logs


def test_redacts_bearer_token() -> None:
    assert redact_logs("Authorization: Bearer abc.def.ghi", placeholder="***") == (
        "Authorization: Bearer ***"
    )


def test_redacts_jwt() -> None:
    text = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
    assert "eyJ" not in redact_logs(text)


def test_redacts_aws_access_key() -> None:
    access_key = "A" + "KIA" + "ABCDEFGHIJKLMNOP"
    assert access_key not in redact_logs(f"key={access_key}")


def test_redacts_aws_secret_key_assignment() -> None:
    secret = "abc" + "defghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
    text = f"credential_value = {secret}"
    redacted = redact_logs(text, placeholder="***")
    assert redacted == "credential_value = ***"


def test_redacts_github_pat() -> None:
    text = "token ghp_" + ("A" * 36)
    assert "ghp_" not in redact_logs(text)


def test_redacts_openai_key() -> None:
    assert "sk-" not in redact_logs("sk-proj-" + ("a" * 30))


def test_redacts_google_api_key() -> None:
    assert "AIza" not in redact_logs("AIza" + ("A" * 35))


def test_redacts_email() -> None:
    assert "admin@example.com" not in redact_logs("email admin@example.com")


def test_redacts_credit_card() -> None:
    assert "4111" not in redact_logs("card 4111 1111 1111 1111")


def test_redacts_ipv4_by_default() -> None:
    assert "192.168.1.1" not in redact_logs("ip 192.168.1.1")


def test_can_keep_ipv4() -> None:
    assert "192.168.1.1" in redact_logs("ip 192.168.1.1", redact_ip=False)


def test_redacts_ipv6() -> None:
    assert "2001:db8::1" not in redact_logs("ip 2001:db8::1")


def test_custom_pattern_string() -> None:
    assert "customer-123" not in redact_logs("id customer-123", custom_patterns=[r"customer-\d+"])


def test_custom_pattern_compiled() -> None:
    assert "ticket-123" not in redact_logs(
        "id ticket-123", custom_patterns=[re.compile(r"ticket-\d+")]
    )


def test_non_string_input_is_converted() -> None:
    assert redact_logs(123) == "123"  # type: ignore[arg-type]

