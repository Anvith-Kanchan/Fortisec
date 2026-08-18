from fortisec.entropy import entropy_score, is_high_entropy, shannon_entropy
from fortisec.hashes import hash_length, identify_hash, is_probably_hash


def test_identify_hex_hashes() -> None:
    cases = [
        ("a" * 8, ["CRC32"]),
        ("a" * 16, ["CRC64"]),
        ("a" * 32, ["MD5", "NTLM", "LM"]),
        ("a" * 40, ["SHA1", "RIPEMD160"]),
        ("a" * 56, ["SHA224"]),
        ("a" * 64, ["SHA256"]),
        ("a" * 96, ["SHA384"]),
        ("a" * 128, ["SHA512"]),
    ]
    for value, expected in cases:
        assert identify_hash(value) == expected


def test_identify_special_hashes() -> None:
    assert identify_hash("$2b$12$" + ("a" * 53)) == ["bcrypt"]
    assert identify_hash("$argon2id$v=19$m=65536,t=3,p=4$abc$def") == ["Argon2"]
    assert identify_hash("$scrypt$ln=16,r=8,p=1$salt$hash") == ["scrypt"]
    assert identify_hash("pbkdf2:sha256:260000$salt$hash") == ["PBKDF2"]


def test_unknown_hashes() -> None:
    cases = ["", "not-a-hash", "z" * 32, "12345", "hello world"]
    assert all(identify_hash(case) == [] for case in cases)


def test_is_probably_hash() -> None:
    assert is_probably_hash("a" * 64)
    assert not is_probably_hash("plain-text")


def test_hash_length() -> None:
    assert hash_length(" abc ") == 3
    assert hash_length("") == 0
    assert hash_length(123) == 0  # type: ignore[arg-type]


def test_shannon_entropy_basic_values() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert round(shannon_entropy("abcd"), 2) == 2.0


def test_entropy_score_range() -> None:
    for value in ["", "aaaa", "abcd", "aB3$xY9!pQ2#zR8"]:
        score = entropy_score(value)
        assert 0.0 <= score <= 1.0


def test_high_entropy_detection() -> None:
    assert is_high_entropy("aB3$xY9!pQ2#zR8@mN5&kL0")
    assert not is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")
    assert not is_high_entropy("short")

