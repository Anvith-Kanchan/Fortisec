"""Hash identification helpers."""

from __future__ import annotations

import re

_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")
_ARGON2_RE = re.compile(r"^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$")
_SCRYPT_RE = re.compile(r"^\$(?:scrypt|7)\$")
_PBKDF2_RE = re.compile(r"^(?:pbkdf2[:$-]|sha\d+[:$-]\d+[:$-])", re.IGNORECASE)

_HEX_LENGTHS: dict[int, list[str]] = {
    8: ["CRC32"],
    16: ["CRC64"],
    32: ["MD5", "NTLM", "LM"],
    40: ["SHA1", "RIPEMD160"],
    56: ["SHA224"],
    64: ["SHA256"],
    96: ["SHA384"],
    128: ["SHA512"],
}


def identify_hash(hash_string: str) -> list[str]:
    """Identify possible hash algorithms from a hash string.

    Args:
        hash_string: Hash string to inspect.

    Returns:
        A list of possible hash names. Returns an empty list when unknown.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> identify_hash("d41d8cd98f00b204e9800998ecf8427e")
        ['MD5', 'NTLM', 'LM']
    """
    if not isinstance(hash_string, str):
        return []
    value = hash_string.strip()
    if not value:
        return []
    if _BCRYPT_RE.fullmatch(value):
        return ["bcrypt"]
    if _ARGON2_RE.match(value):
        return ["Argon2"]
    if _SCRYPT_RE.match(value):
        return ["scrypt"]
    if _PBKDF2_RE.match(value):
        return ["PBKDF2"]
    if _HEX_RE.fullmatch(value):
        return _HEX_LENGTHS.get(len(value), []).copy()
    return []


def is_probably_hash(text: str) -> bool:
    """Return whether text resembles a known hash format.

    Args:
        text: Text to inspect.

    Returns:
        True when the text matches a known hash shape, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> is_probably_hash("a" * 64)
        True
    """
    return bool(identify_hash(text))


def hash_length(hash_string: str) -> int:
    """Return the length of a hash string after trimming whitespace.

    Args:
        hash_string: Hash string to measure.

    Returns:
        Length of the stripped hash string. Non-string values return 0.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> hash_length(" abc ")
        3
    """
    if not isinstance(hash_string, str):
        return 0
    return len(hash_string.strip())

