"""Validation helpers for common network and web values."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

_EMAIL_RE = re.compile(
    r"^(?=.{1,254}$)(?=.{1,64}@)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class ValidationResult:
    """Detailed validation result for callers that need an explanation."""

    valid: bool
    value: str
    reason: str | None = None


def validate_email(email: str) -> bool:
    """Validate an email address.

    Args:
        email: Email address to validate.

    Returns:
        True when the email has a valid practical format, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_email("admin@example.com")
        True
    """
    if not isinstance(email, str):
        return False
    return bool(_EMAIL_RE.fullmatch(email.strip()))


def validate_ipv4(ip: str) -> bool:
    """Validate an IPv4 address.

    Args:
        ip: IPv4 address to validate.

    Returns:
        True for a syntactically valid IPv4 address, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_ipv4("192.168.1.1")
        True
    """
    if not isinstance(ip, str):
        return False
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def validate_ipv6(ip: str) -> bool:
    """Validate an IPv6 address.

    Args:
        ip: IPv6 address to validate.

    Returns:
        True for a syntactically valid IPv6 address, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_ipv6("2001:db8::1")
        True
    """
    if not isinstance(ip, str):
        return False
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def validate_ip(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address to validate.

    Returns:
        True for valid IPv4 or IPv6 addresses, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_ip("127.0.0.1")
        True
    """
    return validate_ipv4(ip) or validate_ipv6(ip)


def validate_domain(domain: str) -> bool:
    """Validate a DNS domain name.

    Args:
        domain: Domain name to validate.

    Returns:
        True when the domain is syntactically valid, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_domain("example.com")
        True
    """
    if not isinstance(domain, str):
        return False
    value = domain.strip().rstrip(".")
    if not value or len(value) > 253 or ".." in value or "." not in value:
        return False
    labels = value.split(".")
    if any(not label for label in labels):
        return False
    return all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def validate_hostname(hostname: str) -> bool:
    """Validate a hostname.

    Args:
        hostname: Hostname to validate.

    Returns:
        True when the hostname is syntactically valid, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_hostname("api-01")
        True
    """
    if not isinstance(hostname, str):
        return False
    value = hostname.strip().rstrip(".")
    if not value or len(value) > 253 or ".." in value:
        return False
    return all(_HOST_LABEL_RE.fullmatch(label) for label in value.split("."))


def validate_url(url: str) -> bool:
    """Validate an HTTP, HTTPS, or FTP URL.

    Args:
        url: URL to validate.

    Returns:
        True when the URL contains a supported scheme and valid host, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_url("https://example.com/path")
        True
    """
    if not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https", "ftp"} or not parsed.netloc:
        return False
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if not host or (port is not None and not validate_port(port)):
        return False
    return validate_ip(host) or validate_domain(host) or validate_hostname(host)


def validate_cidr(cidr: str) -> bool:
    """Validate an IPv4 or IPv6 CIDR network.

    Args:
        cidr: CIDR network to validate.

    Returns:
        True when the CIDR network is valid, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_cidr("10.0.0.0/8")
        True
    """
    if not isinstance(cidr, str):
        return False
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return "/" in cidr


def validate_port(port: int | str) -> bool:
    """Validate a TCP or UDP port number.

    Args:
        port: Port number as an integer or digit-only string.

    Returns:
        True when the port is between 1 and 65535, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> validate_port(443)
        True
    """
    if isinstance(port, bool):
        return False
    if isinstance(port, str):
        if not port.isdigit():
            return False
        port_number = int(port)
    elif isinstance(port, int):
        port_number = port
    else:
        return False
    return 1 <= port_number <= 65535

