"""fortisec: lightweight security utilities for Python."""

from .entropy import EntropyResult, entropy_score, is_high_entropy, shannon_entropy
from .hashes import hash_length, identify_hash, is_probably_hash
from .headers import HeaderScanResult, scan_headers
from .paths import is_safe_path, normalize_path, safe_join
from .redact import redact_logs
from .validators import (
    ValidationResult,
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

__version__ = "0.1.2"

__all__ = [
    "EntropyResult",
    "HeaderScanResult",
    "ValidationResult",
    "entropy_score",
    "hash_length",
    "identify_hash",
    "is_high_entropy",
    "is_probably_hash",
    "is_safe_path",
    "normalize_path",
    "redact_logs",
    "safe_join",
    "scan_headers",
    "shannon_entropy",
    "validate_cidr",
    "validate_domain",
    "validate_email",
    "validate_hostname",
    "validate_ip",
    "validate_ipv4",
    "validate_ipv6",
    "validate_port",
    "validate_url",
]

