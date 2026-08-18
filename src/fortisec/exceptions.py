"""Custom exceptions for fortisec."""


class FortisecError(Exception):
    """Base exception for fortisec errors."""


class HeaderScanError(FortisecError):
    """Raised when HTTP headers cannot be scanned."""


class ValidationError(FortisecError):
    """Raised for validation related errors."""


class PathTraversalError(FortisecError):
    """Raised when a path traversal attempt is detected."""

