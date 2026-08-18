"""Path normalization and traversal protection helpers."""

from __future__ import annotations

from pathlib import Path, PurePath

from .exceptions import PathTraversalError


def normalize_path(path: str | Path) -> str:
    """Normalize a filesystem path without requiring it to exist.

    Args:
        path: Path to normalize.

    Returns:
        Normalized path string.

    Raises:
        TypeError: If path is not path-like.

    Examples:
        >>> normalize_path("a/../b").endswith("b")
        True
    """
    if not isinstance(path, (str, Path)):
        raise TypeError("path must be a string or pathlib.Path")
    return str(Path(path).expanduser().resolve(strict=False))


def is_safe_path(base: str | Path, path: str | Path) -> bool:
    """Return whether path stays inside base after normalization.

    Args:
        base: Base directory.
        path: Candidate path.

    Returns:
        True when the candidate path is within the base directory.

    Raises:
        TypeError: If either argument is not path-like.

    Examples:
        >>> is_safe_path("/tmp/base", "/tmp/base/file.txt")
        True
    """
    if not isinstance(base, (str, Path)) or not isinstance(path, (str, Path)):
        raise TypeError("base and path must be strings or pathlib.Path values")
    base_path = Path(base).expanduser().resolve(strict=False)
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = base_path / candidate
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(base_path)
    except ValueError:
        return False
    return True


def safe_join(base: str | Path, *paths: str | Path) -> str:
    """Join paths while preventing traversal outside a base directory.

    Args:
        base: Trusted base directory.
        *paths: Untrusted path fragments.

    Returns:
        Absolute normalized joined path.

    Raises:
        PathTraversalError: If the joined path escapes the base directory.
        TypeError: If any argument is not path-like.

    Examples:
        >>> safe_join("/tmp/base", "logs", "app.log").endswith("logs/app.log")
        True
    """
    if not isinstance(base, (str, Path)):
        raise TypeError("base must be a string or pathlib.Path")
    if not paths:
        return normalize_path(base)
    for item in paths:
        if not isinstance(item, (str, Path)):
            raise TypeError("paths must contain only strings or pathlib.Path values")
        pure = PurePath(item)
        if pure.is_absolute():
            raise PathTraversalError(f"absolute path is not allowed: {item}")
    base_path = Path(base).expanduser().resolve(strict=False)
    candidate = base_path.joinpath(*paths).resolve(strict=False)
    if not is_safe_path(base_path, candidate):
        raise PathTraversalError(f"path escapes base directory: {candidate}")
    return str(candidate)

