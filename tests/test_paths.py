from pathlib import Path

import pytest

from fortisec.exceptions import PathTraversalError
from fortisec.paths import is_safe_path, normalize_path, safe_join


def test_normalize_path_returns_absolute() -> None:
    assert Path(normalize_path(".")).is_absolute()


def test_safe_join_allows_child(tmp_path: Path) -> None:
    result = safe_join(tmp_path, "uploads", "file.txt")
    assert Path(result).is_absolute()
    assert is_safe_path(tmp_path, result)


def test_safe_join_blocks_parent_traversal(tmp_path: Path) -> None:
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "..", "secret.txt")


def test_safe_join_blocks_nested_parent_traversal(tmp_path: Path) -> None:
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "uploads", "..", "..", "secret.txt")


def test_safe_join_blocks_absolute_path(tmp_path: Path) -> None:
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, Path(tmp_path.anchor) / "etc" / "passwd")


def test_is_safe_path_relative_child(tmp_path: Path) -> None:
    assert is_safe_path(tmp_path, "file.txt")


def test_is_safe_path_absolute_outside(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.txt"
    assert not is_safe_path(tmp_path, outside)


def test_safe_join_accepts_path_objects(tmp_path: Path) -> None:
    assert is_safe_path(tmp_path, safe_join(tmp_path, Path("a"), Path("b.txt")))


def test_safe_join_without_paths_returns_base(tmp_path: Path) -> None:
    assert safe_join(tmp_path) == normalize_path(tmp_path)


def test_invalid_types_raise(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        safe_join(123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        safe_join(tmp_path, 123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        is_safe_path(tmp_path, 123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        normalize_path(123)  # type: ignore[arg-type]

