# Contributing

Thanks for helping improve `fortisec`.

## Development

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run checks before opening a pull request:

```bash
python -m pytest
python -m ruff check .
python -m black --check .
python -m mypy src/fortisec
python -m build
```

## Guidelines

- Keep public APIs small and typed.
- Prefer the Python standard library.
- Add tests for edge cases and invalid input.
- Update documentation when behavior changes.
- Do not add dependencies unless they materially improve correctness or security.

