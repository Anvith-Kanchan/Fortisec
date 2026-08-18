# fortisec


[![PyPI](https://img.shields.io/pypi/v/fortisec.svg)](https://pypi.org/project/fortisec/)
[![Python](https://img.shields.io/pypi/pyversions/fortisec.svg)](https://pypi.org/project/fortisec/)
[![Downloads](https://static.pepy.tech/badge/fortisec/month)](https://pepy.tech/project/fortisec)
[![Ruff](https://img.shields.io/badge/lint-ruff-46a2f1)](https://docs.astral.sh/ruff/)
[![Mypy](https://img.shields.io/badge/types-mypy-blue)](https://mypy-lang.org/)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)](#quality)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A lightweight Python library that helps developers write safer code with ready-to-use
security utilities.

Instead of rewriting validation, log redaction, header checks, entropy scoring, and path
safety in every project, `fortisec` provides well-tested, typed helpers behind a simple
API.

Perfect for:

- Backend APIs
- Security tooling
- DevSecOps automation
- Pentesting scripts
- CI/CD security checks

## Features

- Fully typed
- 98% test coverage
- Zero heavy runtime dependencies
- Python 3.10+
- Cross-platform: Linux, Windows, and macOS
- CI tested on Python 3.10, 3.11, 3.12, and 3.13
- MIT licensed
- Fast startup and pure Python implementation

## Why fortisec?

| Instead of writing | Use fortisec |
| --- | --- |
| 40 lines of email and URL regex | `validate_email()` / `validate_url()` |
| Manual path traversal checks | `safe_join()` |
| Custom entropy calculations | `entropy_score()` |
| Regexes for JWTs and API keys | `redact_logs()` |
| Manual HTTP header inspection | `scan_headers()` |
| Hash length lookup tables | `identify_hash()` |

## Installation

```bash
pip install fortisec
```

For local development:

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Quick Start

```python
from fortisec import identify_hash, redact_logs, safe_join, scan_headers, validate_email

print(validate_email("admin@example.com"))
print(identify_hash("d41d8cd98f00b204e9800998ecf8427e"))

clean = redact_logs("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature")
print(clean)

path = safe_join("/srv/app/uploads", "user/avatar.png")
print(path)

result = scan_headers("https://example.com")
print(result.score)
print(result.missing)
```

## Terminal Output

Redact secrets before logs leave your application:

```pycon
>>> from fortisec import redact_logs
>>> log = """
... Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature
... Email: admin@example.com
... OpenAI Key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz
... """
>>> print(redact_logs(log))

Authorization: Bearer ********
Email: ********
OpenAI Key: ********
```

Scan security headers:

```text
Security Score: 82/100

✓ Strict-Transport-Security
✓ X-Frame-Options
✓ X-Content-Type-Options
✓ Referrer-Policy

✗ Content-Security-Policy
✗ Permissions-Policy

Recommendation: Add a Content-Security-Policy header.
```

## CLI

`fortisec` also ships with a small command-line interface for quick checks:

```bash
fortisec validate-email admin@example.com
```

```text
✔ Valid
```

```bash
fortisec hash d41d8cd98f00b204e9800998ecf8427e
```

```text
MD5
NTLM
LM
```

```bash
fortisec headers https://example.com
```

```bash
fortisec redact "Authorization: Bearer secret-token from admin@example.com"
```

```text
Authorization: Bearer ******** from ********
```

## Real Examples

### Flask uploads

```python
from flask import request
from fortisec import safe_join

UPLOAD_DIR = "/srv/app/uploads"

filename = request.files["avatar"].filename
path = safe_join(UPLOAD_DIR, filename)
request.files["avatar"].save(path)
```

### Logging

```python
import logging

from fortisec import redact_logs

logger = logging.getLogger(__name__)

logger.info(redact_logs(str(request.headers)))
```

### CI checks

```python
from fortisec import validate_url

for url in urls_from_config:
    if not validate_url(url):
        raise ValueError(f"Invalid URL in config: {url}")
```

## API Overview

### Validators

```python
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
```

All validators return `True` or `False` and do not raise for invalid input.

### Hashes

```python
from fortisec.hashes import hash_length, identify_hash, is_probably_hash
```

`identify_hash()` returns possible matches such as `["MD5", "NTLM", "LM"]`,
`["SHA1", "RIPEMD160"]`, or `[]`.

### Entropy

```python
from fortisec.entropy import entropy_score, is_high_entropy, shannon_entropy
```

Useful for identifying API keys, JWT segments, random tokens, and passwords.

### Redaction

```python
from fortisec.redact import redact_logs

redact_logs(
    "Authorization: Bearer secret-token from admin@example.com",
    redact_ip=True,
    placeholder="***",
)
```

Built-in redaction covers JWTs, AWS keys, GitHub PATs, OpenAI keys, Google API
keys, bearer tokens, email addresses, credit cards, IPv4 addresses, and IPv6
addresses. You can also pass custom regex patterns.

### HTTP Headers

```python
from fortisec.headers import scan_headers

result = scan_headers("https://example.com")
print(result.score)
print(result.to_json())
print(result.pretty_print())
```

### Safe Paths

```python
from fortisec.paths import safe_join

safe_path = safe_join("/srv/uploads", "images", "avatar.png")
```

Traversal attempts such as `../../../etc/passwd` raise `PathTraversalError`.

## Quality

```bash
python -m pytest
python -m ruff check .
python -m black --check .
python -m mypy src/fortisec
python -m build
```

## Publishing

Build and upload:

```bash
python -m pip install -U build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

Before uploading, update `project.urls` in `pyproject.toml` and confirm the package
name is available on PyPI.

