"""Command-line interface for fortisec."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from .exceptions import HeaderScanError
from .hashes import identify_hash
from .headers import HeaderScanResult, scan_headers
from .redact import redact_logs
from .validators import validate_email, validate_url


def _print_header_result(result: HeaderScanResult) -> None:
    print(f"Security Score: {result.score}/100")
    print()
    for header in result.present:
        print(f"\u2713 {header}")
    if result.present and result.missing:
        print()
    for header in result.missing:
        print(f"\u2717 {header}")
    if result.missing:
        print()
        print(f"Recommendation: Add a {result.missing[0]} header.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortisec",
        description="Security utility helpers for validation, hashes, headers, and redaction.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    email_parser = subparsers.add_parser("validate-email", help="Validate an email address.")
    email_parser.add_argument("email")

    url_parser = subparsers.add_parser("validate-url", help="Validate a URL.")
    url_parser.add_argument("url")

    hash_parser = subparsers.add_parser("hash", help="Identify a hash string.")
    hash_parser.add_argument("value")

    headers_parser = subparsers.add_parser("headers", help="Scan HTTP security headers.")
    headers_parser.add_argument("url")
    headers_parser.add_argument("--timeout", type=float, default=10.0)

    redact_parser = subparsers.add_parser("redact", help="Redact secrets from text.")
    redact_parser.add_argument("text")
    redact_parser.add_argument("--placeholder", default="********")
    redact_parser.add_argument("--keep-ip", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fortisec command-line interface.

    Args:
        argv: Optional command arguments. When omitted, argparse reads sys.argv.

    Returns:
        Process exit code.

    Raises:
        This function handles expected command errors and returns a non-zero exit code.

    Examples:
        >>> main(["validate-email", "admin@example.com"])
        0
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-email":
        valid = validate_email(args.email)
        print("\u2714 Valid" if valid else "\u2717 Invalid")
        return 0 if valid else 1

    if args.command == "validate-url":
        valid = validate_url(args.url)
        print("\u2714 Valid" if valid else "\u2717 Invalid")
        return 0 if valid else 1

    if args.command == "hash":
        matches = identify_hash(args.value)
        print("\n".join(matches) if matches else "Unknown")
        return 0 if matches else 1

    if args.command == "headers":
        try:
            _print_header_result(scan_headers(args.url, timeout=args.timeout))
        except HeaderScanError as exc:
            parser.exit(2, f"Error: {exc}\n")
        return 0

    if args.command == "redact":
        print(
            redact_logs(
                args.text,
                redact_ip=not args.keep_ip,
                placeholder=args.placeholder,
            )
        )
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

