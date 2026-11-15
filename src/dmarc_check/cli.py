"""Command line interface: ``dmarc-check example.com --dkim-selector s1 --json``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .dns_client import DnsResolver
from .engine import EXIT_USAGE, UsageError, parse_fail_on, parse_list, run, validate_domain
from .report import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmarc-check",
        description="Check SPF, DMARC, DKIM, MX, MTA-STS and TLS-RPT for one or more domains.",
    )
    p.add_argument("domains", nargs="+", help="domain(s) to check; commas also separate domains")
    p.add_argument(
        "--dkim-selector",
        "-s",
        action="append",
        default=[],
        metavar="SELECTOR",
        help="DKIM selector to check (repeat or comma-separate)",
    )
    p.add_argument(
        "--fail-on",
        default="error",
        help="error (default), warn, info, none, and/or a comma list of finding ids",
    )
    p.add_argument("--resolver", action="append", default=[], metavar="IP", help="DNS server(s) to use")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS timeout per query in seconds")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        domains = [validate_domain(d) for d in parse_list(args.domains)]
        fail_on = parse_fail_on(args.fail_on)
    except UsageError as exc:
        print(f"dmarc-check: {exc}", file=sys.stderr)
        return EXIT_USAGE
    resolver = DnsResolver(parse_list(args.resolver) or None, timeout=args.timeout)
    report = run(domains, resolver, parse_list(args.dkim_selector), fail_on)
    print(to_json(report) if args.json else to_text(report))
    return report.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
