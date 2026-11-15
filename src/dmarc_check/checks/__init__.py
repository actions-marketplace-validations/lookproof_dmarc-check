"""Individual checks. Each check takes a :class:`Context` and appends findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..dns_client import Resolver
from ..findings import Finding, Severity
from ..https import PolicyFetcher


@dataclass
class Context:
    domain: str
    resolver: Resolver
    fetch_policy: PolicyFetcher
    dkim_selectors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Filled in by the MX check and used by MTA-STS.
    mx_hosts: list[str] = field(default_factory=list)
    null_mx: bool = False

    def add(self, check: str, fid: str, severity: Severity, message: str) -> None:
        # Messages quote DNS data; strip control characters so a record cannot
        # inject lines into logs or GitHub workflow commands.
        clean = "".join(c if c.isprintable() else "?" for c in message)
        self.findings.append(Finding(fid, severity, check, clean, self.domain))


def parse_tags(record: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse a ``k=v; k=v`` tag list (DMARC, DKIM, MTA-STS, TLS-RPT).

    Returns the tags in order and a list of malformed fragments.
    """
    tags: list[tuple[str, str]] = []
    bad: list[str] = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        key = key.strip()
        if not sep or not key or any(c.isspace() for c in key):
            bad.append(part)
            continue
        tags.append((key, value.strip()))
    return tags, bad
