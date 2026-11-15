"""Runs every check for a list of domains and decides pass/fail."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from . import __version__
from .checks import Context
from .checks.dkim import check_dkim
from .checks.dmarc import check_dmarc
from .checks.mtasts import check_mtasts
from .checks.mx import DomainNotFound, check_mx
from .checks.spf import check_spf
from .checks.tlsrpt import check_tlsrpt
from .dns_client import DnsError, Resolver, normalize
from .findings import REGISTRY, Finding, Severity
from .https import PolicyFetcher, fetch_policy

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


class UsageError(ValueError):
    pass


@dataclass
class DomainResult:
    domain: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class FailOn:
    threshold: Severity | None = Severity.ERROR
    ids: frozenset[str] = frozenset()

    def matches(self, finding: Finding) -> bool:
        if finding.id in self.ids:
            return True
        return self.threshold is not None and finding.severity.rank >= self.threshold.rank

    def describe(self) -> str:
        parts = [self.threshold.value] if self.threshold else []
        parts += sorted(self.ids)
        return ",".join(parts) or "none"


def parse_fail_on(value: str) -> FailOn:
    """Parse ``error``, ``warn``, ``info``, ``none`` and/or a comma list of finding ids.

    A severity sets a threshold; ids fail the run regardless of severity. Both
    can be combined, e.g. ``error,dmarc-policy-none``. A list made only of ids
    fails on those ids alone.
    """
    tokens = [t.strip().lower() for t in value.replace("\n", ",").split(",") if t.strip()]
    if not tokens:
        return FailOn()
    threshold: Severity | None = None
    ids: set[str] = set()
    for tok in tokens:
        if tok in ("error", "warn", "info"):
            sev = Severity(tok)
            if threshold is None or sev.rank < threshold.rank:
                threshold = sev
        elif tok in ("none", "never"):
            continue
        elif tok in REGISTRY:
            ids.add(tok)
        else:
            raise UsageError(f"fail-on: unknown severity or finding id {tok!r}")
    return FailOn(threshold, frozenset(ids))


def parse_list(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        for part in value.replace("\n", ",").replace(" ", ",").split(","):
            part = part.strip()
            if part and part not in out:
                out.append(part)
    return out


def validate_domain(domain: str) -> str:
    name = normalize(domain)
    if "://" in name or "/" in name or "@" in name:
        raise UsageError(f"{domain!r} is not a domain name")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UsageError(f"{domain!r} is not a valid domain name") from exc
    labels = name.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels) or len(name) > 253:
        raise UsageError(f"{domain!r} is not a valid domain name")
    return name


Check = Callable[[Context], None]
CHECKS: list[tuple[str, Check]] = [
    ("mx", check_mx),
    ("spf", check_spf),
    ("dmarc", check_dmarc),
    ("dkim", check_dkim),
    ("mta-sts", check_mtasts),
    ("tls-rpt", check_tlsrpt),
]
_SKIPPED_WITHOUT_MX = {"mta-sts", "tls-rpt"}


def check_domain(
    domain: str,
    resolver: Resolver,
    dkim_selectors: list[str] | None = None,
    fetcher: PolicyFetcher | None = None,
) -> DomainResult:
    ctx = Context(domain, resolver, fetcher or fetch_policy, list(dkim_selectors or []))
    for name, check in CHECKS:
        if name in _SKIPPED_WITHOUT_MX and (ctx.null_mx or not ctx.mx_hosts):
            continue
        try:
            check(ctx)
        except DomainNotFound:
            break
        except DnsError as exc:
            fid = "dns-resolver-timeout" if exc.timeout else "dns-resolver-failure"
            ctx.add(name, fid, Severity.ERROR, f"{name} check incomplete: {exc}")
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the rest
            ctx.add(name, "check-internal-error", Severity.ERROR, f"{name} check crashed: {type(exc).__name__}: {exc}")
    return DomainResult(domain, ctx.findings)


@dataclass
class Report:
    results: list[DomainResult]
    fail_on: FailOn

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def failing(self) -> list[Finding]:
        return [f for f in self.findings if self.fail_on.matches(f)]

    @property
    def failed(self) -> bool:
        return bool(self.failing)

    @property
    def exit_code(self) -> int:
        return EXIT_FAILED if self.failed else EXIT_OK

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": "dmarc-check",
            "version": __version__,
            "fail_on": self.fail_on.describe(),
            "failed": self.failed,
            "exit_code": self.exit_code,
            "counts": self.counts(),
            "domains": [{"domain": r.domain, "findings": [f.to_dict() for f in r.findings]} for r in self.results],
        }


def run(
    domains: list[str],
    resolver: Resolver,
    dkim_selectors: list[str] | None = None,
    fail_on: FailOn | None = None,
    fetcher: PolicyFetcher | None = None,
) -> Report:
    results = [check_domain(d, resolver, dkim_selectors, fetcher) for d in domains]
    return Report(results, fail_on or FailOn())
