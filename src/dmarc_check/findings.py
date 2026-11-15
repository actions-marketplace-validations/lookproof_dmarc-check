"""Finding model and the registry of every finding id this tool can emit."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

FINDINGS_BASE_URL = "https://lookproof.dev/findings/"


class Severity(str, Enum):
    ERROR = "error"
    WARN = "warn"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "warn": 1, "error": 2}[self.value]


# Finding id -> slug of the page on lookproof.dev/findings/ that explains it.
# Only slugs that exist in https://lookproof.dev/sitemap.xml may be used here;
# tests/test_links.py verifies that against the live sitemap.
REGISTRY: dict[str, str] = {
    # DNS / engine
    "dns-domain-not-found": "dns-domain-not-found",
    "dns-resolver-failure": "dns-resolver-failure",
    "dns-resolver-timeout": "dns-resolver-timeout",
    "check-internal-error": "check-internal-error",
    # SPF
    "spf-not-found": "spf-not-found",
    "spf-multiple-records": "spf-multiple-records",
    "spf-syntax-error": "spf-syntax-error",
    "spf-too-many-lookups": "spf-too-many-lookups",
    "spf-too-many-void-lookups": "spf-too-many-void-lookups",
    "spf-pass-all": "spf-pass-all",
    "spf-neutral-all": "spf-neutral-all",
    "spf-no-all": "spf-no-all",
    "spf-include-not-found": "spf-include-not-found",
    "spf-include-loop": "spf-include-loop",
    "spf-ptr-mechanism": "spf-ptr-mechanism",
    "spf-macro-not-evaluated": "spf-macro-not-evaluated",
    # DMARC
    "dmarc-not-found": "dmarc-not-found",
    "dmarc-multiple-records": "dmarc-multiple-records",
    "dmarc-syntax-error": "dmarc-syntax-error",
    "dmarc-invalid-policy": "dmarc-invalid-policy",
    "dmarc-policy-none": "dmarc-policy-none",
    "dmarc-subdomain-policy-none": "spoof-subdomains-unprotected",
    "dmarc-partial-pct": "dmarc-partial-pct",
    "dmarc-testing-mode": "dmarc-testing-mode",
    "dmarc-no-rua": "dmarc-no-rua",
    "dmarc-invalid-report-uri": "dmarc-invalid-report-uri",
    "dmarc-unknown-tag": "dmarc-unknown-tag",
    # DKIM
    "dkim-not-found": "dkim-not-found",
    "dkim-multiple-records": "dkim-multiple-records",
    "dkim-syntax-error": "dkim-syntax-error",
    "dkim-invalid-key": "dkim-invalid-key",
    "dkim-key-revoked": "dkim-key-revoked",
    "dkim-weak-key": "dkim-weak-key",
    "dkim-key-too-short": "dkim-weak-key",
    "dkim-testing-mode": "dkim-testing-mode",
    # MX
    "mx-not-found": "mx-not-found",
    "mx-null": "mx-null",
    "mx-null-with-others": "mx-null-with-others",
    "mx-target-is-ip": "mx-target-is-ip",
    "mx-target-unresolvable": "mx-target-unresolvable",
    # MTA-STS
    "mtasts-not-found": "mtasts-not-found",
    "mtasts-multiple-records": "mtasts-multiple-records",
    "mtasts-invalid-record": "mtasts-invalid-record",
    "mtasts-policy-unavailable": "mtasts-policy-unavailable",
    "mtasts-invalid-policy": "mtasts-invalid-policy",
    "mtasts-mode-none": "mtasts-mode-none",
    "mtasts-mode-testing": "mtasts-mode-testing",
    "mtasts-low-max-age": "mtasts-low-max-age",
    "mtasts-mx-not-covered": "mtasts-mx-not-covered",
    "mtasts-mx-not-covered-testing": "mtasts-mx-not-covered-testing",
    # TLS-RPT
    "tlsrpt-not-found": "tlsrpt-not-found",
    "tlsrpt-invalid": "tlsrpt-invalid",
}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    check: str
    message: str
    domain: str

    def __post_init__(self) -> None:
        if self.id not in REGISTRY:
            raise ValueError(f"unregistered finding id: {self.id}")

    @property
    def url(self) -> str:
        return FINDINGS_BASE_URL + REGISTRY[self.id]

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "check": self.check,
            "domain": self.domain,
            "message": self.message,
            "url": self.url,
        }
