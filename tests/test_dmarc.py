from __future__ import annotations

import pytest

from dmarc_check.checks.dmarc import check_dmarc
from dmarc_check.findings import Severity

from .conftest import ids

GOOD = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"


def run(dns, make_ctx, *records: str):
    dns.txt_records["_dmarc.example.com"] = list(records)
    ctx = make_ctx()
    check_dmarc(ctx)
    return ctx


def test_good_record(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, GOOD)) == []


def test_good_record_with_all_tags(dns, make_ctx) -> None:
    record = (
        "v=DMARC1; p=quarantine; sp=reject; np=reject; pct=100; adkim=s; aspf=r; fo=1; "
        "rua=mailto:a@example.com,mailto:b@example.net!10m; ruf=mailto:f@example.com"
    )
    assert ids(run(dns, make_ctx, record)) == []


def test_not_found(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, "v=spf1 -all")) == ["dmarc-not-found"]


def test_not_found_nxdomain(make_ctx) -> None:
    ctx = make_ctx()
    check_dmarc(ctx)
    assert ids(ctx) == ["dmarc-not-found"]


def test_multiple(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, GOOD, "v=DMARC1; p=none")) == ["dmarc-multiple-records"]


def test_missing_p(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, "v=DMARC1; rua=mailto:d@example.com")) == ["dmarc-invalid-policy"]


def test_invalid_p(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, "v=DMARC1; p=block; rua=mailto:d@example.com")) == ["dmarc-invalid-policy"]


@pytest.mark.parametrize("tag", ["sp", "np"])
def test_invalid_sp_np(dns, make_ctx, tag: str) -> None:
    assert ids(run(dns, make_ctx, f"{GOOD}; {tag}=maybe")) == ["dmarc-invalid-policy"]


def test_policy_none(dns, make_ctx) -> None:
    ctx = run(dns, make_ctx, "v=DMARC1; p=none; rua=mailto:d@example.com")
    assert ids(ctx) == ["dmarc-policy-none"]
    assert ctx.findings[0].severity is Severity.WARN


@pytest.mark.parametrize("tag", ["sp", "np"])
def test_subdomain_policy_none(dns, make_ctx, tag: str) -> None:
    ctx = run(dns, make_ctx, f"{GOOD}; {tag}=none")
    assert ids(ctx) == ["dmarc-subdomain-policy-none"]
    assert ctx.findings[0].url == "https://lookproof.dev/findings/spoof-subdomains-unprotected"


def test_sp_none_with_p_none_only_reports_p(dns, make_ctx) -> None:
    ctx = run(dns, make_ctx, "v=DMARC1; p=none; sp=none; rua=mailto:d@example.com")
    assert ids(ctx) == ["dmarc-policy-none"]


def test_partial_pct(dns, make_ctx) -> None:
    ctx = run(dns, make_ctx, f"{GOOD}; pct=25")
    assert ids(ctx) == ["dmarc-partial-pct"]
    assert ctx.findings[0].severity is Severity.WARN


@pytest.mark.parametrize("pct", ["abc", "101", "-1"])
def test_bad_pct(dns, make_ctx, pct: str) -> None:
    assert ids(run(dns, make_ctx, f"{GOOD}; pct={pct}")) == ["dmarc-syntax-error"]


def test_testing_mode(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, f"{GOOD}; t=y")) == ["dmarc-testing-mode"]


def test_no_rua(dns, make_ctx) -> None:
    ctx = run(dns, make_ctx, "v=DMARC1; p=reject")
    assert ids(ctx) == ["dmarc-no-rua"]
    assert ctx.findings[0].severity is Severity.INFO


@pytest.mark.parametrize("uri", ["https://example.com/report", "mailto:nope", "dmarc@example.com"])
def test_invalid_report_uri(dns, make_ctx, uri: str) -> None:
    assert ids(run(dns, make_ctx, f"v=DMARC1; p=reject; rua={uri}")) == ["dmarc-invalid-report-uri"]


@pytest.mark.parametrize(
    "record",
    ["v=DMARC1; p=reject; adkim=x; rua=mailto:d@example.com", f"{GOOD}; p=reject", f"{GOOD}; garbage"],
)
def test_syntax_errors(dns, make_ctx, record: str) -> None:
    assert "dmarc-syntax-error" in ids(run(dns, make_ctx, record))


def test_unknown_tag(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, f"{GOOD}; foo=bar")) == ["dmarc-unknown-tag"]


def test_whitespace_and_case_tolerated(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, "v = DMARC1 ;p=Reject; rua=MAILTO:d@example.com;")) == []
