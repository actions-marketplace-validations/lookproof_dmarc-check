from __future__ import annotations

import pytest

from dmarc_check.checks.mtasts import check_mtasts, mx_matches
from dmarc_check.checks.tlsrpt import check_tlsrpt
from dmarc_check.findings import Severity
from dmarc_check.https import FetchError

from .conftest import ids, policy

HOST = "mta-sts.example.com"
RECORD = "v=STSv1; id=20260101"
POLICY = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mail.example.net\nmax_age: 604800\n"
MX = ["mx1.example.com", "a.mail.example.net"]


def run(dns, fetcher, make_ctx, record: str | None = RECORD, resp=None, mx_hosts=MX):
    if record is not None:
        dns.txt_records["_mta-sts.example.com"] = [record]
    if resp is not None:
        fetcher.responses[HOST] = resp
    ctx = make_ctx(mx_hosts=mx_hosts)
    check_mtasts(ctx)
    return ctx


@pytest.mark.parametrize(
    ("pattern", "host", "expected"),
    [
        ("mx.example.com", "mx.example.com", True),
        ("MX.example.com.", "mx.example.com", True),
        ("*.example.com", "mx.example.com", True),
        ("*.example.com", "a.b.example.com", False),
        ("*.example.com", "example.com", False),
        ("mx.example.com", "mx2.example.com", False),
    ],
)
def test_mx_matches(pattern: str, host: str, expected: bool) -> None:
    assert mx_matches(pattern, host) is expected


def test_good(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy(POLICY.replace("\n", "\r\n")))
    assert ids(ctx) == []
    assert fetcher.calls == [HOST]


def test_content_type_with_charset_ok(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy(POLICY, content_type="text/plain; charset=utf-8"))
    assert ids(ctx) == []


def test_not_found(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, record=None)
    assert ids(ctx) == ["mtasts-not-found"]
    assert ctx.findings[0].severity is Severity.INFO
    assert fetcher.calls == []


def test_multiple(dns, fetcher, make_ctx) -> None:
    dns.txt_records["_mta-sts.example.com"] = [RECORD, "v=STSv1; id=2"]
    ctx = make_ctx(mx_hosts=MX)
    check_mtasts(ctx)
    assert ids(ctx) == ["mtasts-multiple-records"]


@pytest.mark.parametrize("record", ["v=STSv1", "v=STSv1; id=has-dash", "v=STSv1; id=" + "a" * 33, "v=STSv1; junk"])
def test_invalid_record(dns, fetcher, make_ctx, record: str) -> None:
    assert ids(run(dns, fetcher, make_ctx, record=record)) == ["mtasts-invalid-record"]


def test_fetch_error(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=FetchError("TLS certificate validation failed: expired"))
    assert ids(ctx) == ["mtasts-policy-unavailable"]
    assert "certificate" in ctx.findings[0].message


def test_redirect_not_followed(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy("", status=301))
    assert ids(ctx) == ["mtasts-policy-unavailable"]
    assert "redirect" in ctx.findings[0].message


def test_http_404(dns, fetcher, make_ctx) -> None:
    assert ids(run(dns, fetcher, make_ctx, resp=policy("nope", status=404))) == ["mtasts-policy-unavailable"]


def test_wrong_content_type(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy(POLICY, content_type="text/html"))
    assert ids(ctx) == ["mtasts-invalid-policy"]


def test_too_large(dns, fetcher, make_ctx) -> None:
    assert ids(run(dns, fetcher, make_ctx, resp=policy(POLICY + "#" * 70000))) == ["mtasts-invalid-policy"]


def test_not_utf8(dns, fetcher, make_ctx) -> None:
    resp = policy(POLICY)
    resp.body = b"\xff\xfe"
    assert ids(run(dns, fetcher, make_ctx, resp=resp)) == ["mtasts-invalid-policy"]


@pytest.mark.parametrize(
    "text",
    [
        "version: STSv2\nmode: enforce\nmx: mx1.example.com\nmax_age: 86400\n",
        "version: STSv1\nmode: strict\nmx: mx1.example.com\nmax_age: 86400\n",
        "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: forever\n",
        "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 99999999\n",
        "version: STSv1\nmode: enforce\nmax_age: 86400\n",
        "version: STSv1\nmode: enforce\nmode: testing\nmx: mx1.example.com\nmax_age: 86400\n",
        "<html>hello</html>",
    ],
)
def test_invalid_policy(dns, fetcher, make_ctx, text: str) -> None:
    assert ids(run(dns, fetcher, make_ctx, resp=policy(text))) == ["mtasts-invalid-policy"]


def test_mode_none(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy("version: STSv1\nmode: none\nmax_age: 86400\n"))
    assert ids(ctx) == ["mtasts-mode-none"]


def test_mode_testing(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy(POLICY.replace("enforce", "testing")))
    assert ids(ctx) == ["mtasts-mode-testing"]


def test_low_max_age(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy(POLICY.replace("604800", "3600")))
    assert ids(ctx) == ["mtasts-low-max-age"]


def test_mx_not_covered_enforce(dns, fetcher, make_ctx) -> None:
    ctx = run(dns, fetcher, make_ctx, resp=policy(POLICY), mx_hosts=[*MX, "backup.example.org"])
    assert ids(ctx) == ["mtasts-mx-not-covered"]
    assert ctx.findings[0].severity is Severity.ERROR
    assert "backup.example.org" in ctx.findings[0].message


def test_mx_not_covered_testing(dns, fetcher, make_ctx) -> None:
    ctx = run(
        dns, fetcher, make_ctx, resp=policy(POLICY.replace("enforce", "testing")), mx_hosts=["x.b.mail.example.net"]
    )
    assert ids(ctx) == ["mtasts-mode-testing", "mtasts-mx-not-covered-testing"]


# TLS-RPT


def run_tlsrpt(dns, make_ctx, *records: str):
    dns.txt_records["_smtp._tls.example.com"] = list(records)
    ctx = make_ctx()
    check_tlsrpt(ctx)
    return ctx


def test_tlsrpt_good(dns, make_ctx) -> None:
    ctx = run_tlsrpt(dns, make_ctx, "v=TLSRPTv1; rua=mailto:tls@example.com,https://r.example.com/tls")
    assert ids(ctx) == []


def test_tlsrpt_not_found(dns, make_ctx) -> None:
    ctx = run_tlsrpt(dns, make_ctx, "v=spf1 -all")
    assert ids(ctx) == ["tlsrpt-not-found"]
    assert ctx.findings[0].severity is Severity.INFO


@pytest.mark.parametrize(
    "records",
    [
        ["v=TLSRPTv1"],
        ["v=TLSRPTv1; rua=ftp://example.com"],
        ["v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"],
    ],
)
def test_tlsrpt_invalid(dns, make_ctx, records: list[str]) -> None:
    ctx = run_tlsrpt(dns, make_ctx, *records)
    assert ids(ctx) == ["tlsrpt-invalid"]
