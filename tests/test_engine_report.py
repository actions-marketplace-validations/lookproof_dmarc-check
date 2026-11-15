from __future__ import annotations

import json

import pytest

from dmarc_check.engine import (
    FailOn,
    UsageError,
    check_domain,
    parse_fail_on,
    parse_list,
    run,
    validate_domain,
)
from dmarc_check.findings import REGISTRY, Finding, Severity
from dmarc_check.report import SENDERWARD_LINE, to_json, to_markdown, to_text

from .conftest import SERVFAIL, TIMEOUT, policy


def healthy(dns, fetcher, domain: str = "example.com") -> None:
    dns.mx_records[domain] = [(10, "mx." + domain)]
    dns.addr_records["mx." + domain] = ["192.0.2.1"]
    dns.txt_records[domain] = ["v=spf1 mx -all"]
    dns.txt_records["_dmarc." + domain] = ["v=DMARC1; p=reject; rua=mailto:d@" + domain]
    dns.txt_records["_mta-sts." + domain] = ["v=STSv1; id=1"]
    dns.txt_records["_smtp._tls." + domain] = ["v=TLSRPTv1; rua=mailto:tls@" + domain]
    fetcher.responses["mta-sts." + domain] = policy(
        f"version: STSv1\nmode: enforce\nmx: mx.{domain}\nmax_age: 604800\n"
    )


def test_healthy_domain(dns, fetcher) -> None:
    healthy(dns, fetcher)
    result = check_domain("example.com", dns, [], fetcher)
    assert result.findings == []


def test_null_mx_skips_mtasts_and_tlsrpt(dns, fetcher) -> None:
    dns.mx_records["example.com"] = [(0, "")]
    dns.txt_records["example.com"] = ["v=spf1 -all"]
    dns.txt_records["_dmarc.example.com"] = ["v=DMARC1; p=reject; rua=mailto:d@example.net"]
    result = check_domain("example.com", dns, [], fetcher)
    assert [f.id for f in result.findings] == ["mx-null"]
    assert ("TXT", "_mta-sts.example.com") not in dns.queries
    assert fetcher.calls == []


def test_nxdomain_stops_early(dns, fetcher) -> None:
    result = check_domain("nope.example", dns, ["s1"], fetcher)
    assert [f.id for f in result.findings] == ["dns-domain-not-found"]


def test_dns_failures_are_findings(dns, fetcher) -> None:
    healthy(dns, fetcher)
    dns.txt_records["example.com"] = TIMEOUT
    dns.txt_records["_dmarc.example.com"] = SERVFAIL
    result = check_domain("example.com", dns, [], fetcher)
    assert [f.id for f in result.findings] == ["dns-resolver-timeout", "dns-resolver-failure"]
    assert all(f.severity is Severity.ERROR for f in result.findings)


def test_crashing_check_is_contained(dns, fetcher, monkeypatch) -> None:
    import dmarc_check.engine as engine

    healthy(dns, fetcher)

    def boom(ctx):
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "CHECKS", [("spf", boom), *engine.CHECKS[2:]])
    result = check_domain("example.com", dns, [], fetcher)
    assert [f.id for f in result.findings] == ["check-internal-error"]


def test_control_characters_stripped(dns, fetcher) -> None:
    healthy(dns, fetcher)
    dns.txt_records["example.com"] = ["v=spf1 bogus\n::add-mask::x -all"]
    result = check_domain("example.com", dns, [], fetcher)
    assert "\n" not in result.findings[0].message


def test_unregistered_id_rejected() -> None:
    with pytest.raises(ValueError):
        Finding("made-up", Severity.INFO, "x", "y", "example.com")


@pytest.mark.parametrize(
    ("value", "threshold", "ids"),
    [
        ("", Severity.ERROR, set()),
        ("error", Severity.ERROR, set()),
        ("WARN", Severity.WARN, set()),
        ("info", Severity.INFO, set()),
        ("none", None, set()),
        ("dmarc-policy-none, spf-neutral-all", None, {"dmarc-policy-none", "spf-neutral-all"}),
        ("error,dmarc-no-rua", Severity.ERROR, {"dmarc-no-rua"}),
        ("error,warn", Severity.WARN, set()),
    ],
)
def test_parse_fail_on(value, threshold, ids) -> None:
    fo = parse_fail_on(value)
    assert fo.threshold == threshold
    assert fo.ids == frozenset(ids)


def test_parse_fail_on_rejects_unknown() -> None:
    with pytest.raises(UsageError):
        parse_fail_on("errors")


def test_fail_on_matching() -> None:
    warn = Finding("dmarc-policy-none", Severity.WARN, "dmarc", "m", "example.com")
    info = Finding("dmarc-no-rua", Severity.INFO, "dmarc", "m", "example.com")
    assert not FailOn().matches(warn)
    assert FailOn(Severity.WARN).matches(warn)
    assert not FailOn(Severity.WARN).matches(info)
    assert FailOn(None, frozenset({"dmarc-no-rua"})).matches(info)
    assert not FailOn(None, frozenset({"dmarc-no-rua"})).matches(warn)
    assert FailOn(None).describe() == "none"


def test_parse_list() -> None:
    assert parse_list(["a.com, b.com", "a.com\nc.com"]) == ["a.com", "b.com", "c.com"]


@pytest.mark.parametrize("value", ["Example.COM.", " example.com "])
def test_validate_domain(value: str) -> None:
    assert validate_domain(value) == "example.com"


def test_validate_idn() -> None:
    assert validate_domain("bücher.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize("value", ["localhost", "https://example.com", "a@b.com", "a..com", "x" * 64 + ".com"])
def test_validate_domain_rejects(value: str) -> None:
    with pytest.raises(UsageError):
        validate_domain(value)


def _report(dns, fetcher, fail_on: str = "error"):
    healthy(dns, fetcher, "good.example")
    dns.mx_records["bad.example"] = [(10, "mx.good.example")]
    dns.txt_records["bad.example"] = ["v=spf1 ?all"]
    dns.txt_records["_dmarc.bad.example"] = ["v=DMARC1; p=none; rua=mailto:x|y@bad"]
    return run(["good.example", "bad.example"], dns, [], parse_fail_on(fail_on), fetcher)


def test_report_exit_codes(dns, fetcher) -> None:
    report = _report(dns, fetcher)
    assert not report.failed and report.exit_code == 0  # only warn/info
    report = _report(dns, fetcher, "warn")
    assert report.failed and report.exit_code == 1
    report = _report(dns, fetcher, "tlsrpt-not-found")
    assert report.exit_code == 1
    assert [f.id for f in report.failing] == ["tlsrpt-not-found"]


def test_json(dns, fetcher) -> None:
    data = json.loads(to_json(_report(dns, fetcher, "warn")))
    assert data["failed"] is True
    assert data["exit_code"] == 1
    assert data["fail_on"] == "warn"
    assert data["domains"][0] == {"domain": "good.example", "findings": []}
    first = data["domains"][1]["findings"][0]
    assert set(first) == {"id", "severity", "check", "domain", "message", "url"}
    assert data["counts"]["warn"] >= 2


def test_markdown(dns, fetcher) -> None:
    md = to_markdown(_report(dns, fetcher, "warn"))
    lines = md.strip().splitlines()
    assert lines[0] == "## dmarc-check"
    assert "❌ Failed" in md
    assert "| good.example | ok | | No findings |" in md
    assert "[`spf-neutral-all`](https://lookproof.dev/findings/spf-neutral-all)" in md
    assert "**warn**" in md
    assert lines[-1] == SENDERWARD_LINE
    assert md.count("senderward.com") == 1
    assert "x\\|y&#64;bad" in md  # pipes and @ from DNS data are escaped


def test_markdown_without_footer(dns, fetcher) -> None:
    md = to_markdown(_report(dns, fetcher), footer=False)
    assert "senderward" not in md
    assert "✅ Passed" in md


def test_text(dns, fetcher) -> None:
    text = to_text(_report(dns, fetcher, "warn"))
    assert "FAILED (fail-on: warn)" in text
    assert "https://lookproof.dev/findings/dmarc-policy-none" in text
    assert "senderward" not in text
    assert "ok     no findings" in text


def test_every_registered_slug_is_lowercase_slug() -> None:
    import re

    for fid, slug in REGISTRY.items():
        assert re.fullmatch(r"[a-z0-9-]+", fid)
        assert re.fullmatch(r"[a-z0-9-]+", slug)


def test_readme_documents_every_finding() -> None:
    from pathlib import Path

    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    missing = [
        fid for fid, slug in REGISTRY.items() if f"[`{fid}`](https://lookproof.dev/findings/{slug})" not in readme
    ]
    assert not missing
