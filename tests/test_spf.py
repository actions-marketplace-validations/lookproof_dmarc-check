from __future__ import annotations

import pytest

from dmarc_check.checks.spf import check_spf, is_spf
from dmarc_check.findings import Severity

from .conftest import SERVFAIL, ids


def test_is_spf() -> None:
    assert is_spf("v=spf1 -all")
    assert is_spf("V=SPF1")
    assert not is_spf("v=spf10 -all")
    assert not is_spf("google-site-verification=abc")


def test_valid_record_passes(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.net -all"]
    dns.txt_records["_spf.example.net"] = ["v=spf1 ip4:198.51.100.1 ~all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == []


def test_not_found(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["some-verification=1"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-not-found"]
    assert ctx.findings[0].severity is Severity.ERROR


def test_not_found_nxdomain(make_ctx) -> None:
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-not-found"]


def test_multiple_records(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 -all", "v=spf1 mx -all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-multiple-records"]


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 foo -all",
        "v=spf1 ip4:300.1.1.1 -all",
        "v=spf1 ip4:2001:db8::1 -all",
        "v=spf1 ip6:192.0.2.1 -all",
        "v=spf1 ip4 -all",
        "v=spf1 include: -all",
        "v=spf1 include:nodot -all",
        "v=spf1 a/33 -all",
        "v=spf1 mx//129 -all",
        "v=spf1 all:x",
        "v=spf1 redirect=a.example redirect=b.example",
        "v=spf1 exists:%{z} -all",
    ],
)
def test_syntax_errors(dns, make_ctx, record: str) -> None:
    dns.txt_records["example.com"] = [record]
    ctx = make_ctx()
    check_spf(ctx)
    assert "spf-syntax-error" in ids(ctx)


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 a mx a/24 mx//64 a:mail.example.com/28//64 -all",
        "v=spf1 ip4:192.0.2.1 ip6:::1 unknown=thing -all",
        "v=spf1 -ip4:192.0.2.1 ~all exp=explain.example.com",
    ],
)
def test_valid_syntax(dns, make_ctx, record: str) -> None:
    dns.txt_records["example.com"] = [record]
    dns.addr_records["example.com"] = ["192.0.2.1"]
    dns.addr_records["mail.example.com"] = ["192.0.2.2"]
    dns.mx_records["example.com"] = [(10, "mail.example.com")]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == []


def test_syntax_error_in_include_is_reported(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 include:bad.example -all"]
    dns.txt_records["bad.example"] = ["v=spf1 bogus -all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-syntax-error"]
    assert "bad.example" in ctx.findings[0].message


def _chain(dns, n: int) -> None:
    """example.com includes n domains, each with one SPF record and no lookups."""
    includes = " ".join(f"include:i{i}.example.net" for i in range(n))
    dns.txt_records["example.com"] = [f"v=spf1 {includes} -all"]
    for i in range(n):
        dns.txt_records[f"i{i}.example.net"] = ["v=spf1 ip4:192.0.2.1 -all"]


def test_ten_lookups_is_ok(dns, make_ctx) -> None:
    _chain(dns, 10)
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == []


def test_too_many_lookups_counts_recursively(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 include:a.example.net include:b.example.net -all"]
    dns.txt_records["a.example.net"] = ["v=spf1 a mx include:c.example.net ~all"]
    dns.txt_records["b.example.net"] = ["v=spf1 a mx exists:x.example.net ptr ~all"]
    dns.txt_records["c.example.net"] = ["v=spf1 a mx a:z.example.net redirect=d.example.net"]
    dns.txt_records["d.example.net"] = ["v=spf1 ip4:192.0.2.1 -all"]
    for name in ["a.example.net", "b.example.net", "c.example.net", "x.example.net", "z.example.net"]:
        dns.addr_records[name] = ["192.0.2.1"]
        dns.mx_records[name] = [(10, "mx." + name)]
    ctx = make_ctx()
    check_spf(ctx)
    assert "spf-too-many-lookups" in ids(ctx)
    finding = next(f for f in ctx.findings if f.id == "spf-too-many-lookups")
    assert "13 DNS lookups" in finding.message


def test_runaway_lookups_are_capped(dns, make_ctx) -> None:
    _chain(dns, 60)
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-too-many-lookups"]
    assert "more than 40" in ctx.findings[0].message
    assert len(dns.queries) < 45


def test_void_lookups(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 a:gone1.example mx:gone2.example exists:gone3.example -all"]
    dns.mx_records["gone2.example"] = []  # NODATA counts as void too
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-too-many-void-lookups"]
    assert "3 void" in ctx.findings[0].message


def test_two_void_lookups_ok(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 a:gone1.example a:gone2.example -all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == []


def test_include_not_found(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 include:missing.example include:nospf.example -all"]
    dns.txt_records["nospf.example"] = ["hello"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-include-not-found", "spf-include-not-found"]


def test_include_with_multiple_records(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 include:dup.example -all"]
    dns.txt_records["dup.example"] = ["v=spf1 -all", "v=spf1 ~all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-multiple-records"]


def test_include_loop(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 include:a.example -all"]
    dns.txt_records["a.example"] = ["v=spf1 include:example.com -all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-include-loop"]


def test_redirect_followed(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 redirect=_spf.example.com"]
    dns.txt_records["_spf.example.com"] = ["v=spf1 ip4:192.0.2.1 +all"]
    ctx = make_ctx()
    check_spf(ctx)
    # Top-level has no all, but redirect means that is fine; the target's +all
    # is not reported as the domain's own qualifier.
    assert ids(ctx) == []


def test_redirect_ignored_when_all_present(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 -all redirect=missing.example"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == []


def test_redirect_to_missing_record(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 redirect=missing.example"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-include-not-found"]


def test_pass_all(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 +all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-pass-all"]


def test_bare_all_is_pass_all(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-pass-all"]


def test_neutral_all(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 ?all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-neutral-all"]
    assert ctx.findings[0].severity is Severity.WARN


def test_softfail_all_ok(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 ip4:192.0.2.1 ~all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == []


def test_no_all(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 ip4:192.0.2.1"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-no-all"]


def test_ptr(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 ptr -all"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-ptr-mechanism"]


def test_macros_counted_not_resolved(dns, make_ctx) -> None:
    dns.txt_records["example.com"] = ["v=spf1 exists:%{i}._spf.example.com redirect=%{d}.example.net"]
    ctx = make_ctx()
    check_spf(ctx)
    assert ids(ctx) == ["spf-macro-not-evaluated"]
    assert ("TXT", "%{d}.example.net") not in dns.queries


def test_dns_error_propagates(dns, make_ctx) -> None:
    from dmarc_check.dns_client import DnsError

    dns.txt_records["example.com"] = ["v=spf1 include:broken.example -all"]
    dns.txt_records["broken.example"] = SERVFAIL
    with pytest.raises(DnsError):
        check_spf(make_ctx())
