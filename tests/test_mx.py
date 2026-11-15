from __future__ import annotations

import pytest

from dmarc_check.checks.mx import DomainNotFound, check_mx

from .conftest import ids


def test_good(dns, make_ctx) -> None:
    dns.mx_records["example.com"] = [(10, "mx1.example.com"), (20, "mx2.example.com")]
    dns.addr_records["mx1.example.com"] = ["192.0.2.1"]
    dns.addr_records["mx2.example.com"] = ["2001:db8::1"]
    ctx = make_ctx()
    check_mx(ctx)
    assert ids(ctx) == []
    assert ctx.mx_hosts == ["mx1.example.com", "mx2.example.com"]
    assert not ctx.null_mx


def test_not_found(dns, make_ctx) -> None:
    dns.mx_records["example.com"] = []
    ctx = make_ctx()
    check_mx(ctx)
    assert ids(ctx) == ["mx-not-found"]


def test_domain_nxdomain(make_ctx) -> None:
    ctx = make_ctx()
    with pytest.raises(DomainNotFound):
        check_mx(ctx)
    assert ids(ctx) == ["dns-domain-not-found"]


def test_null_mx(dns, make_ctx) -> None:
    dns.mx_records["example.com"] = [(0, "")]
    ctx = make_ctx()
    check_mx(ctx)
    assert ids(ctx) == ["mx-null"]
    assert ctx.null_mx
    assert ctx.mx_hosts == []


def test_null_mx_with_others(dns, make_ctx) -> None:
    dns.mx_records["example.com"] = [(0, ""), (10, "mx.example.com")]
    dns.addr_records["mx.example.com"] = ["192.0.2.1"]
    ctx = make_ctx()
    check_mx(ctx)
    assert ids(ctx) == ["mx-null-with-others"]
    assert not ctx.null_mx


def test_target_is_ip(dns, make_ctx) -> None:
    dns.mx_records["example.com"] = [(10, "192.0.2.1")]
    ctx = make_ctx()
    check_mx(ctx)
    assert ids(ctx) == ["mx-target-is-ip"]


def test_target_unresolvable(dns, make_ctx) -> None:
    dns.mx_records["example.com"] = [(10, "gone.example.com")]
    ctx = make_ctx()
    check_mx(ctx)
    assert ids(ctx) == ["mx-target-unresolvable"]
