"""Tests for the dnspython and HTTPS adapters, with the network replaced by fakes."""

from __future__ import annotations

import http.client
import ssl
from typing import ClassVar

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from dmarc_check import https
from dmarc_check.dns_client import DnsError, DnsResolver


def _rr(rdtype: str, text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), text)


class FakeDnspython:
    def __init__(self, answers: dict[tuple[str, str], object]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    def resolve(self, name: str, rdtype: str, search: bool = False) -> list[dns.rdata.Rdata]:
        self.calls.append((name, rdtype))
        value = self.answers.get((name, rdtype), dns.resolver.NXDOMAIN())
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, list)
        return value


@pytest.fixture
def resolver() -> DnsResolver:
    return DnsResolver(["192.0.2.53"], timeout=1)


def test_nameservers_and_timeout(resolver: DnsResolver) -> None:
    assert resolver._r.nameservers == ["192.0.2.53"]
    assert resolver._r.lifetime == 1


def test_txt_joins_strings_and_caches(resolver: DnsResolver) -> None:
    fake = FakeDnspython({("example.com.", "TXT"): [_rr("TXT", '"v=spf1 " "-all"')]})
    resolver._r = fake  # type: ignore[assignment]
    assert resolver.txt("Example.com.").records == ["v=spf1 -all"]
    assert resolver.txt("example.com").status == "ok"
    assert len(fake.calls) == 1


def test_mx_normalises_and_null_mx(resolver: DnsResolver) -> None:
    resolver._r = FakeDnspython(  # type: ignore[assignment]
        {
            ("a.example.", "MX"): [_rr("MX", "20 MX2.Example.com."), _rr("MX", "10 mx1.example.com.")],
            ("b.example.", "MX"): [_rr("MX", "0 .")],
        }
    )
    assert resolver.mx("a.example").records == [(10, "mx1.example.com"), (20, "mx2.example.com")]
    assert resolver.mx("b.example").records == [(0, "")]


def test_addresses(resolver: DnsResolver) -> None:
    resolver._r = FakeDnspython(  # type: ignore[assignment]
        {
            ("v4.example.", "A"): [_rr("A", "192.0.2.1")],
            ("v4.example.", "AAAA"): dns.resolver.NoAnswer(),
            ("none.example.", "A"): dns.resolver.NoAnswer(),
            ("none.example.", "AAAA"): dns.resolver.NoAnswer(),
        }
    )
    assert resolver.addresses("v4.example").records == ["192.0.2.1"]
    assert resolver.addresses("none.example").status == "nodata"
    assert resolver.addresses("gone.example").status == "nxdomain"


@pytest.mark.parametrize(
    ("exc", "timeout"),
    [
        (dns.resolver.LifetimeTimeout(timeout=1.0, errors=[]), True),
        (dns.resolver.NoNameservers(), False),
        (dns.resolver.YXDOMAIN(), False),
    ],
)
def test_errors(resolver: DnsResolver, exc: Exception, timeout: bool) -> None:
    resolver._r = FakeDnspython({("x.example.", "TXT"): exc})  # type: ignore[assignment]
    with pytest.raises(DnsError) as info:
        resolver.txt("x.example")
    assert info.value.timeout is timeout


# HTTPS


class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    def read(self, n: int) -> bytes:
        return self.body[:n]


class FakeConnection:
    instances: ClassVar[list[FakeConnection]] = []
    response: FakeResponse | BaseException = FakeResponse(200, {"Content-Type": "text/plain"}, b"x")

    def __init__(self, host: str, port: int, timeout: float, context: ssl.SSLContext) -> None:
        self.host, self.port, self.context = host, port, context
        self.tunnel: tuple[str, int] | None = None
        self.closed = False
        self.requests: list[tuple[str, str]] = []
        FakeConnection.instances.append(self)

    def set_tunnel(self, host: str, port: int) -> None:
        self.tunnel = (host, port)

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        self.requests.append((method, path))

    def getresponse(self) -> FakeResponse:
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_conn(monkeypatch: pytest.MonkeyPatch) -> type[FakeConnection]:
    FakeConnection.instances = []
    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConnection)
    for var in ("https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"):
        monkeypatch.delenv(var, raising=False)
    return FakeConnection


def test_fetch_policy(fake_conn: type[FakeConnection]) -> None:
    fake_conn.response = FakeResponse(301, {"Content-Type": "text/html", "Location": "https://x/"}, b"")
    resp = https.fetch_policy("mta-sts.example.com")
    conn = fake_conn.instances[0]
    assert (conn.host, conn.port, conn.tunnel) == ("mta-sts.example.com", 443, None)
    assert conn.requests == [("GET", "/.well-known/mta-sts.txt")]
    assert conn.context.verify_mode == ssl.CERT_REQUIRED and conn.context.check_hostname
    assert conn.closed
    assert (resp.status, resp.location) == (301, "https://x/")


def test_fetch_policy_caps_body(fake_conn: type[FakeConnection]) -> None:
    fake_conn.response = FakeResponse(200, {}, b"a" * (https.MAX_POLICY_BYTES * 2))
    assert len(https.fetch_policy("h").body) == https.MAX_POLICY_BYTES + 1


def test_fetch_policy_through_proxy(fake_conn: type[FakeConnection], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    https.fetch_policy("mta-sts.example.com")
    conn = fake_conn.instances[0]
    assert (conn.host, conn.port, conn.tunnel) == ("proxy.internal", 3128, ("mta-sts.example.com", 443))


def test_no_proxy_respected(fake_conn: type[FakeConnection], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "proxy.internal")
    monkeypatch.setenv("NO_PROXY", "example.com")
    https.fetch_policy("mta-sts.example.com")
    assert fake_conn.instances[0].tunnel is None


def _cert_error() -> ssl.SSLCertVerificationError:
    err = ssl.SSLCertVerificationError(1, "certificate verify failed")
    err.verify_message = "certificate has expired"
    return err


@pytest.mark.parametrize(
    ("exc", "text"),
    [
        (_cert_error(), "certificate has expired"),
        (ssl.SSLError(1, "handshake failure"), "TLS error"),
        (TimeoutError("timed out"), "timed out"),
        (ConnectionRefusedError("refused"), "connection failed"),
    ],
)
def test_fetch_errors(fake_conn: type[FakeConnection], exc: BaseException, text: str) -> None:
    fake_conn.response = exc
    with pytest.raises(https.FetchError, match=text):
        https.fetch_policy("h")
    assert fake_conn.instances[0].closed
