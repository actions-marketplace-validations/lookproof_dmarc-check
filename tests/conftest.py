from __future__ import annotations

from collections.abc import Callable

import pytest

from dmarc_check.checks import Context
from dmarc_check.dns_client import AddrAnswer, DnsError, MxAnswer, TxtAnswer, normalize
from dmarc_check.https import FetchError, PolicyResponse

TIMEOUT = object()
SERVFAIL = object()


class FakeResolver:
    """In-memory DNS. Missing names are NXDOMAIN; an empty list is NODATA."""

    def __init__(self) -> None:
        self.txt_records: dict[str, object] = {}
        self.mx_records: dict[str, object] = {}
        self.addr_records: dict[str, object] = {}
        self.queries: list[tuple[str, str]] = []

    def _get(self, table: dict[str, object], name: str, rdtype: str) -> tuple[str, list]:  # type: ignore[type-arg]
        name = normalize(name)
        self.queries.append((rdtype, name))
        value = table.get(name)
        if value is TIMEOUT:
            raise DnsError(name, rdtype, "timeout", timeout=True)
        if value is SERVFAIL:
            raise DnsError(name, rdtype, "SERVFAIL")
        if value is None:
            return "nxdomain", []
        assert isinstance(value, list)
        return ("ok" if value else "nodata"), value

    def txt(self, name: str) -> TxtAnswer:
        status, records = self._get(self.txt_records, name, "TXT")
        return TxtAnswer(status, list(records))  # type: ignore[arg-type]

    def mx(self, name: str) -> MxAnswer:
        status, records = self._get(self.mx_records, name, "MX")
        return MxAnswer(status, sorted(records))  # type: ignore[arg-type]

    def addresses(self, name: str) -> AddrAnswer:
        status, records = self._get(self.addr_records, name, "A")
        return AddrAnswer(status, list(records))  # type: ignore[arg-type]


class FakeFetcher:
    def __init__(self) -> None:
        self.responses: dict[str, PolicyResponse | FetchError] = {}
        self.calls: list[str] = []

    def __call__(self, host: str) -> PolicyResponse:
        self.calls.append(host)
        resp = self.responses.get(host)
        if resp is None:
            raise FetchError("connection failed: name not found")
        if isinstance(resp, FetchError):
            raise resp
        return resp


@pytest.fixture
def dns() -> FakeResolver:
    return FakeResolver()


@pytest.fixture
def fetcher() -> FakeFetcher:
    return FakeFetcher()


@pytest.fixture
def make_ctx(dns: FakeResolver, fetcher: FakeFetcher) -> Callable[..., Context]:
    def make(
        domain: str = "example.com", selectors: list[str] | None = None, mx_hosts: list[str] | None = None
    ) -> Context:
        return Context(domain, dns, fetcher, selectors or [], mx_hosts=list(mx_hosts or []))

    return make


def ids(ctx: Context) -> list[str]:
    return [f.id for f in ctx.findings]


def policy(text: str, status: int = 200, content_type: str = "text/plain") -> PolicyResponse:
    return PolicyResponse(status, content_type, text.encode())
