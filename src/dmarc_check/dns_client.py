"""Thin DNS layer over dnspython.

Checks only talk to the :class:`Resolver` protocol, so tests can swap in a
fake without touching the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

Status = Literal["ok", "nxdomain", "nodata"]


class DnsError(Exception):
    """A lookup that could not be answered (timeout, SERVFAIL, refused ...)."""

    def __init__(self, name: str, rdtype: str, reason: str, timeout: bool = False):
        super().__init__(f"{rdtype} lookup for {name} failed: {reason}")
        self.name = name
        self.rdtype = rdtype
        self.reason = reason
        self.timeout = timeout


@dataclass
class TxtAnswer:
    status: Status
    records: list[str] = field(default_factory=list)


@dataclass
class MxAnswer:
    status: Status
    # (preference, exchange) with the exchange lower-cased and without the
    # trailing dot. The root name (null MX) is represented as "".
    records: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class AddrAnswer:
    status: Status
    records: list[str] = field(default_factory=list)


class Resolver(Protocol):
    def txt(self, name: str) -> TxtAnswer: ...

    def mx(self, name: str) -> MxAnswer: ...

    def addresses(self, name: str) -> AddrAnswer: ...


def normalize(name: str) -> str:
    return name.strip().rstrip(".").lower()


class DnsResolver:
    """Resolver backed by dnspython with a per-run cache."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        self._r = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            self._r.nameservers = nameservers
        self._r.lifetime = timeout
        self._r.timeout = min(timeout, 2.0)
        self._cache: dict[tuple[str, str], tuple[Status, list[object]]] = {}

    def _query(self, name: str, rdtype: str) -> tuple[Status, list[object]]:
        key = (normalize(name), rdtype)
        if key in self._cache:
            return self._cache[key]
        try:
            answer = self._r.resolve(key[0] + ".", rdtype, search=False)
            result: tuple[Status, list[object]] = ("ok", list(answer))
        except dns.resolver.NXDOMAIN:
            result = ("nxdomain", [])
        except dns.resolver.NoAnswer:
            result = ("nodata", [])
        except dns.resolver.LifetimeTimeout as exc:
            raise DnsError(key[0], rdtype, "timeout", timeout=True) from exc
        except dns.resolver.NoNameservers as exc:
            raise DnsError(key[0], rdtype, "no nameserver answered (SERVFAIL)") from exc
        except dns.exception.DNSException as exc:
            raise DnsError(key[0], rdtype, str(exc) or type(exc).__name__) from exc
        self._cache[key] = result
        return result

    def txt(self, name: str) -> TxtAnswer:
        status, rrs = self._query(name, "TXT")
        out = []
        for rr in rrs:
            strings = getattr(rr, "strings", ())
            out.append(b"".join(strings).decode("utf-8", "replace"))
        return TxtAnswer(status, out)

    def mx(self, name: str) -> MxAnswer:
        status, rrs = self._query(name, "MX")
        out = []
        for rr in rrs:
            exchange = normalize(rr.exchange.to_text())  # type: ignore[attr-defined]
            out.append((int(rr.preference), exchange))  # type: ignore[attr-defined]
        return MxAnswer(status, sorted(out))

    def addresses(self, name: str) -> AddrAnswer:
        s4, a = self._query(name, "A")
        if s4 == "nxdomain":
            return AddrAnswer("nxdomain")
        _, aaaa = self._query(name, "AAAA")
        records = [rr.to_text() for rr in a + aaaa]  # type: ignore[attr-defined]
        return AddrAnswer("ok" if records else "nodata", records)
