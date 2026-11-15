"""SPF (RFC 7208): presence, uniqueness, syntax, lookup limits and ``all``."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ..dns_client import normalize
from ..findings import Severity
from . import Context

CHECK = "spf"
MAX_LOOKUPS = 10
MAX_VOID_LOOKUPS = 2
# Keep resolving past the limit so the report can say how far over it is,
# but stop eventually so a hostile record cannot make us walk forever.
HARD_CAP = 40

MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
_MODIFIER = re.compile(r"^([a-z][a-z0-9_.\-]*)=(.*)$", re.IGNORECASE)
_MACRO = re.compile(r"%(?:\{[slodiphcrtv]\d*r?[.\-+,/_=]*\}|%|_|-)", re.IGNORECASE)
_LABEL = re.compile(r"^(?!-)[a-z0-9_\-]{1,63}(?<!-)$", re.IGNORECASE)
_CIDR = re.compile(r"^(?P<spec>.*?)(?:/(?P<c4>\d+))?(?://(?P<c6>\d+))?$")


def is_spf(txt: str) -> bool:
    lowered = txt.strip().lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def _valid_domain_spec(spec: str) -> bool:
    if "%" in spec:
        # Strip valid macros and make sure nothing malformed is left.
        return "%" not in _MACRO.sub("", spec)
    labels = spec.rstrip(".").split(".")
    return len(labels) >= 2 and all(_LABEL.match(label) for label in labels)


@dataclass
class _State:
    ctx: Context
    lookups: int = 0
    void: int = 0
    stack: list[str] = field(default_factory=list)
    macros_seen: bool = False

    def report(self, fid: str, severity: Severity, message: str) -> None:
        self.ctx.add(CHECK, fid, severity, message)


@dataclass
class _Term:
    qualifier: str
    name: str
    arg: str | None


def _parse(record: str, where: str, st: _State) -> tuple[list[_Term], dict[str, str]] | None:
    """Parse an SPF record. Reports a syntax error and returns None on failure."""
    terms: list[_Term] = []
    modifiers: dict[str, str] = {}
    errors: list[str] = []
    for raw in record.split()[1:]:
        mod = _MODIFIER.match(raw)
        if mod and mod.group(1).lower() not in MECHANISMS:
            name, value = mod.group(1).lower(), mod.group(2)
            if name in modifiers and name in ("redirect", "exp"):
                errors.append(f"duplicate {name}= modifier")
            elif name in ("redirect", "exp") and not _valid_domain_spec(value):
                errors.append(f"invalid domain in {raw!r}")
            modifiers[name] = value
            continue
        qualifier = "+"
        body = raw
        if body[:1] in "+-~?":
            qualifier, body = body[0], body[1:]
        name, sep, arg = body.partition(":")
        name = name.lower()
        if "/" in name and name.split("/", 1)[0] in ("a", "mx"):
            # a/24 or mx//64 without a domain-spec
            name, cidr = name.split("/", 1)
            arg, sep = "/" + cidr, ""
        if name not in MECHANISMS:
            errors.append(f"unknown mechanism {raw!r}")
            continue
        problem = _check_arg(name, arg if (sep or arg) else None)
        if problem:
            errors.append(f"{problem} in {raw!r}")
            continue
        terms.append(_Term(qualifier, name, arg if (sep or arg) else None))
    if errors:
        st.report(
            "spf-syntax-error",
            Severity.ERROR,
            f"SPF record{where} is invalid: " + "; ".join(errors),
        )
        return None
    return terms, modifiers


def _check_arg(name: str, arg: str | None) -> str | None:
    if name == "all":
        return "all takes no argument" if arg else None
    if name in ("include", "exists"):
        if not arg:
            return f"{name} needs a domain"
        return None if _valid_domain_spec(arg) else "invalid domain"
    if name in ("a", "mx"):
        if not arg:
            return None
        m = _CIDR.match(arg)
        assert m is not None
        if m.group("c4") is not None and not 0 <= int(m.group("c4")) <= 32:
            return "invalid IPv4 prefix length"
        if m.group("c6") is not None and not 0 <= int(m.group("c6")) <= 128:
            return "invalid IPv6 prefix length"
        spec = m.group("spec")
        if spec and not _valid_domain_spec(spec):
            return "invalid domain"
        return None
    if name == "ptr":
        return None if not arg or _valid_domain_spec(arg) else "invalid domain"
    if name in ("ip4", "ip6"):
        if not arg:
            return f"{name} needs an address"
        try:
            net = ipaddress.ip_network(arg, strict=False)
        except ValueError:
            return "invalid address"
        if (name == "ip4") != (net.version == 4):
            return "address family does not match mechanism"
        return None
    return None  # pragma: no cover


def _target(arg: str | None, domain: str) -> str:
    if not arg:
        return domain
    m = _CIDR.match(arg)
    spec = m.group("spec") if m else arg
    return normalize(spec) if spec else domain


def _fetch_spf(st: _State, target: str, via: str) -> str | None:
    """Fetch the single SPF record of an include/redirect target."""
    ans = st.ctx.resolver.txt(target)
    records = [t for t in ans.records if is_spf(t)]
    if ans.status != "ok" or not ans.records:
        st.void += 1
    if not records:
        st.report(
            "spf-include-not-found",
            Severity.ERROR,
            f"{via}:{target} has no SPF record (this is a permanent error)",
        )
        return None
    if len(records) > 1:
        st.report(
            "spf-multiple-records",
            Severity.ERROR,
            f"{via}:{target} publishes {len(records)} SPF records",
        )
        return None
    return records[0]


def _evaluate(st: _State, domain: str, record: str) -> None:
    where = "" if not st.stack else f" of {domain} (via {' -> '.join(st.stack)})"
    parsed = _parse(record, where, st)
    if parsed is None:
        return
    terms, modifiers = parsed
    st.stack.append(domain)
    try:
        for term in terms:
            if term.name not in LOOKUP_TERMS:
                continue
            st.lookups += 1
            if term.name == "ptr" and len(st.stack) == 1:
                st.report(
                    "spf-ptr-mechanism",
                    Severity.WARN,
                    "SPF uses the ptr mechanism, which is slow and deprecated (RFC 7208 5.5)",
                )
            if st.lookups > HARD_CAP:
                return
            target = _target(term.arg, domain)
            if "%" in target:
                st.macros_seen = True
                continue
            if term.name == "include":
                _descend(st, target, "include")
            elif term.name == "a" or term.name == "exists":
                if st.ctx.resolver.addresses(target).status != "ok":
                    st.void += 1
            elif term.name == "mx" and st.ctx.resolver.mx(target).status != "ok":
                st.void += 1
        redirect = modifiers.get("redirect")
        has_all = any(t.name == "all" for t in terms)
        if redirect and not has_all:
            st.lookups += 1
            if st.lookups > HARD_CAP:
                return
            if "%" in redirect:
                st.macros_seen = True
            else:
                _descend(st, normalize(redirect), "redirect")
    finally:
        st.stack.pop()


def _descend(st: _State, target: str, via: str) -> None:
    if target in st.stack:
        st.report(
            "spf-include-loop",
            Severity.ERROR,
            f"SPF {via} loop: {' -> '.join([*st.stack, target])}",
        )
        return
    record = _fetch_spf(st, target, via)
    if record is not None:
        _evaluate(st, target, record)


def _top_level_all(record: str) -> tuple[str | None, bool]:
    qualifier = None
    has_redirect = False
    for raw in record.split()[1:]:
        low = raw.lower()
        if low.startswith("redirect="):
            has_redirect = True
        body = low[1:] if low[:1] in "+-~?" else low
        if body == "all":
            qualifier = low[0] if low[0] in "+-~?" else "+"
    return qualifier, has_redirect


def check_spf(ctx: Context) -> None:
    ans = ctx.resolver.txt(ctx.domain)
    records = [t for t in ans.records if is_spf(t)]
    if not records:
        ctx.add(CHECK, "spf-not-found", Severity.ERROR, f"No SPF record on {ctx.domain}")
        return
    if len(records) > 1:
        ctx.add(
            CHECK,
            "spf-multiple-records",
            Severity.ERROR,
            f"{len(records)} SPF records on {ctx.domain}; there must be exactly one",
        )
        return
    record = records[0]
    st = _State(ctx)
    _evaluate(st, ctx.domain, record)

    if st.lookups > MAX_LOOKUPS:
        count = f"more than {HARD_CAP}" if st.lookups > HARD_CAP else str(st.lookups)
        ctx.add(
            CHECK,
            "spf-too-many-lookups",
            Severity.ERROR,
            f"SPF needs {count} DNS lookups (limit {MAX_LOOKUPS})",
        )
    if st.void > MAX_VOID_LOOKUPS:
        ctx.add(
            CHECK,
            "spf-too-many-void-lookups",
            Severity.ERROR,
            f"SPF has {st.void} void lookups (limit {MAX_VOID_LOOKUPS})",
        )
    if st.macros_seen:
        ctx.add(
            CHECK,
            "spf-macro-not-evaluated",
            Severity.INFO,
            "SPF uses macros; macro targets were counted but not resolved",
        )

    qualifier, has_redirect = _top_level_all(record)
    if qualifier == "+":
        ctx.add(
            CHECK,
            "spf-pass-all",
            Severity.ERROR,
            "SPF ends in +all, which authorises every server on the internet",
        )
    elif qualifier == "?":
        ctx.add(
            CHECK,
            "spf-neutral-all",
            Severity.WARN,
            "SPF ends in ?all (neutral), which gives no protection",
        )
    elif qualifier is None and not has_redirect:
        ctx.add(
            CHECK,
            "spf-no-all",
            Severity.INFO,
            "SPF has no all mechanism; unmatched senders default to neutral",
        )
