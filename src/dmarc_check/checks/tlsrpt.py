"""SMTP TLS reporting (RFC 8460)."""

from __future__ import annotations

from ..findings import Severity
from . import Context, parse_tags

CHECK = "tls-rpt"


def _is_tlsrpt(txt: str) -> bool:
    return txt.split(";", 1)[0].replace(" ", "") == "v=TLSRPTv1"


def check_tlsrpt(ctx: Context) -> None:
    name = "_smtp._tls." + ctx.domain
    ans = ctx.resolver.txt(name)
    records = [t for t in ans.records if _is_tlsrpt(t)]
    if not records:
        ctx.add(
            CHECK,
            "tlsrpt-not-found",
            Severity.INFO,
            f"No TLS-RPT record at {name}; you will not hear about inbound TLS failures",
        )
        return
    if len(records) > 1:
        ctx.add(CHECK, "tlsrpt-invalid", Severity.WARN, f"{len(records)} TLS-RPT records at {name}; there must be one")
        return
    tags, _ = parse_tags(records[0])
    values = dict(tags)
    rua = [u.strip() for u in values.get("rua", "").split(",") if u.strip()]
    if not rua:
        ctx.add(CHECK, "tlsrpt-invalid", Severity.WARN, f"TLS-RPT record at {name} has no rua=")
        return
    bad = [u for u in rua if not (u.lower().startswith("mailto:") or u.lower().startswith("https://"))]
    if bad:
        ctx.add(
            CHECK,
            "tlsrpt-invalid",
            Severity.WARN,
            "TLS-RPT rua must be mailto: or https: URIs: " + ", ".join(bad),
        )
