"""MX records, including null MX (RFC 7505)."""

from __future__ import annotations

import ipaddress

from ..findings import Severity
from . import Context

CHECK = "mx"


class DomainNotFound(Exception):
    pass


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def check_mx(ctx: Context) -> None:
    ans = ctx.resolver.mx(ctx.domain)
    if ans.status == "nxdomain":
        ctx.add("dns", "dns-domain-not-found", Severity.ERROR, f"{ctx.domain} does not exist (NXDOMAIN)")
        raise DomainNotFound(ctx.domain)
    if not ans.records:
        ctx.add(
            CHECK,
            "mx-not-found",
            Severity.WARN,
            f"No MX records on {ctx.domain}; senders fall back to its A/AAAA record. "
            "Publish a null MX (0 .) if the domain receives no mail",
        )
        return
    hosts = [host for _, host in ans.records]
    if "" in hosts:
        if len(hosts) > 1:
            ctx.add(
                CHECK,
                "mx-null-with-others",
                Severity.ERROR,
                "Null MX (0 .) is published together with other MX records",
            )
        else:
            ctx.null_mx = True
            ctx.add(
                CHECK,
                "mx-null",
                Severity.INFO,
                f"{ctx.domain} publishes a null MX and accepts no mail; MTA-STS and TLS-RPT are skipped",
            )
            return
    for host in hosts:
        if not host:
            continue
        if _is_ip(host):
            ctx.add(CHECK, "mx-target-is-ip", Severity.ERROR, f"MX target {host} is an IP address, not a host name")
            continue
        ctx.mx_hosts.append(host)
        if ctx.resolver.addresses(host).status != "ok":
            ctx.add(
                CHECK,
                "mx-target-unresolvable",
                Severity.ERROR,
                f"MX host {host} has no A or AAAA record",
            )
