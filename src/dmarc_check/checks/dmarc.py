"""DMARC (RFC 7489 / DMARCbis): presence, uniqueness, policy, pct and reporting."""

from __future__ import annotations

import re

from ..findings import Severity
from . import Context, parse_tags

CHECK = "dmarc"
POLICIES = {"none", "quarantine", "reject"}
KNOWN_TAGS = {"v", "p", "sp", "np", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri", "t", "psd"}
_MAILTO = re.compile(r"^mailto:[^@\s]+@[^@\s]+\.[^@\s]+(?:!\d+[kmgt]?)?$", re.IGNORECASE)


def _is_dmarc(txt: str) -> bool:
    first = txt.split(";", 1)[0].replace(" ", "").lower()
    return first == "v=dmarc1"


def check_dmarc(ctx: Context) -> None:
    name = "_dmarc." + ctx.domain
    ans = ctx.resolver.txt(name)
    records = [t for t in ans.records if _is_dmarc(t)]
    if not records:
        ctx.add(CHECK, "dmarc-not-found", Severity.ERROR, f"No DMARC record at {name}")
        return
    if len(records) > 1:
        ctx.add(
            CHECK,
            "dmarc-multiple-records",
            Severity.ERROR,
            f"{len(records)} DMARC records at {name}; receivers ignore all of them",
        )
        return

    tags, bad = parse_tags(records[0])
    keys = [k.lower() for k, _ in tags]
    values = {k.lower(): v for k, v in tags}
    problems = [f"malformed tag {b!r}" for b in bad]
    dupes = sorted({k for k in keys if keys.count(k) > 1})
    problems += [f"duplicate tag {k}=" for k in dupes]
    for tag in ("adkim", "aspf"):
        if tag in values and values[tag].lower() not in ("r", "s"):
            problems.append(f"{tag}={values[tag]} must be r or s")
    pct: int | None = None
    if "pct" in values:
        try:
            pct = int(values["pct"])
            if not 0 <= pct <= 100:
                raise ValueError
        except ValueError:
            problems.append(f"pct={values['pct']} must be an integer from 0 to 100")
            pct = None
    if problems:
        ctx.add(CHECK, "dmarc-syntax-error", Severity.ERROR, "DMARC record is invalid: " + "; ".join(problems))

    p = values.get("p", "").lower()
    if "p" not in values:
        ctx.add(CHECK, "dmarc-invalid-policy", Severity.ERROR, "DMARC record has no p= tag")
    elif p not in POLICIES:
        ctx.add(
            CHECK,
            "dmarc-invalid-policy",
            Severity.ERROR,
            f"p={values['p']} is not none, quarantine or reject",
        )
    elif p == "none":
        ctx.add(
            CHECK,
            "dmarc-policy-none",
            Severity.WARN,
            "DMARC policy is p=none: spoofed mail is reported but still delivered",
        )

    for tag in ("sp", "np"):
        if tag not in values:
            continue
        value = values[tag].lower()
        if value not in POLICIES:
            ctx.add(
                CHECK,
                "dmarc-invalid-policy",
                Severity.ERROR,
                f"{tag}={values[tag]} is not none, quarantine or reject",
            )
        elif value == "none" and p in ("quarantine", "reject"):
            what = "subdomains" if tag == "sp" else "non-existent subdomains"
            ctx.add(
                CHECK,
                "dmarc-subdomain-policy-none",
                Severity.WARN,
                f"{tag}=none leaves {what} unprotected although p={p}",
            )

    if pct is not None and pct < 100:
        ctx.add(
            CHECK,
            "dmarc-partial-pct",
            Severity.WARN,
            f"pct={pct}: the policy only applies to {pct}% of failing mail",
        )
    if values.get("t", "").lower() == "y":
        ctx.add(
            CHECK,
            "dmarc-testing-mode",
            Severity.WARN,
            "t=y: receivers are asked to apply a less strict policy (testing mode)",
        )

    if not values.get("rua"):
        ctx.add(
            CHECK,
            "dmarc-no-rua",
            Severity.INFO,
            "No rua= tag: you will not receive aggregate DMARC reports",
        )
    for tag in ("rua", "ruf"):
        for uri in filter(None, (u.strip() for u in values.get(tag, "").split(","))):
            if not _MAILTO.match(uri):
                ctx.add(
                    CHECK,
                    "dmarc-invalid-report-uri",
                    Severity.WARN,
                    f"{tag} URI {uri!r} is not a valid mailto: address",
                )

    unknown = [k for k in dict.fromkeys(keys) if k not in KNOWN_TAGS]
    if unknown:
        ctx.add(
            CHECK,
            "dmarc-unknown-tag",
            Severity.INFO,
            "Unknown DMARC tag(s) ignored by receivers: " + ", ".join(unknown),
        )
