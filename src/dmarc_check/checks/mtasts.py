"""MTA-STS (RFC 8461): TXT record, HTTPS policy, mode and MX coverage."""

from __future__ import annotations

import re

from ..findings import Severity
from ..https import MAX_POLICY_BYTES, FetchError
from . import Context, parse_tags

CHECK = "mta-sts"
MIN_MAX_AGE = 86400
MAX_MAX_AGE = 31557600
_ID = re.compile(r"^[A-Za-z0-9]{1,32}$")


def _is_sts(txt: str) -> bool:
    return txt.split(";", 1)[0].replace(" ", "") == "v=STSv1"


def mx_matches(pattern: str, host: str) -> bool:
    pattern = pattern.strip().rstrip(".").lower()
    host = host.rstrip(".").lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and "." not in host[: -len(suffix)] and len(host) > len(suffix)
    return host == pattern


def parse_policy(text: str) -> tuple[dict[str, str], list[str], list[str]]:
    """Return (fields, mx patterns, problems)."""
    fields: dict[str, str] = {}
    mx: list[str] = []
    problems: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not sep or not key:
            problems.append(f"malformed line {line.strip()!r}")
            continue
        if key == "mx":
            mx.append(value)
        elif key in fields and key in ("version", "mode", "max_age"):
            problems.append(f"duplicate {key}")
        else:
            fields[key] = value
    if fields.get("version") != "STSv1":
        problems.append("version must be STSv1")
    mode = fields.get("mode")
    if mode not in ("enforce", "testing", "none"):
        problems.append("mode must be enforce, testing or none")
    max_age = fields.get("max_age", "")
    if not max_age.isdigit() or int(max_age) > MAX_MAX_AGE:
        problems.append(f"max_age must be an integer from 0 to {MAX_MAX_AGE}")
    if mode in ("enforce", "testing") and not mx:
        problems.append("no mx: lines")
    return fields, mx, problems


def check_mtasts(ctx: Context) -> None:
    name = "_mta-sts." + ctx.domain
    ans = ctx.resolver.txt(name)
    records = [t for t in ans.records if _is_sts(t)]
    if not records:
        ctx.add(
            CHECK,
            "mtasts-not-found",
            Severity.INFO,
            f"No MTA-STS record at {name}; inbound TLS can be downgraded",
        )
        return
    if len(records) > 1:
        ctx.add(
            CHECK,
            "mtasts-multiple-records",
            Severity.ERROR,
            f"{len(records)} MTA-STS records at {name}; senders treat this as no policy",
        )
        return
    tags, bad = parse_tags(records[0])
    values = dict(tags)
    if bad or not _ID.match(values.get("id", "")):
        ctx.add(
            CHECK,
            "mtasts-invalid-record",
            Severity.ERROR,
            f"MTA-STS record at {name} needs v=STSv1 and an id= of 1-32 letters/digits",
        )
        return

    host = "mta-sts." + ctx.domain
    url = f"https://{host}/.well-known/mta-sts.txt"
    try:
        resp = ctx.fetch_policy(host)
    except FetchError as exc:
        ctx.add(CHECK, "mtasts-policy-unavailable", Severity.ERROR, f"Could not fetch {url}: {exc}")
        return
    if 300 <= resp.status < 400:
        ctx.add(
            CHECK,
            "mtasts-policy-unavailable",
            Severity.ERROR,
            f"{url} redirects (HTTP {resp.status}); redirects are not allowed",
        )
        return
    if resp.status != 200:
        ctx.add(CHECK, "mtasts-policy-unavailable", Severity.ERROR, f"{url} returned HTTP {resp.status}")
        return
    media_type = resp.content_type.split(";", 1)[0].strip().lower()
    if media_type != "text/plain":
        ctx.add(
            CHECK,
            "mtasts-invalid-policy",
            Severity.ERROR,
            f"{url} is served as {media_type or 'no content type'}; it must be text/plain",
        )
        return
    if len(resp.body) > MAX_POLICY_BYTES:
        ctx.add(CHECK, "mtasts-invalid-policy", Severity.ERROR, f"{url} is larger than {MAX_POLICY_BYTES} bytes")
        return
    try:
        text = resp.body.decode("utf-8")
    except UnicodeDecodeError:
        ctx.add(CHECK, "mtasts-invalid-policy", Severity.ERROR, f"{url} is not valid UTF-8")
        return

    fields, patterns, problems = parse_policy(text)
    if problems:
        ctx.add(CHECK, "mtasts-invalid-policy", Severity.ERROR, "MTA-STS policy is invalid: " + "; ".join(problems))
        return
    mode = fields["mode"]
    if mode == "none":
        ctx.add(CHECK, "mtasts-mode-none", Severity.WARN, "MTA-STS policy mode is none (policy withdrawn)")
        return
    if mode == "testing":
        ctx.add(
            CHECK,
            "mtasts-mode-testing",
            Severity.INFO,
            "MTA-STS policy mode is testing: failures are reported, not enforced",
        )
    if int(fields["max_age"]) < MIN_MAX_AGE:
        ctx.add(
            CHECK,
            "mtasts-low-max-age",
            Severity.WARN,
            f"max_age={fields['max_age']} is under one day ({MIN_MAX_AGE})",
        )
    uncovered = [h for h in ctx.mx_hosts if not any(mx_matches(p, h) for p in patterns)]
    if uncovered:
        if mode == "enforce":
            ctx.add(
                CHECK,
                "mtasts-mx-not-covered",
                Severity.ERROR,
                "MX host(s) not covered by the enforced MTA-STS policy, mail to them will fail: "
                + ", ".join(uncovered),
            )
        else:
            ctx.add(
                CHECK,
                "mtasts-mx-not-covered-testing",
                Severity.WARN,
                "MX host(s) not covered by the MTA-STS policy: " + ", ".join(uncovered),
            )
