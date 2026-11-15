"""Rendering of a :class:`Report` as text, JSON and Markdown."""

from __future__ import annotations

import json

from .engine import Report

SENDERWARD_LINE = "Want daily monitoring, alerts and DMARC report parsing? → https://senderward.com"
_ORDER = {"error": 0, "warn": 1, "info": 2}


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _counts_line(report: Report) -> str:
    c = report.counts()
    return f"{_plural(c['error'], 'error')}, {_plural(c['warn'], 'warning')}, {c['info']} info"


def to_text(report: Report) -> str:
    lines: list[str] = []
    for result in report.results:
        lines.append(result.domain)
        if not result.findings:
            lines.append("  ok     no findings")
        for f in sorted(result.findings, key=lambda f: _ORDER[f.severity.value]):
            marker = " *" if report.fail_on.matches(f) else ""
            lines.append(f"  {f.severity.value:<6} {f.id}{marker}")
            lines.append(f"         {f.message}")
            lines.append(f"         {f.url}")
        lines.append("")
    verdict = "FAILED" if report.failed else "passed"
    lines.append(f"{verdict} (fail-on: {report.fail_on.describe()}): {_counts_line(report)}")
    if report.failed:
        lines.append("* = matches fail-on")
    return "\n".join(lines)


def _cell(text: str) -> str:
    # Messages quote DNS data, so neutralise anything that renders as markup,
    # links or @mentions in a step summary or issue.
    out = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for ch in "\\`*_[]|":
        out = out.replace(ch, "\\" + ch)
    return out.replace("@", "&#64;").replace("\n", " ")


def to_markdown(report: Report, heading: str = "## dmarc-check", footer: bool = True) -> str:
    verdict = "❌ Failed" if report.failed else "✅ Passed"
    lines = [
        heading,
        "",
        f"**{verdict}** (fail-on: `{report.fail_on.describe()}`): {_counts_line(report)}",
        "",
        "| Domain | Severity | Finding | Details |",
        "| --- | --- | --- | --- |",
    ]
    for result in report.results:
        if not result.findings:
            lines.append(f"| {result.domain} | ok | | No findings |")
        for f in sorted(result.findings, key=lambda f: _ORDER[f.severity.value]):
            sev = f"**{f.severity.value}**" if report.fail_on.matches(f) else f.severity.value
            lines.append(f"| {result.domain} | {sev} | [`{f.id}`]({f.url}) | {_cell(f.message)} |")
    lines.append("")
    if footer:
        lines.append(SENDERWARD_LINE)
        lines.append("")
    return "\n".join(lines)
