"""Entry point for the GitHub Action (``python -m dmarc_check.action``).

Inputs arrive as ``DMARC_CHECK_*`` environment variables set by action.yml.
"""

from __future__ import annotations

import os
import secrets
import sys
from collections.abc import Mapping

from .dns_client import DnsResolver, Resolver
from .engine import EXIT_USAGE, UsageError, parse_fail_on, parse_list, run, validate_domain
from .github import GitHubClient, GitHubError, sync_issue
from .https import PolicyFetcher
from .report import to_json, to_markdown, to_text

DEFAULT_ISSUE_TITLE = "dmarc-check: mail authentication problems"


def _escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _append(path: str | None, text: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)


def _set_output(path: str | None, name: str, value: str) -> None:
    delimiter = f"EOF_{secrets.token_hex(8)}"
    _append(path, f"{name}<<{delimiter}\n{value}\n{delimiter}\n")


def main(
    env: Mapping[str, str] | None = None,
    resolver: Resolver | None = None,
    fetcher: PolicyFetcher | None = None,
    client: GitHubClient | None = None,
) -> int:
    env = os.environ if env is None else env
    try:
        domains = [validate_domain(d) for d in parse_list([env.get("DMARC_CHECK_DOMAINS", "")])]
        if not domains:
            raise UsageError("the domains input is empty")
        fail_on = parse_fail_on(env.get("DMARC_CHECK_FAIL_ON", "error"))
    except UsageError as exc:
        print(f"::error title=dmarc-check::{_escape(str(exc))}")
        return EXIT_USAGE

    selectors = parse_list([env.get("DMARC_CHECK_DKIM_SELECTORS", "")])
    if resolver is None:
        nameservers = parse_list([env.get("DMARC_CHECK_RESOLVER", "")])
        resolver = DnsResolver(nameservers or None)
    report = run(domains, resolver, selectors, fail_on, fetcher)

    print(to_text(report))
    for f in report.failing:
        print(f"::error title=dmarc-check {f.id} ({f.domain})::{_escape(f.message)} {f.url}")

    _append(env.get("GITHUB_STEP_SUMMARY"), to_markdown(report))
    _set_output(env.get("GITHUB_OUTPUT"), "json", to_json(report))
    _set_output(env.get("GITHUB_OUTPUT"), "exit-code", str(report.exit_code))

    if _bool(env.get("DMARC_CHECK_CREATE_ISSUE", "false")):
        title = env.get("DMARC_CHECK_ISSUE_TITLE", "").strip() or DEFAULT_ISSUE_TITLE
        run_url = ""
        if env.get("GITHUB_RUN_ID"):
            server = env.get("GITHUB_SERVER_URL", "https://github.com")
            run_url = f"{server}/{env.get('GITHUB_REPOSITORY', '')}/actions/runs/{env['GITHUB_RUN_ID']}"
        body = to_markdown(report, heading="## dmarc-check report", footer=False)
        if run_url:
            body += f"\nLast checked by [this workflow run]({run_url}). "
        body += "This issue is updated by dmarc-check and closed automatically when the checks pass.\n"
        try:
            gh = client or GitHubClient(
                env.get("DMARC_CHECK_GITHUB_TOKEN", ""),
                env.get("GITHUB_REPOSITORY", ""),
                env.get("GITHUB_API_URL", "https://api.github.com"),
            )
            print(sync_issue(gh, title, report.failed, body))
        except GitHubError as exc:
            print(f"::error title=dmarc-check issue::{_escape(str(exc))}")
            return max(report.exit_code, 1)

    return report.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
