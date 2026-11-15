from __future__ import annotations

import json
from pathlib import Path

import pytest

import dmarc_check.cli as cli
from dmarc_check import action
from dmarc_check.github import ISSUE_MARKER, GitHubClient, GitHubError, sync_issue
from dmarc_check.report import SENDERWARD_LINE

from .test_engine_report import healthy

# CLI


@pytest.fixture
def patched_cli(monkeypatch, dns, fetcher):
    healthy(dns, fetcher)
    seen: dict[str, object] = {}

    def fake_resolver(nameservers=None, timeout=5.0):
        seen["nameservers"] = nameservers
        seen["timeout"] = timeout
        return dns

    monkeypatch.setattr(cli, "DnsResolver", fake_resolver)
    import dmarc_check.engine as engine

    monkeypatch.setattr(engine, "fetch_policy", fetcher)
    return seen


def test_cli_json_pass(patched_cli, capsys) -> None:
    code = cli.main(["example.com", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["failed"] is False


def test_cli_text_fail_and_selector(patched_cli, dns, capsys) -> None:
    code = cli.main(["example.com", "--dkim-selector", "s1", "--resolver", "1.1.1.1", "--timeout", "3"])
    out = capsys.readouterr().out
    assert code == 1
    assert "dkim-not-found" in out
    assert ("TXT", "s1._domainkey.example.com") in dns.queries
    assert patched_cli == {"nameservers": ["1.1.1.1"], "timeout": 3.0}


def test_cli_fail_on_none(patched_cli) -> None:
    assert cli.main(["example.com", "-s", "s1", "--fail-on", "none"]) == 0


def test_cli_usage_errors(patched_cli, capsys) -> None:
    assert cli.main(["not a domain"]) == 2
    assert cli.main(["example.com", "--fail-on", "bogus"]) == 2
    assert "bogus" in capsys.readouterr().err


# Action


def _env(tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "DMARC_CHECK_DOMAINS": "example.com",
        "DMARC_CHECK_FAIL_ON": "error",
    }
    env.update(extra)
    return env


def _outputs(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    lines = path.read_text().splitlines()
    i = 0
    while i < len(lines):
        name, _, delim = lines[i].partition("<<")
        end = lines.index(delim, i + 1)
        out[name] = "\n".join(lines[i + 1 : end])
        i = end + 1
    return out


def test_action_pass(tmp_path, dns, fetcher, capsys) -> None:
    healthy(dns, fetcher)
    code = action.main(_env(tmp_path), resolver=dns, fetcher=fetcher)
    assert code == 0
    summary = (tmp_path / "summary.md").read_text()
    assert summary.strip().splitlines()[-1] == SENDERWARD_LINE
    outputs = _outputs(tmp_path / "output")
    assert outputs["exit-code"] == "0"
    assert json.loads(outputs["json"])["domains"][0]["domain"] == "example.com"
    assert "::error" not in capsys.readouterr().out


def test_action_fail_emits_annotations(tmp_path, dns, fetcher, capsys) -> None:
    healthy(dns, fetcher)
    env = _env(tmp_path, DMARC_CHECK_DKIM_SELECTORS="s1, s2", DMARC_CHECK_FAIL_ON="error")
    code = action.main(env, resolver=dns, fetcher=fetcher)
    out = capsys.readouterr().out
    assert code == 1
    assert out.count("::error title=dmarc-check dkim-not-found") == 2
    assert _outputs(tmp_path / "output")["exit-code"] == "1"
    summary = (tmp_path / "summary.md").read_text()
    assert summary.count("senderward.com") == 1


def test_action_usage_error(tmp_path, dns, capsys) -> None:
    assert action.main(_env(tmp_path, DMARC_CHECK_DOMAINS=" "), resolver=dns) == 2
    assert action.main(_env(tmp_path, DMARC_CHECK_FAIL_ON="nope"), resolver=dns) == 2
    assert "::error title=dmarc-check::" in capsys.readouterr().out


class FakeGitHub(GitHubClient):
    def __init__(self, issues: list[dict[str, object]] | None = None) -> None:
        super().__init__("token", "lookproof/test")
        self.issues = issues or []
        self.calls: list[tuple[str, str, dict[str, object] | None]] = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET":
            return self.issues if path.endswith("&page=1") else []
        if method == "POST" and path == "/issues":
            return {"number": 7}
        return {}


def test_action_creates_issue(tmp_path, dns, fetcher, capsys) -> None:
    healthy(dns, fetcher)
    gh = FakeGitHub()
    env = _env(tmp_path, DMARC_CHECK_DKIM_SELECTORS="s1", DMARC_CHECK_CREATE_ISSUE="true", GITHUB_RUN_ID="42")
    code = action.main(env, resolver=dns, fetcher=fetcher, client=gh)
    assert code == 1
    method, path, body = gh.calls[-1]
    assert (method, path) == ("POST", "/issues")
    assert body is not None
    assert body["title"] == action.DEFAULT_ISSUE_TITLE
    text = str(body["body"])
    assert ISSUE_MARKER in text
    assert "dkim-not-found" in text
    assert "actions/runs/42" in text
    assert "senderward" not in text
    assert "Opened issue #7" in capsys.readouterr().out


def test_action_issue_error_fails_step(tmp_path, dns, fetcher) -> None:
    healthy(dns, fetcher)
    env = _env(tmp_path, DMARC_CHECK_CREATE_ISSUE="true", DMARC_CHECK_GITHUB_TOKEN="")
    assert action.main(env, resolver=dns, fetcher=fetcher) == 1


def test_sync_issue_updates_existing() -> None:
    gh = FakeGitHub([{"number": 3, "title": "T"}, {"number": 4, "title": "T", "pull_request": {}}])
    assert sync_issue(gh, "T", True, "body") == "Updated issue #3"
    assert gh.calls[-1][0:2] == ("PATCH", "/issues/3")


def test_sync_issue_dedupes_on_title_only() -> None:
    gh = FakeGitHub([{"number": 3, "title": "Other"}])
    assert sync_issue(gh, "T", True, "body") == "Opened issue #7"


def test_sync_issue_closes_when_green() -> None:
    gh = FakeGitHub([{"number": 3, "title": "T"}])
    assert sync_issue(gh, "T", False, "body") == "Closed issue #3"
    assert gh.calls[-2][0:2] == ("POST", "/issues/3/comments")
    method, path, body = gh.calls[-1]
    assert (method, path) == ("PATCH", "/issues/3")
    assert body is not None and body["state"] == "closed"


def test_sync_issue_noop_when_green_and_none_open() -> None:
    gh = FakeGitHub()
    assert sync_issue(gh, "T", False, "body") == "No open issue and nothing failing"
    assert [c[0] for c in gh.calls] == ["GET"]


def test_find_open_issue_paginates() -> None:
    class Paged(FakeGitHub):
        def request(self, method, path, body=None):
            self.calls.append((method, path, body))
            if path.endswith("&page=1"):
                return [{"number": i, "title": f"x{i}"} for i in range(100)]
            return [{"number": 500, "title": "T"}]

    gh = Paged()
    issue = gh.find_open_issue("T")
    assert issue is not None and issue["number"] == 500
    assert len(gh.calls) == 2


def test_github_client_validation() -> None:
    with pytest.raises(GitHubError):
        GitHubClient("", "a/b")
    with pytest.raises(GitHubError):
        GitHubClient("t", "nope")


def test_github_client_request(monkeypatch) -> None:
    import io
    import urllib.error
    import urllib.request

    captured = {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["auth"] = req.get_header("Authorization")
        captured["data"] = req.data
        return Resp(b'{"number": 1}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    gh = GitHubClient("tok", "o/r", "https://ghe.example/api/v3/")
    assert gh.request("POST", "/issues", {"title": "x"}) == {"number": 1}
    assert captured["url"] == "https://ghe.example/api/v3/repos/o/r/issues"
    assert captured["auth"] == "Bearer tok"
    assert json.loads(captured["data"]) == {"title": "x"}

    def http_error(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"denied"))  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", http_error)
    with pytest.raises(GitHubError, match="issues: write"):
        gh.request("GET", "/issues")

    def url_error(req, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", url_error)
    with pytest.raises(GitHubError, match="offline"):
        gh.request("GET", "/issues")


def test_github_client_rejects_non_http_api_url() -> None:
    with pytest.raises(GitHubError):
        GitHubClient("t", "a/b", "file:///etc/passwd")
