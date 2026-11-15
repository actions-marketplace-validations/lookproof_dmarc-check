# dmarc-check

Checks a domain's mail authentication records (SPF, DMARC, DKIM, MX, MTA-STS and TLS-RPT) in CI. It is a GitHub Action and a command line tool, and both use the same engine.

All checks are local DNS lookups made with [dnspython](https://www.dnspython.org/), plus one HTTPS request for the MTA-STS policy. The tool sends nothing to Lookproof or anyone else and has no telemetry. Each finding links to a page on [lookproof.dev/findings](https://lookproof.dev/findings) that explains it and how to fix it.

## What it checks

| Area | Checks |
| --- | --- |
| SPF | A record exists and there is exactly one. Syntax is valid. At most 10 DNS lookups, counted recursively through `include:` and `redirect=`. At most 2 void lookups. Includes that are missing or loop. `+all` (error) and `?all` (warning). |
| DMARC | A record exists at `_dmarc.<domain>` and there is exactly one. `p`, `sp` and `np` are valid, with a warning for `p=none` and for `sp=none` or `np=none` under an enforcing `p`. Warns when `pct` is below 100 or `t=y` is set. Notes a missing `rua` (info). |
| DKIM | Only the selectors you pass in. The key exists, there is one record and it parses. RSA keys under 2048 bits warn; keys under 1024 bits are an error. Revoked keys (`p=`) and testing mode (`t=y`). Ed25519 is supported. |
| MX | MX records exist. Null MX (`0 .`, RFC 7505) is recognised: the domain counts as accepting no mail, and MTA-STS and TLS-RPT are skipped. Null MX mixed with other records, MX targets that are IP addresses, and MX hosts without A/AAAA records. |
| MTA-STS | The `_mta-sts` TXT record (`v=STSv1`, `id`). The policy is fetched from `https://mta-sts.<domain>/.well-known/mta-sts.txt` with certificate and host name validation. Redirects are not followed, and the response must be `text/plain` and at most 64 KiB. Checks the policy syntax, `mode`, a `max_age` of at least one day, and that every MX host matches an `mx:` line. |
| TLS-RPT | `_smtp._tls` has one `v=TLSRPTv1` record with a `rua` of `mailto:` or `https:` URIs. |

DNS timeouts and resolver failures are reported as errors, so a check that could not run never passes silently.

## Quick start

### Check on pull requests

```yaml
# .github/workflows/mail-auth.yml
name: Mail authentication
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  dmarc-check:
    runs-on: ubuntu-latest
    steps:
      - uses: lookproof/dmarc-check@v1
        with:
          domains: example.com, example.org
          dkim-selectors: google, s1
          fail-on: error
```

### Daily check that opens an issue

The action opens one issue while the check fails, updates it on later runs, and closes it once the check passes. Issues are matched on their exact title.

```yaml
# .github/workflows/mail-auth-daily.yml
name: Mail authentication (daily)
on:
  schedule:
    - cron: "23 5 * * *"
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  dmarc-check:
    runs-on: ubuntu-latest
    steps:
      - uses: lookproof/dmarc-check@v1
        with:
          domains: example.com
          dkim-selectors: google
          fail-on: warn
          create-issue: true
```

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `domains` | (required) | Comma-separated domains. |
| `dkim-selectors` | `""` | Comma-separated DKIM selectors, checked on every domain. DKIM is skipped when this is empty. |
| `fail-on` | `error` | `error`, `warn`, `info` or `none`, and/or a comma list of finding ids. A severity fails on that severity or worse. Ids fail on that finding whatever its severity. You can combine them, e.g. `error,dmarc-policy-none`. |
| `resolver` | `""` | Comma-separated DNS server IPs. Defaults to the runner's resolver. |
| `create-issue` | `false` | Open, update and close one tracking issue. Needs `issues: write`. |
| `issue-title` | `dmarc-check: mail authentication problems` | Title used to find the tracking issue. |
| `github-token` | `${{ github.token }}` | Token for `create-issue`. |
| `python-version` | `3.12` | Python used to run the tool. It is not added to `PATH` for later steps. |

### Outputs

| Output | Description |
| --- | --- |
| `json` | Every finding as JSON (same format as `dmarc-check --json`). |
| `exit-code` | `0` when nothing matches `fail-on`, `1` when something does, `2` on invalid input. |

The step exits with the same code, so a failing check fails the job. To keep going and read the result yourself, set `continue-on-error: true` on the step and read `steps.<id>.outputs.json`.

## Summary output

The action writes a table to the job summary. Findings that match `fail-on` are shown in bold:

> ## dmarc-check
>
> **❌ Failed** (fail-on: `error`): 1 error, 2 warnings, 1 info
>
> | Domain | Severity | Finding | Details |
> | --- | --- | --- | --- |
> | example.com | **error** | [`spf-too-many-lookups`](https://lookproof.dev/findings/spf-too-many-lookups) | SPF needs 13 DNS lookups (limit 10) |
> | example.com | warn | [`dmarc-policy-none`](https://lookproof.dev/findings/dmarc-policy-none) | DMARC policy is p=none: spoofed mail is reported but still delivered |
> | example.com | warn | [`dkim-weak-key`](https://lookproof.dev/findings/dkim-weak-key) | Selector s1: 1024-bit RSA key; use 2048 bits |
> | example.com | info | [`tlsrpt-not-found`](https://lookproof.dev/findings/tlsrpt-not-found) | No TLS-RPT record at \_smtp.\_tls.example.com; you will not hear about inbound TLS failures |
> | example.org | ok | | No findings |
>
> Want daily monitoring, alerts and DMARC report parsing? → https://senderward.com

Findings that match `fail-on` are also added to the run as error annotations.

## Command line

```bash
pip install dmarc-check
```

```bash
dmarc-check example.com --dkim-selector s1 --json
```

```
usage: dmarc-check [-h] [--dkim-selector SELECTOR] [--fail-on FAIL_ON] [--resolver IP]
                   [--timeout TIMEOUT] [--json] [--version]
                   domains [domains ...]
```

`--dkim-selector` and `--resolver` can be repeated or comma-separated. The exit codes are the same as the action's: `0` passed, `1` a finding matched `--fail-on`, `2` invalid arguments.

Text output:

```
example.com
  error  spf-too-many-lookups *
         SPF needs 13 DNS lookups (limit 10)
         https://lookproof.dev/findings/spf-too-many-lookups
  warn   dmarc-policy-none
         DMARC policy is p=none: spoofed mail is reported but still delivered
         https://lookproof.dev/findings/dmarc-policy-none

FAILED (fail-on: error): 1 error, 1 warning, 0 info
* = matches fail-on
```

JSON output:

```json
{
  "tool": "dmarc-check",
  "version": "1.0.0",
  "fail_on": "error",
  "failed": true,
  "exit_code": 1,
  "counts": { "error": 1, "warn": 1, "info": 0 },
  "domains": [
    {
      "domain": "example.com",
      "findings": [
        {
          "id": "spf-too-many-lookups",
          "severity": "error",
          "check": "spf",
          "domain": "example.com",
          "message": "SPF needs 13 DNS lookups (limit 10)",
          "url": "https://lookproof.dev/findings/spf-too-many-lookups"
        }
      ]
    }
  ]
}
```

## Findings

| Id | Severity | Meaning |
| --- | --- | --- |
| [`spf-not-found`](https://lookproof.dev/findings/spf-not-found) | error | No SPF record. |
| [`spf-multiple-records`](https://lookproof.dev/findings/spf-multiple-records) | error | More than one SPF record on the domain or an included domain. |
| [`spf-syntax-error`](https://lookproof.dev/findings/spf-syntax-error) | error | Unknown mechanism, bad IP or prefix, invalid domain, duplicate modifier. |
| [`spf-too-many-lookups`](https://lookproof.dev/findings/spf-too-many-lookups) | error | More than 10 DNS-querying terms, counted recursively. |
| [`spf-too-many-void-lookups`](https://lookproof.dev/findings/spf-too-many-void-lookups) | error | More than 2 lookups returned NXDOMAIN or no data. |
| [`spf-include-not-found`](https://lookproof.dev/findings/spf-include-not-found) | error | An `include:` or `redirect=` target has no SPF record. |
| [`spf-include-loop`](https://lookproof.dev/findings/spf-include-loop) | error | Includes or redirects form a loop. |
| [`spf-pass-all`](https://lookproof.dev/findings/spf-pass-all) | error | The record ends in `+all` (or bare `all`). |
| [`spf-neutral-all`](https://lookproof.dev/findings/spf-neutral-all) | warn | The record ends in `?all`. |
| [`spf-ptr-mechanism`](https://lookproof.dev/findings/spf-ptr-mechanism) | warn | Uses the deprecated `ptr` mechanism. |
| [`spf-no-all`](https://lookproof.dev/findings/spf-no-all) | info | No `all` and no `redirect=`. |
| [`spf-macro-not-evaluated`](https://lookproof.dev/findings/spf-macro-not-evaluated) | info | Macro terms are counted but not resolved. |
| [`dmarc-not-found`](https://lookproof.dev/findings/dmarc-not-found) | error | No DMARC record at `_dmarc.<domain>`. |
| [`dmarc-multiple-records`](https://lookproof.dev/findings/dmarc-multiple-records) | error | More than one DMARC record. |
| [`dmarc-syntax-error`](https://lookproof.dev/findings/dmarc-syntax-error) | error | Malformed or duplicate tags, bad `pct`, `adkim` or `aspf`. |
| [`dmarc-invalid-policy`](https://lookproof.dev/findings/dmarc-invalid-policy) | error | `p` is missing, or `p`, `sp` or `np` has an invalid value. |
| [`dmarc-policy-none`](https://lookproof.dev/findings/dmarc-policy-none) | warn | `p=none`. |
| [`dmarc-subdomain-policy-none`](https://lookproof.dev/findings/spoof-subdomains-unprotected) | warn | `sp=none` or `np=none` while `p` enforces. |
| [`dmarc-partial-pct`](https://lookproof.dev/findings/dmarc-partial-pct) | warn | `pct` below 100. |
| [`dmarc-testing-mode`](https://lookproof.dev/findings/dmarc-testing-mode) | warn | `t=y`. |
| [`dmarc-invalid-report-uri`](https://lookproof.dev/findings/dmarc-invalid-report-uri) | warn | A `rua` or `ruf` URI is not a valid `mailto:`. |
| [`dmarc-no-rua`](https://lookproof.dev/findings/dmarc-no-rua) | info | No `rua` tag, so no aggregate reports are sent. |
| [`dmarc-unknown-tag`](https://lookproof.dev/findings/dmarc-unknown-tag) | info | Tags that receivers ignore. |
| [`dkim-not-found`](https://lookproof.dev/findings/dkim-not-found) | error | No key at `<selector>._domainkey.<domain>`. |
| [`dkim-multiple-records`](https://lookproof.dev/findings/dkim-multiple-records) | error | More than one key record for a selector. |
| [`dkim-syntax-error`](https://lookproof.dev/findings/dkim-syntax-error) | error | Malformed tags, or `v=` that is not `DKIM1` or not first. |
| [`dkim-invalid-key`](https://lookproof.dev/findings/dkim-invalid-key) | error | The key is not valid base64, cannot be parsed, or has an unknown `k=`. |
| [`dkim-key-too-short`](https://lookproof.dev/findings/dkim-weak-key) | error | RSA key under 1024 bits. |
| [`dkim-weak-key`](https://lookproof.dev/findings/dkim-weak-key) | warn | RSA key from 1024 up to 2047 bits. |
| [`dkim-key-revoked`](https://lookproof.dev/findings/dkim-key-revoked) | warn | Empty `p=`. |
| [`dkim-testing-mode`](https://lookproof.dev/findings/dkim-testing-mode) | info | `t=y`. |
| [`dns-domain-not-found`](https://lookproof.dev/findings/dns-domain-not-found) | error | The domain does not exist (NXDOMAIN). |
| [`mx-null-with-others`](https://lookproof.dev/findings/mx-null-with-others) | error | A null MX next to other MX records. |
| [`mx-target-is-ip`](https://lookproof.dev/findings/mx-target-is-ip) | error | An MX points to an IP address. |
| [`mx-target-unresolvable`](https://lookproof.dev/findings/mx-target-unresolvable) | error | An MX host has no A or AAAA record. |
| [`mx-not-found`](https://lookproof.dev/findings/mx-not-found) | warn | No MX records (implicit MX via A/AAAA). |
| [`mx-null`](https://lookproof.dev/findings/mx-null) | info | Null MX: the domain accepts no mail. |
| [`mtasts-multiple-records`](https://lookproof.dev/findings/mtasts-multiple-records) | error | More than one `_mta-sts` record. |
| [`mtasts-invalid-record`](https://lookproof.dev/findings/mtasts-invalid-record) | error | The `_mta-sts` record lacks `v=STSv1` or a valid `id`. |
| [`mtasts-policy-unavailable`](https://lookproof.dev/findings/mtasts-policy-unavailable) | error | The policy could not be fetched: TLS or certificate error, redirect, or a status other than 200. |
| [`mtasts-invalid-policy`](https://lookproof.dev/findings/mtasts-invalid-policy) | error | Wrong content type, too large, or invalid policy fields. |
| [`mtasts-mx-not-covered`](https://lookproof.dev/findings/mtasts-mx-not-covered) | error | An MX host matches no `mx:` line in an `enforce` policy. |
| [`mtasts-mx-not-covered-testing`](https://lookproof.dev/findings/mtasts-mx-not-covered-testing) | warn | Same, in a `testing` policy. |
| [`mtasts-mode-none`](https://lookproof.dev/findings/mtasts-mode-none) | warn | `mode: none`. |
| [`mtasts-low-max-age`](https://lookproof.dev/findings/mtasts-low-max-age) | warn | `max_age` under 86400 seconds. |
| [`mtasts-mode-testing`](https://lookproof.dev/findings/mtasts-mode-testing) | info | `mode: testing`. |
| [`mtasts-not-found`](https://lookproof.dev/findings/mtasts-not-found) | info | No MTA-STS record. |
| [`tlsrpt-invalid`](https://lookproof.dev/findings/tlsrpt-invalid) | warn | Several records, a missing `rua`, or a URI that is not `mailto:` or `https:`. |
| [`tlsrpt-not-found`](https://lookproof.dev/findings/tlsrpt-not-found) | info | No TLS-RPT record. |
| [`dns-resolver-timeout`](https://lookproof.dev/findings/dns-resolver-timeout) | error | A DNS query timed out, so the check is incomplete. |
| [`dns-resolver-failure`](https://lookproof.dev/findings/dns-resolver-failure) | error | A DNS query failed (SERVFAIL, refused), so the check is incomplete. |
| [`check-internal-error`](https://lookproof.dev/findings/check-internal-error) | error | A bug in dmarc-check. Please open an issue. |

## Development

```bash
pip install -e ".[dev]"
```

```bash
ruff check . && ruff format --check . && mypy && pytest
```

The unit tests use a fake resolver and need no network. `pytest -m network` checks that every finding link exists in the lookproof.dev sitemap.

## License

MIT
