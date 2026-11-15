"""Strict HTTPS fetch of an MTA-STS policy (RFC 8461 section 3.3).

The certificate and host name are validated, redirects are never followed and
the response size is capped. ``HTTPS_PROXY`` / ``NO_PROXY`` are honoured so the
tool works on self-hosted runners behind a proxy.
"""

from __future__ import annotations

import http.client
import ssl
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

MAX_POLICY_BYTES = 64 * 1024
POLICY_PATH = "/.well-known/mta-sts.txt"


@dataclass
class PolicyResponse:
    status: int
    content_type: str
    body: bytes
    location: str | None = None


class FetchError(Exception):
    pass


PolicyFetcher = Callable[[str], PolicyResponse]


def _proxy_for(host: str) -> tuple[str, int] | None:
    proxies = urllib.request.getproxies()
    proxy = proxies.get("https")
    if not proxy or urllib.request.proxy_bypass(host):
        return None
    parsed = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    if not parsed.hostname:
        return None
    return parsed.hostname, parsed.port or 8080


def fetch_policy(host: str, timeout: float = 10.0) -> PolicyResponse:
    context = ssl.create_default_context()
    proxy = _proxy_for(host)
    if proxy:
        conn = http.client.HTTPSConnection(proxy[0], proxy[1], timeout=timeout, context=context)
        conn.set_tunnel(host, 443)
    else:
        conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=context)
    try:
        conn.request("GET", POLICY_PATH, headers={"User-Agent": "dmarc-check", "Accept": "text/plain"})
        resp = conn.getresponse()
        body = resp.read(MAX_POLICY_BYTES + 1)
        return PolicyResponse(
            status=resp.status,
            content_type=resp.getheader("Content-Type", "") or "",
            body=body,
            location=resp.getheader("Location"),
        )
    except ssl.SSLCertVerificationError as exc:
        raise FetchError(f"TLS certificate validation failed: {exc.verify_message}") from exc
    except ssl.SSLError as exc:
        raise FetchError(f"TLS error: {getattr(exc, 'reason', None) or exc}") from exc
    except TimeoutError as exc:
        raise FetchError("connection timed out") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(f"connection failed: {exc}") from exc
    finally:
        conn.close()
