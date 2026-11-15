"""Every finding must link to a page that exists on lookproof.dev.

Needs the network, so it is excluded by default. Run it with ``pytest -m network``.
"""

from __future__ import annotations

import re
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from dmarc_check.findings import FINDINGS_BASE_URL, REGISTRY

SITEMAP = "https://lookproof.dev/sitemap.xml"
NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}


def _sitemap_urls(url: str, depth: int = 0) -> set[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "dmarc-check-tests"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        root = ET.fromstring(resp.read())
    locs = {el.text.strip() for el in root.iterfind(".//sm:loc", NS) if el.text}
    if root.tag.endswith("sitemapindex") and depth < 2:
        return set().union(*(_sitemap_urls(loc, depth + 1) for loc in locs))
    return {loc.rstrip("/") for loc in locs}


@pytest.mark.network
def test_all_finding_links_exist() -> None:
    urls = _sitemap_urls(SITEMAP)
    missing = sorted({FINDINGS_BASE_URL + slug for slug in REGISTRY.values()} - urls)
    assert not missing, "finding pages not in sitemap: " + ", ".join(missing)


@pytest.mark.network
def test_readme_links_exist() -> None:
    urls = _sitemap_urls(SITEMAP)
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    linked = {m.rstrip("/") for m in re.findall(r"https://lookproof\.dev/findings/[a-z0-9-]+", readme)}
    assert linked
    missing = sorted(linked - urls)
    assert not missing, "README links to finding pages not in sitemap: " + ", ".join(missing)
