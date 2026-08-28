"""Ingestion of real threat reports from public CTI sources.

Sources:
  - CISA cybersecurity advisories (RSS feed -> advisory pages). No key needed.
  - AlienVault OTX pulses. Requires free API key in env OTX_API_KEY.

All network calls are real; nothing is mocked or fabricated.
"""
from __future__ import annotations

import logging
import os
import re
import time
import xml.etree.ElementTree as ET

import requests

from .schema import Report

log = logging.getLogger(__name__)

UA = {"User-Agent": "ThreatLens-research/0.1 (academic research; contact: see repo)"}
CISA_FEED = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
OTX_API = "https://otx.alienvault.com/api/v1"

_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_HTML_RE = re.compile(r"<[^>]+>")


def html_to_text(html: str) -> str:
    """Minimal, dependency-free HTML -> text. Good enough for advisories."""
    txt = _TAG_RE.sub(" ", html)
    txt = re.sub(r"<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", txt, flags=re.I)
    txt = _HTML_RE.sub(" ", txt)
    txt = txt.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    txt = txt.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    txt = re.sub(r"[ \t]+", " ", txt)
    txt = re.sub(r"\n\s*\n+", "\n\n", txt)
    return txt.strip()


def fetch_cisa(limit: int = 20, delay: float = 1.0) -> list[Report]:
    """Fetch recent CISA advisories via the public RSS feed."""
    r = requests.get(CISA_FEED, headers=UA, timeout=30)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    reports: list[Report] = []
    for item in root.iter("item"):
        if len(reports) >= limit:
            break
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        if not link:
            continue
        try:
            page = requests.get(link, headers=UA, timeout=30)
            page.raise_for_status()
            text = html_to_text(page.text)
        except requests.RequestException as e:
            log.warning("CISA fetch failed for %s: %s", link, e)
            continue
        # advisory ID is usually the last URL segment, e.g. aa24-131a
        source_id = link.rstrip("/").rsplit("/", 1)[-1]
        reports.append(Report(
            source="cisa", source_id=source_id, title=title,
            url=link, published=pub, text=text,
        ))
        time.sleep(delay)  # be polite
    log.info("Fetched %d CISA advisories", len(reports))
    return reports


def fetch_otx(limit: int = 20, modified_since: str | None = None) -> list[Report]:
    """Fetch subscribed OTX pulses. Requires OTX_API_KEY env var (free account)."""
    key = os.environ.get("OTX_API_KEY")
    if not key:
        raise RuntimeError(
            "OTX_API_KEY not set. Create a free account at otx.alienvault.com, "
            "copy the key from Settings, and put it in .env or your environment."
        )
    headers = {**UA, "X-OTX-API-KEY": key}
    params: dict = {"limit": min(limit, 50)}
    if modified_since:
        params["modified_since"] = modified_since
    r = requests.get(f"{OTX_API}/pulses/subscribed", headers=headers,
                     params=params, timeout=30)
    r.raise_for_status()
    reports: list[Report] = []
    for p in r.json().get("results", [])[:limit]:
        body = p.get("description") or ""
        # Append the pulse's own IoC list as text so provenance checking is fair:
        # OTX descriptions are often short; indicators are first-class data here.
        inds = p.get("indicators") or []
        if inds:
            body += "\n\nIndicators:\n" + "\n".join(
                f"{i.get('type','?')}: {i.get('indicator','')}" for i in inds
            )
        reports.append(Report(
            source="otx", source_id=str(p.get("id", "")),
            title=p.get("name", ""),
            url=f"https://otx.alienvault.com/pulse/{p.get('id','')}",
            published=p.get("created", ""), text=body,
        ))
    log.info("Fetched %d OTX pulses", len(reports))
    return reports
