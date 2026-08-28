"""Ingestion from MISP OSINT feeds (CIRCL, botvrij.eu).

These feeds are TLP:WHITE / explicitly published for reuse — license-clean
for a research corpus, unlike vendor blog scraping.

  CIRCL:   https://www.circl.lu/doc/misp/feed-osint/
  botvrij: https://www.botvrij.eu/data/feed-osint/
"""
from __future__ import annotations

import logging

import requests

from .schema import Report

log = logging.getLogger(__name__)

FEEDS = {
    "circl": "https://www.circl.lu/doc/misp/feed-osint",
    "botvrij": "https://www.botvrij.eu/data/feed-osint",
}
UA = {"User-Agent": "ThreatLens-research/0.1 (academic research)"}


def event_to_report(event: dict, feed: str) -> Report:
    """Normalize a MISP event JSON into a Report. The report text is the
    event narrative (info + text/comment attributes) plus the indicator
    list — indicators are first-class data in MISP, so including them keeps
    the provenance check fair."""
    e = event["Event"]
    lines = [e.get("info", ""), f"Event date: {e.get('date','')}", ""]
    indicators, context = [], []
    for a in e.get("Attribute", []):
        t, v = a.get("type", ""), a.get("value", "")
        if t in ("text", "comment", "other"):
            context.append(v)
        elif t == "link":
            context.append(f"Reference: {v}")
        else:
            indicators.append(f"{t}: {v}")
        if a.get("comment"):
            context.append(a["comment"])
    # Objects (newer MISP events) also carry attributes
    for obj in e.get("Object", []):
        for a in obj.get("Attribute", []):
            indicators.append(f"{a.get('type','')}: {a.get('value','')}")
    if context:
        lines += ["Context:", *dict.fromkeys(context), ""]
    if indicators:
        lines += ["Indicators:", *indicators]
    return Report(
        source=f"misp-{feed}",
        source_id=e["uuid"],
        title=e.get("info", ""),
        url=f"{FEEDS[feed]}/{e['uuid']}.json",
        published=e.get("date", ""),
        text="\n".join(lines),
    )


def fetch_misp(feed: str = "circl", limit: int = 20) -> list[Report]:
    base = FEEDS[feed]
    manifest = requests.get(f"{base}/manifest.json", headers=UA, timeout=60).json()
    # newest first by event timestamp
    uuids = sorted(manifest, key=lambda u: int(manifest[u].get("timestamp", 0)),
                   reverse=True)[:limit]
    reports = []
    for u in uuids:
        try:
            ev = requests.get(f"{base}/{u}.json", headers=UA, timeout=60).json()
            reports.append(event_to_report(ev, feed))
        except (requests.RequestException, KeyError, ValueError) as ex:
            log.warning("MISP event %s failed: %s", u, ex)
    log.info("Fetched %d MISP events from %s", len(reports), feed)
    return reports
