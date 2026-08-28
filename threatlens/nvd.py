"""NVD API 2.0 client with on-disk cache and rate limiting.

Free: 5 req/30s without key; 50 req/30s with free key (env NVD_API_KEY).
https://nvd.nist.gov/developers/vulnerabilities
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path

import requests

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_FORMAT = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class NVDClient:
    def __init__(self, cache_dir: Path | str = "data/nvd_cache"):
        self.cache = Path(cache_dir)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.api_key = os.environ.get("NVD_API_KEY")
        self._min_interval = 0.7 if self.api_key else 6.5  # stay under limits
        self._last_call = 0.0

    def lookup(self, cve_id: str) -> dict | None:
        """Return {'exists': bool, 'description': str, 'published': str} or
        None on API failure (failure != non-existence; verifier treats None
        as 'unverifiable', never as 'fabricated')."""
        cve_id = cve_id.upper().strip()
        if not CVE_FORMAT.match(cve_id):
            return {"exists": False, "reason": "malformed_id"}

        cached = self.cache / f"{cve_id}.json"
        if cached.exists():
            return json.loads(cached.read_text(encoding="utf-8"))

        self._throttle()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            r = requests.get(NVD_URL, params={"cveId": cve_id},
                             headers=headers, timeout=30)
            if r.status_code == 404:
                result = {"exists": False, "reason": "not_in_nvd"}
            else:
                r.raise_for_status()
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    result = {"exists": False, "reason": "not_in_nvd"}
                else:
                    cve = vulns[0]["cve"]
                    desc = next((d["value"] for d in cve.get("descriptions", [])
                                 if d.get("lang") == "en"), "")
                    result = {
                        "exists": True,
                        "description": desc,
                        "published": cve.get("published", ""),
                        "status": cve.get("vulnStatus", ""),
                    }
        except requests.RequestException as e:
            log.warning("NVD lookup failed for %s: %s", cve_id, e)
            return None  # do NOT cache failures

        if not result.get("exists"):
            # NVD enrichment lag: fresh CVEs (e.g. cited in same-week CISA
            # advisories) often aren't in NVD yet. Cross-check CVE.org (CNA
            # records) before declaring non-existence.
            alt = self._cve_org(cve_id)
            if alt is None:
                result["secondary_check"] = "cve.org_unavailable"
                return result  # don't cache an unconfirmed negative
            if alt.get("exists"):
                alt["reason"] = "in_cve_org_not_nvd_yet"
                result = alt
            else:
                result["reason"] = "not_in_nvd_or_cve_org"

        cached.write_text(json.dumps(result), encoding="utf-8")
        return result

    def _cve_org(self, cve_id: str) -> dict | None:
        """Secondary authority: CVE.org CNA records (cveawg.mitre.org).
        Returns None when unreachable — caller must not treat that as
        non-existence."""
        try:
            r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}",
                             timeout=30)
            if r.status_code == 404:
                return {"exists": False}
            r.raise_for_status()
            data = r.json()
            state = data.get("cveMetadata", {}).get("state", "")
            desc = next((d.get("value", "") for d in data.get("containers", {})
                         .get("cna", {}).get("descriptions", [])
                         if d.get("lang", "").startswith("en")), "")
            return {"exists": state in ("PUBLISHED", "RESERVED"),
                    "state": state, "description": desc, "source": "cve.org"}
        except (requests.RequestException, ValueError) as e:
            log.warning("CVE.org lookup failed for %s: %s", cve_id, e)
            return None

    def _throttle(self):
        wait = self._min_interval - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.time()
