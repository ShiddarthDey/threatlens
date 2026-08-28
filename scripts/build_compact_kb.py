"""Build a compact ATT&CK KB from the `attack-stix-lookup` PyPI package
(bundles lookup data derived from official MITRE enterprise-attack STIX).

Use when downloading the full ~50 MB STIX bundle is not possible.
The full bundle (scripts/download_attack.py) remains the preferred authority.

  pip install attack-stix-lookup
  python scripts/build_compact_kb.py
"""
from __future__ import annotations

import importlib.resources as ir
import json
from datetime import datetime, timezone
from pathlib import Path

DEST = Path(__file__).resolve().parent.parent / "data" / "attack_kb_compact.json"


def _load(name_part: str) -> dict:
    data_dir = ir.files("attack_stix_lookup") / "data"
    for f in data_dir.iterdir():
        if name_part in f.name:
            return json.loads(f.read_text(encoding="utf-8"))
    raise FileNotFoundError(name_part)


def main():
    ap = _load("attack-patterns-lookup")
    gc = _load("groups-campaigns-lookup")
    sw = _load("software-lookup")

    techniques, revoked = {}, []
    for t in ap["attack_patterns"]:
        tid = t["external_id"]
        techniques[tid] = t["name"]
        if t.get("revoked") or t.get("deprecated"):
            revoked.append(tid)

    actor_aliases = {}
    for g in gc["groups_campaigns"]:
        if g.get("stix_type") != "intrusion-set":
            continue
        for alias in {g["name"], *(g.get("aliases") or [])}:
            if alias:
                actor_aliases[alias.lower()] = g["name"]

    malware = sorted({a.lower()
                      for s in sw["software"]
                      for a in {s["name"], *(s.get("aliases") or [])} if a})

    out = {
        "_metadata": {
            "built_at": datetime.now(timezone.utc).isoformat(),
            "source": "PyPI package attack-stix-lookup "
                      "(derived from official mitre-attack STIX bundle)",
            "source_metadata": ap.get("_metadata", {}),
            "note": "Fallback KB. Prefer full STIX bundle via "
                    "scripts/download_attack.py when network allows.",
        },
        "techniques": techniques,
        "revoked": revoked,
        "actor_aliases": actor_aliases,
        "malware_names": malware,
    }
    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {DEST} | techniques={len(techniques)} "
          f"actors={len(actor_aliases)} malware={len(malware)}")


if __name__ == "__main__":
    main()
