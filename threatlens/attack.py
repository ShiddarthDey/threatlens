"""MITRE ATT&CK STIX 2.1 knowledge base — offline authority for verification.

Download once with scripts/download_attack.py (~50 MB enterprise bundle).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
DEFAULT_PATH = Path("data/enterprise-attack.json")
COMPACT_PATH = Path("data/attack_kb_compact.json")


class AttackKB:
    """Indexes techniques (external ID -> name) and intrusion-set aliases.

    Loads the full STIX bundle if present, else the compact fallback KB
    (built by scripts/build_compact_kb.py from the attack-stix-lookup
    PyPI package, itself derived from the official MITRE STIX bundle).
    """

    def __init__(self, bundle_path: Path | str = DEFAULT_PATH):
        p = Path(bundle_path)
        self.techniques: dict[str, str] = {}
        self.revoked: set[str] = set()
        self.actor_aliases: dict[str, str] = {}
        self.malware_names: set[str] = set()

        if not p.exists():
            compact = p.parent / COMPACT_PATH.name
            if compact.exists():
                self._load_compact(compact)
                return
            raise FileNotFoundError(
                f"Neither {p} nor {compact} found. Run "
                "scripts/download_attack.py (preferred) or "
                "scripts/build_compact_kb.py."
            )
        with open(p, encoding="utf-8") as f:
            bundle = json.load(f)

        for obj in bundle.get("objects", []):
            t = obj.get("type")
            if t == "attack-pattern":
                ext_id = _ext_id(obj)
                if not ext_id:
                    continue
                self.techniques[ext_id] = obj.get("name", "")
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    self.revoked.add(ext_id)
            elif t == "intrusion-set":
                canon = obj.get("name", "")
                for alias in [canon, *obj.get("aliases", [])]:
                    if alias:
                        self.actor_aliases[alias.lower()] = canon
            elif t in ("malware", "tool"):
                for alias in [obj.get("name", ""), *obj.get("x_mitre_aliases", [])]:
                    if alias:
                        self.malware_names.add(alias.lower())

        log.info("ATT&CK KB: %d techniques, %d actor aliases, %d malware/tools",
                 len(self.techniques), len(self.actor_aliases),
                 len(self.malware_names))

    def _load_compact(self, path: Path):
        with open(path, encoding="utf-8") as f:
            kb = json.load(f)
        self.techniques = kb["techniques"]
        self.revoked = set(kb.get("revoked", []))
        self.actor_aliases = kb["actor_aliases"]
        self.malware_names = set(kb["malware_names"])
        log.info("ATT&CK KB (compact fallback, %s): %d techniques, "
                 "%d actor aliases, %d malware/tools",
                 kb.get("_metadata", {}).get("source", "?"),
                 len(self.techniques), len(self.actor_aliases),
                 len(self.malware_names))

    def technique_name(self, tid: str) -> str | None:
        return self.techniques.get(tid.upper())

    def is_valid_technique(self, tid: str) -> bool:
        return tid.upper() in self.techniques

    def resolve_actor(self, name: str) -> str | None:
        return self.actor_aliases.get(name.lower().strip())

    def is_known_malware(self, name: str) -> bool:
        return name.lower().strip() in self.malware_names


def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None
