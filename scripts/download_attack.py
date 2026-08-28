"""Download the MITRE ATT&CK Enterprise STIX 2.1 bundle (~50 MB)."""
import sys
from pathlib import Path

import requests

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
       "master/enterprise-attack/enterprise-attack.json")
DEST = Path(__file__).resolve().parent.parent / "data" / "enterprise-attack.json"


def main():
    DEST.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading ATT&CK Enterprise bundle -> {DEST}")
    with requests.get(URL, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(DEST, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
    print(f"Done: {DEST.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    sys.exit(main())
