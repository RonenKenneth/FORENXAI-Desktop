"""
update_suricata_rules.py
------------------------
Downloads the Emerging Threats Open ruleset for the installed Suricata and
writes it, with Suricata's own decoder and stream event rules (used for
Evasion), to <repo>/tools/suricata/et-open.rules -- the file
packet_rule_service.run_suricata loads when rules.json names no rules_file.

    python update_suricata_rules.py [--version 7.0.3]

Rerun it to update the signatures; the case report records the ruleset date.
"""
from __future__ import annotations

import argparse
import io
import tarfile
import urllib.request
from datetime import date
from pathlib import Path

from app.services.packet_rule_service import DEFAULT_RULES_FILE, _suricata_binary

URL = "https://rules.emergingthreats.net/open/suricata-{version}/emerging.rules.tar.gz"
EVENT_RULES = ("decoder-events.rules", "stream-events.rules")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="7.0.3", help="ET Open build to fetch (Suricata 7.x)")
    args = ap.parse_args()

    url = URL.format(version=args.version)
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response:
        archive = response.read()
    parts = [f"# ET Open {args.version}, downloaded {date.today().isoformat()}\n"]
    count = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in sorted(tar.getmembers(), key=lambda m: m.name):
            if member.isfile() and member.name.endswith(".rules"):
                text = tar.extractfile(member).read().decode("utf-8", "replace")
                count += sum(1 for line in text.splitlines() if line.startswith("alert"))
                parts.append(f"\n# ---- {Path(member.name).name}\n{text}")

    binary = _suricata_binary({})
    if binary:
        for name in EVENT_RULES:
            path = Path(binary).parent / "rules" / name
            if path.is_file():
                parts.append(f"\n# ---- {name} (Suricata)\n{path.read_text(encoding='utf-8')}")

    DEFAULT_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_RULES_FILE.write_text("".join(parts), encoding="utf-8")
    print(f"wrote {count:,} ET Open signatures to {DEFAULT_RULES_FILE}")


if __name__ == "__main__":
    main()
