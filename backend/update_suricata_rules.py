"""
update_suricata_rules.py
------------------------
Downloads the free rulesets Tier 2 uses and writes them, with Suricata's own
protocol-event rules, to <repo>/tools/suricata/et-open.rules -- the file
packet_rule_service.run_suricata loads when rules.json names no rules_file.

    python update_suricata_rules.py [--version 7.0.3]

Sources (all free, listed in the OISF ruleset index used by suricata-update):
  et/open                     Emerging Threats Open (MIT)
  ptrules/open                Positive Technologies open rules
  ptresearch/attackdetection  Positive Technologies Attack Detection team
  aleksibovellan/nmap         Nmap scan-type detection (MIT)
  abuse.ch/sslbl-ja3          malicious TLS client fingerprints (CC0)
  abuse.ch/sslbl-blacklist    malicious TLS certificates (CC0)
plus Suricata's decoder, stream, http, dns, tls, smtp and app-layer event
rules from the installed Suricata. A source that cannot be downloaded is
skipped and reported; the others are still written.

Rerun it to update the signatures; the file header records the date.
"""
from __future__ import annotations

import argparse
import io
import tarfile
import urllib.request
from datetime import date
from pathlib import Path

from app.services.packet_rule_service import DEFAULT_RULES_FILE, _suricata_binary

SOURCES = {
    "et/open": "https://rules.emergingthreats.net/open/suricata-{version}/emerging.rules.tar.gz",
    "ptrules/open": "https://rules.ptsecurity.com/files/ptopen.rules.tar.gz",
    "ptresearch/attackdetection": "https://raw.githubusercontent.com/ptresearch/AttackDetection/master/pt.rules.tar.gz",
    "aleksibovellan/nmap": "https://raw.githubusercontent.com/aleksibovellan/opnsense-suricata-nmaps/main/local.rules",
    "abuse.ch/sslbl-ja3": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.tar.gz",
    "abuse.ch/sslbl-blacklist": "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz",
}
EVENT_RULES = ("decoder-events.rules", "stream-events.rules", "http-events.rules", "dns-events.rules",
               "tls-events.rules", "smtp-events.rules", "app-layer-events.rules")


def _rules_texts(url: str):
    """(name, text) for every .rules file behind `url` (a .tar.gz or a plain .rules file)."""
    request = urllib.request.Request(url, headers={"User-Agent": "FORENXAI rule updater"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    if not url.endswith((".tar.gz", ".tgz")):
        return [(Path(url).name, data.decode("utf-8", "replace"))]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return [(Path(m.name).name, tar.extractfile(m).read().decode("utf-8", "replace"))
                for m in sorted(tar.getmembers(), key=lambda m: m.name)
                if m.isfile() and m.name.endswith(".rules")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="7.0.3", help="ET Open build to fetch (Suricata 7.x)")
    args = ap.parse_args()

    parts = [f"# FORENXAI Tier 2 rules, downloaded {date.today().isoformat()}\n"]
    for key, url in SOURCES.items():
        url = url.format(version=args.version)
        try:
            files = _rules_texts(url)
        except Exception as error:                          # noqa: BLE001
            print(f"  skipped {key}: {type(error).__name__}: {error}")
            continue
        count = sum(line.startswith("alert") for _, text in files for line in text.splitlines())
        print(f"  {key:<28} {count:>7,} signatures")
        parts += [f"\n# ==== {key}: {name}\n{text}" for name, text in files]

    binary = _suricata_binary({})
    if binary:
        for name in EVENT_RULES:
            path = Path(binary).parent / "rules" / name
            if path.is_file():
                parts.append(f"\n# ==== suricata: {name}\n{path.read_text(encoding='utf-8')}")

    DEFAULT_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_RULES_FILE.write_text("".join(parts), encoding="utf-8")
    total = sum(line.startswith("alert") for part in parts for line in part.splitlines())
    print(f"wrote {total:,} signatures to {DEFAULT_RULES_FILE}")


if __name__ == "__main__":
    main()
