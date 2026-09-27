"""
test_rules.py
-------------
Tier 1 rules on small synthetic captures: every rule must fire on its pattern
and stay silent on a near miss.

    python test_rules.py          # exit status = failures
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services import rule_service as rs      # noqa: E402

FAILED = []
T0 = datetime(2026, 9, 26, 14, 0, 0)

# The rule LOGIC is tested against fixed thresholds, so these tests do not
# change when rules.json is re-tuned. Section 5 tests the shipped rules.json.
LOGIC_THRESHOLDS = {
    "T1-PORTSCAN-01": {"min_distinct_ports": 20},
    "T1-DDOS-01": {"enabled": True, "min_flooding_sources": 3, "per_source_min_flows": 50},
    "T1-DOS-01": {"min_flows": 100},
    "T1-BRUTEFORCE-01": {"min_attempts": 10, "max_size_cv": 0.3},
}
_TMP = tempfile.TemporaryDirectory()
LOGIC_FILE = Path(_TMP.name) / "rules_logic.json"
_raw = json.loads(rs.RULES_FILE.read_text(encoding="utf-8"))
for _rid, _values in LOGIC_THRESHOLDS.items():
    _raw["rules"][_rid].update(_values)
LOGIC_FILE.write_text(json.dumps(_raw), encoding="utf-8")


def check(name, condition, detail=""):
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}  {detail}")
    if not condition:
        FAILED.append(name)


def flows(n, src="10.0.0.5", dst="10.0.0.20", dport=80, start=T0, step=0.0,
          fwd_pkts=1, fwd_bytes=60, bwd_bytes=0, duration_s=0.001, fwd_mean=None,
          down_up=0.0, ports=None, sources=None, sizes=None, gaps=None):
    """n flow records in the application's CICFlowMeter layout."""
    times, t = [], start
    for i in range(n):
        times.append(t)
        t += timedelta(seconds=float(gaps[i] if gaps is not None and i < len(gaps) else step))
    return pd.DataFrame({
        "Flow ID": [f"f{i}" for i in range(n)],
        "Src IP": sources if sources is not None else [src] * n,
        "Src Port": 40000 + np.arange(n),
        "Dst IP": [dst] * n,
        "Dst Port": ports if ports is not None else [dport] * n,
        "Protocol": 6,
        "Timestamp": [x.strftime("%d/%m/%Y %I:%M:%S %p") for x in times],
        "Flow Duration": [duration_s * 1e6] * n,
        "Total Fwd Packet": [fwd_pkts] * n,
        "Total Bwd packets": 1,
        "Total Length of Fwd Packet": sizes if sizes is not None else [fwd_bytes] * n,
        "Total Length of Bwd Packet": [bwd_bytes] * n,
        "Fwd Packet Length Mean": [fwd_mean if fwd_mean is not None else fwd_bytes / max(fwd_pkts, 1)] * n,
        "Down/Up Ratio": [down_up] * n,
    })


def fired(frame, rule_id, sensitivity=None, shipped=False):
    config = rs.load_config(None if shipped else LOGIC_FILE, sensitivity=sensitivity)
    per_row = rs.evaluate_frame(frame, config)
    return sum(any(h["rule_id"] == rule_id for h in hits) for hits in per_row), per_row


def main():
    print("\n1. each rule fires on its pattern and not on a near miss")

    n, per = fired(flows(25, ports=list(range(1000, 1025)), step=1), "T1-PORTSCAN-01")
    check("PortScan: 25 ports in 25 s fires on all 25 flows", n == 25)
    hit = next(h for hits in per for h in hits)
    check("PortScan: evidence carries the measured count and threshold",
          "25 distinct destination ports" in hit["evidence"] and "(threshold 20)" in hit["evidence"]
          and hit["measured"] == 25 and hit["threshold"] == 20)
    check("PortScan: 5 ports does not fire",
          fired(flows(5, ports=list(range(1000, 1005)), step=1), "T1-PORTSCAN-01")[0] == 0)
    check("PortScan: 25 ports spread over 25 minutes does not fire",
          fired(flows(25, ports=list(range(1000, 1025)), step=60), "T1-PORTSCAN-01")[0] == 0)
    check("PortScan: full sessions (median 20 packets) do not fire",
          fired(flows(25, ports=list(range(1000, 1025)), step=1, fwd_pkts=20), "T1-PORTSCAN-01")[0] == 0)

    srcs = [f"172.16.0.{i % 4}" for i in range(240)]
    check("DDoS: 4 sources each sending 60 flows to one service in 60 s fires",
          fired(flows(240, sources=srcs, step=0.2), "T1-DDOS-01")[0] == 240)
    srcs = [f"172.16.{i // 250}.{i % 250}" for i in range(200)]
    check("DDoS: a busy server (200 clients, one flow each) does not fire",
          fired(flows(200, sources=srcs, step=0.2), "T1-DDOS-01")[0] == 0)
    srcs = [f"172.16.0.{i % 2}" for i in range(240)]
    check("DDoS: only 2 flooding sources does not fire",
          fired(flows(240, sources=srcs, step=0.2), "T1-DDOS-01")[0] == 0)

    check("DoS: 120 flows from one source in 60 s fires",
          fired(flows(120, step=0.2), "T1-DOS-01")[0] == 120)
    check("DoS: 60 flows does not fire", fired(flows(60, step=0.2), "T1-DOS-01")[0] == 0)
    check("DoS: 120 queries to a DNS resolver do not fire (name-service port)",
          fired(flows(120, dport=53, step=0.2), "T1-DOS-01")[0] == 0)

    slow = dict(dport=80, duration_s=45, fwd_mean=20, fwd_bytes=200, fwd_pkts=10)
    check("Slowloris: 25 overlapping 45 s near-idle connections fires",
          fired(flows(25, step=0.5, **slow), "T1-SLOWLORIS-01")[0] == 25)
    check("Slowloris: the same connections one after another does not fire",
          fired(flows(25, step=50, **slow), "T1-SLOWLORIS-01")[0] == 0)
    check("Slowloris: short connections do not fire",
          fired(flows(25, step=0.5, **dict(slow, duration_s=5)), "T1-SLOWLORIS-01")[0] == 0)
    check("Slowloris: busy connections (large packets) do not fire",
          fired(flows(25, step=0.5, **dict(slow, fwd_mean=900)), "T1-SLOWLORIS-01")[0] == 0)
    check("Slowloris: non-web port does not fire",
          fired(flows(25, step=0.5, **dict(slow, dport=5000)), "T1-SLOWLORIS-01")[0] == 0)

    check("Bruteforce: 12 same-size SSH attempts in 60 s fires",
          fired(flows(12, dport=22, step=3, fwd_bytes=1200, fwd_pkts=12), "T1-BRUTEFORCE-01")[0] == 12)
    check("Bruteforce: very different sizes do not fire",
          fired(flows(12, dport=22, step=3, sizes=[100, 5000] * 6, fwd_pkts=12), "T1-BRUTEFORCE-01")[0] == 0)
    check("Bruteforce: non-authentication port does not fire",
          fired(flows(12, dport=8081, step=3, fwd_bytes=1200, fwd_pkts=12), "T1-BRUTEFORCE-01")[0] == 0)
    check("Bruteforce: 5 attempts do not fire",
          fired(flows(5, dport=22, step=3, fwd_bytes=1200, fwd_pkts=12), "T1-BRUTEFORCE-01")[0] == 0)

    check("C2: 8 small contacts every 30 s fires",
          fired(flows(8, dport=443, step=30, fwd_bytes=300, bwd_bytes=200, fwd_pkts=4), "T1-C2-01")[0] == 8)
    rng = np.random.default_rng(1)
    check("C2: irregular contacts do not fire",
          fired(flows(8, dport=443, gaps=list(rng.integers(2, 200, 8)), fwd_bytes=300, fwd_pkts=4), "T1-C2-01")[0] == 0)
    check("C2: regular but large transfers do not fire",
          fired(flows(8, dport=443, step=30, fwd_bytes=50000, bwd_bytes=50000, fwd_pkts=40), "T1-C2-01")[0] == 0)
    check("C2: rapid bursts (sub-second) do not fire",
          fired(flows(8, dport=443, step=0, fwd_bytes=300, fwd_pkts=4), "T1-C2-01")[0] == 0)

    check("Exfiltration: 20 MB out, ratio 0.01 fires",
          fired(flows(1, fwd_bytes=20_000_000, fwd_pkts=15000, down_up=0.01), "T1-EXFIL-01")[0] == 1)
    check("Exfiltration: 1 MB out does not fire",
          fired(flows(1, fwd_bytes=1_000_000, fwd_pkts=800, down_up=0.01), "T1-EXFIL-01")[0] == 0)
    check("Exfiltration: balanced transfer does not fire",
          fired(flows(1, fwd_bytes=20_000_000, fwd_pkts=15000, down_up=1.0), "T1-EXFIL-01")[0] == 0)

    print("\n2. adjustable thresholds")
    scan15 = flows(15, ports=list(range(1000, 1015)), step=1)
    check("sensitivity medium: 15 ports does not fire", fired(scan15, "T1-PORTSCAN-01")[0] == 0)
    check("sensitivity high (x0.7 -> 14): 15 ports fires", fired(scan15, "T1-PORTSCAN-01", "high")[0] == 15)
    check("sensitivity low (x1.5 -> 30): 25 ports does not fire",
          fired(flows(25, ports=list(range(1000, 1025)), step=1), "T1-PORTSCAN-01", "low")[0] == 0)
    check("ratios and durations are not scaled",
          rs.load_config(sensitivity="high")["rules"]["T1-EXFIL-01"]["max_down_up_ratio"] == 0.1
          and rs.load_config(sensitivity="high")["rules"]["T1-SLOWLORIS-01"]["min_duration_seconds"] == 30)

    print("\n3. input handling")
    epoch = flows(25, ports=list(range(1000, 1025)), step=1)
    epoch["Timestamp"] = [(T0 + timedelta(seconds=i)).timestamp() for i in range(25)]
    check("epoch timestamps (TRUSTLab export) are read", fired(epoch, "T1-PORTSCAN-01")[0] == 25)
    short = epoch.rename(columns={"Total Fwd Packet": "Tot Fwd Pkts",
                                  "Total Length of Fwd Packet": "TotLen Fwd Pkts",
                                  "Total Length of Bwd Packet": "TotLen Bwd Pkts",
                                  "Fwd Packet Length Mean": "Fwd Pkt Len Mean"})
    check("short column names (TRUSTLab export) are read", fired(short, "T1-PORTSCAN-01")[0] == 25)
    mixed = pd.concat([flows(25, ports=list(range(1000, 1025)), step=1),
                       flows(120, src="10.0.0.9", step=0.2)], ignore_index=True)
    per = rs.evaluate_frame(mixed, rs.load_config(LOGIC_FILE))
    check("hits stay on their own rows",
          all(h["rule_id"] == "T1-PORTSCAN-01" for hits in per[:25] for h in hits)
          and all(h["rule_id"] == "T1-DOS-01" for hits in per[25:] for h in hits))

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "flows.csv"
        shipped_scan = rs.load_config()["rules"]["T1-PORTSCAN-01"]["min_distinct_ports"] + 5
        mixed = flows(shipped_scan, ports=list(range(1000, 1000 + shipped_scan)), step=0.5)
        mixed.to_csv(path, index=False)
        findings = [{"flow_index": i} for i in range(len(mixed))]
        result = rs.evaluate(str(path), findings)
        check("evaluate(): one entry per flow_index", result is not None and len(result) == len(mixed))
        check("evaluate(): a flow with no hit maps to []", result is not None and result[0] and not
              any(result[i] for i in range(25, 25)) and isinstance(result[len(mixed) - 1], list))
        check("evaluate(): row-count mismatch -> not evaluated (None)",
              rs.evaluate(str(path), findings[:-1]) is None)
        mixed.drop(columns=["Dst Port"]).to_csv(path, index=False)
        check("evaluate(): missing columns -> not evaluated (None)", rs.evaluate(str(path), findings) is None)
        check("evaluate(): unreadable file -> not evaluated (None)",
              rs.evaluate(str(Path(tmp) / "absent.csv"), findings) is None)

    print("\n4. priority")
    # a scan of 24 ports plus 12 same-size SSH attempts: the SSH flows are
    # part of the scan (PortScan) and a brute-force run (Bruteforce)
    both = flows(36, ports=list(range(1000, 1024)) + [22] * 12, step=1, fwd_bytes=60)
    hits = rs.evaluate_frame(both, rs.load_config(LOGIC_FILE))[24]
    order = rs.load_config()["priority"]
    check("several rules on one flow are ordered by priority",
          [h["class"] for h in hits] == sorted([h["class"] for h in hits], key=order.index)
          and [h["class"] for h in hits] == ["Bruteforce", "PortScan"], str([h["class"] for h in hits]))

    print("\n4b. DNS, TLS and allowlist")
    dns = rs.load_config()["rules"]["T1-DNS-01"]
    n = dns["min_flows"]
    reflected = flows(n, src="8.8.8.8", dst="10.0.0.5", step=0.5, fwd_bytes=3000, bwd_bytes=0)
    reflected["Src Port"] = 53
    reflected["Dst Port"] = 40000 + np.arange(n)
    check(f"DNS: {n} unsolicited large replies from port 53 fire",
          fired(reflected, "T1-DNS-01", shipped=True)[0] == n)
    normal = flows(n * 3, dport=53, step=0.2, fwd_bytes=40, bwd_bytes=120)
    check("DNS: ordinary lookups (reply 3x query) do not", fired(normal, "T1-DNS-01", shipped=True)[0] == 0)
    check(f"DNS: {n - 1} amplified replies do not",
          fired(reflected.iloc[: n - 1], "T1-DNS-01", shipped=True)[0] == 0)
    tls = rs.load_config()["rules"]["T1-TLS-01"]
    m = tls["min_failed_handshakes"]
    resets = flows(m, dport=443, step=1, fwd_pkts=3)
    resets["RST Flag Count"] = 1
    check(f"TLS: {m} short connections reset on 443 fire", fired(resets, "T1-TLS-01", shipped=True)[0] == m)
    check("TLS: without RST they do not",
          fired(resets.assign(**{"RST Flag Count": 0}), "T1-TLS-01", shipped=True)[0] == 0)
    check("TLS: without an RST column the rule is skipped, not an error",
          fired(flows(m, dport=443, step=1), "T1-TLS-01", shipped=True)[0] == 0)
    allow = rs.load_config()
    allow["allowlist"] = {"ips": ["10.0.0.20"], "ports": []}
    scan = flows(60, ports=list(range(1000, 1060)), step=0.5)
    per = rs.evaluate_frame(scan, allow)
    check("allowlisted host: flows marked Benign by the allowlist, scan hit suppressed",
          all([h["rule_id"] for h in row] == ["ALLOWLIST"] for row in per))

    print("\n5. shipped rules.json (tuned thresholds)")
    shipped = rs.load_config()
    check("rules.json records how it was tuned",
          "tuning" in shipped and shipped["tuning"]["tuned_rules"])
    ports = shipped["rules"]["T1-PORTSCAN-01"]["min_distinct_ports"]
    check(f"PortScan fires at its tuned threshold ({ports} ports)",
          fired(flows(ports, ports=list(range(1000, 1000 + ports)), step=0.5),
                "T1-PORTSCAN-01", shipped=True)[0] == ports)
    check(f"PortScan stays silent just below it ({ports - 1} ports)",
          fired(flows(ports - 1, ports=list(range(1000, 999 + ports)), step=0.5),
                "T1-PORTSCAN-01", shipped=True)[0] == 0)
    n_dos = shipped["rules"]["T1-DOS-01"]["min_flows"]
    check(f"DoS fires at its tuned threshold ({n_dos} flows / 60 s)",
          fired(flows(n_dos, step=50 / n_dos), "T1-DOS-01", shipped=True)[0] == n_dos)
    check("DoS stays silent just below it",
          fired(flows(n_dos - 1, step=50 / n_dos), "T1-DOS-01", shipped=True)[0] == 0)
    attempts = shipped["rules"]["T1-BRUTEFORCE-01"]["min_attempts"]
    check(f"Bruteforce fires at its tuned threshold ({attempts} attempts)",
          fired(flows(attempts, dport=22, step=2, fwd_bytes=1200, fwd_pkts=12),
                "T1-BRUTEFORCE-01", shipped=True)[0] == attempts)
    srcs = [f"172.16.0.{i % 4}" for i in range(800)]
    check("DDoS is disabled in the shipped configuration, with a reason",
          not shipped["rules"]["T1-DDOS-01"]["enabled"]
          and shipped["rules"]["T1-DDOS-01"].get("disabled_reason")
          and fired(flows(800, sources=srcs, step=0.05), "T1-DDOS-01", shipped=True)[0] == 0)

    print(f"\n{'ALL CHECKS PASSED' if not FAILED else f'{len(FAILED)} FAILED: {FAILED}'}")
    return len(FAILED)


if __name__ == "__main__":
    sys.exit(main())
