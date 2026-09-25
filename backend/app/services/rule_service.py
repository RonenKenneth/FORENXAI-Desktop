"""
rule_service.py
---------------
Tier 1 rule-based detection: behavioural rules over CICFlowMeter flow records.

It runs beside XGBoost on the same CSV, never after it, and never reads the
model's output. Its hits are read by the recommendation stage and shown in the
interface next to the prediction and SHAP, with whether the two agree.

WHAT A TIER 1 RULE IS
A count over flows, compared with a threshold. Most attacks in scope are
visible only across many flows -- one probe is not a scan, one login is not a
brute-force attempt -- so most rules group flows by source, destination and
service inside a time window (window_seconds, default 60 s) and count:

  T1-PORTSCAN-01    distinct destination ports, one source -> one host
  T1-DDOS-01        several sources, each flooding one destination service
  T1-DOS-01         flows from one source to one destination service
  T1-SLOWLORIS-01   long, near-idle web connections held open at once
  T1-BRUTEFORCE-01  near-identical attempts on an authentication port
  T1-C2-01          regularly spaced contacts to one service (whole capture)
  T1-EXFIL-01       one flow sending far more than it receives
  T1-DNS-01         many DNS flows from one host whose replies dwarf the queries
  T1-TLS-01         repeated short TLS connections torn down with RST

An allowlist (known resolvers, update servers, backup jobs) marks matching
flows Benign and suppresses every other rule on them.

Every threshold is in app/rules/rules.json, with a sensitivity setting
(low / medium / high) that scales the count thresholds. Payload attacks
(WebBased, API, Exploitation, BufferOverflow, Evasion) and MITM are Tier 2 --
they need the packet contents or ARP, which flow records do not carry; see
packet_rule_service.py.

WHAT A HIT IS
    {"rule_id": "T1-PORTSCAN-01", "class": "PortScan", "tier": 1,
     "evidence": "25 distinct destination ports from 10.0.0.5 to 10.0.0.20 "
                 "within 60 s (threshold 20); median 1 forward packets per flow.",
     "measured": 25, "threshold": 20, "severity": "medium"}

`evidence` is a factual sentence with numbers. It is shown to the analyst and
given to Qwen as a citable source, and the verifier checks that any number an
action quotes from it is really in it.

Both CICFlowMeter naming schemes are accepted: the Java tool the application
runs ("Total Fwd Packet", string timestamps) and the one TRUSTLab was exported
with ("Tot Fwd Pkts", epoch timestamps), so the same rules can be validated on
the labelled dataset (validate_rules.py).
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "rules.json"

# canonical name -> accepted column names
ALIASES = {
    "src_ip": ["Src IP"],
    "dst_ip": ["Dst IP"],
    "dst_port": ["Dst Port"],
    "ts": ["Timestamp"],
    "duration": ["Flow Duration"],
    "fwd_pkts": ["Total Fwd Packet", "Total Fwd Packets", "Tot Fwd Pkts"],
    "fwd_bytes": ["Total Length of Fwd Packet", "Total Length of Fwd Packets", "TotLen Fwd Pkts"],
    "bwd_bytes": ["Total Length of Bwd Packet", "Total Length of Bwd Packets", "TotLen Bwd Pkts"],
    "fwd_len_mean": ["Fwd Packet Length Mean", "Fwd Pkt Len Mean"],
    "down_up": ["Down/Up Ratio"],
}

# Used when present; the rules that need them are skipped otherwise.
OPTIONAL_ALIASES = {
    "src_port": ["Src Port"],
    "proto": ["Protocol"],
    "rst": ["RST Flag Count", "RST Flag Cnt"],
    "bwd_pkts": ["Total Bwd packets", "Total Bwd Packets", "Tot Bwd Pkts"],
}

# Thresholds the sensitivity factor scales. Ratios, durations and
# regularity limits are properties of the attack, not of how many alerts an
# analyst wants, so they are left alone.
SCALED = {"min_distinct_ports", "min_flooding_sources", "per_source_min_flows", "min_flows",
          "min_concurrent_flows", "min_attempts", "min_fwd_bytes", "min_failed_handshakes"}


# ------------------------------------------------------------------
# configuration
# ------------------------------------------------------------------

def load_config(path: Optional[Path] = None,
                sensitivity: Optional[str] = None) -> Dict[str, Any]:
    """rules.json with the sensitivity factor applied to count thresholds."""
    config = json.loads(Path(path or RULES_FILE).read_text(encoding="utf-8"))
    level = sensitivity or config.get("sensitivity", "medium")
    factor = config["sensitivity_factors"][level]
    for rule in config["rules"].values():
        for key in list(rule):
            if key in SCALED:
                value = rule[key] * factor
                rule[key] = int(math.ceil(value)) if isinstance(rule[key], int) else value
    config["sensitivity"] = level
    return config


# ------------------------------------------------------------------
# input
# ------------------------------------------------------------------

def _timestamps(series: pd.Series) -> pd.Series:
    """Epoch seconds (TRUSTLab) or CICFlowMeter's 'dd/MM/yyyy hh:mm:ss a'."""
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().mean() > 0.9:
        return pd.to_datetime(numeric, unit="s", errors="coerce")
    text = series.astype(str).str.strip()
    parsed = pd.to_datetime(text, format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
    if parsed.notna().mean() < 0.9:
        parsed = pd.to_datetime(text, dayfirst=True, errors="coerce")
    return parsed


def normalise(frame: pd.DataFrame) -> pd.DataFrame:
    """The columns the rules use, under canonical names, in the input's row order."""
    frame = frame.rename(columns=lambda c: str(c).strip())
    out = pd.DataFrame(index=frame.index)
    missing = []
    for name, options in ALIASES.items():
        column = next((c for c in options if c in frame.columns), None)
        if column is None:
            missing.append(f"{name} ({' / '.join(options)})")
            continue
        out[name] = frame[column]
    if missing:
        raise KeyError("flow records lack: " + ", ".join(missing))
    for name, options in OPTIONAL_ALIASES.items():
        column = next((c for c in options if c in frame.columns), None)
        out[name] = frame[column] if column else np.nan
    for name in ("dst_port", "duration", "fwd_pkts", "fwd_bytes", "bwd_bytes",
                 "fwd_len_mean", "down_up", "src_port", "proto", "rst", "bwd_pkts"):
        out[name] = pd.to_numeric(out[name], errors="coerce").replace([np.inf, -np.inf], np.nan)
    out["src_ip"] = out["src_ip"].astype(str).str.strip()
    out["dst_ip"] = out["dst_ip"].astype(str).str.strip()
    out["ts"] = _timestamps(out["ts"])
    return out


def _seconds(series: pd.Series) -> np.ndarray:
    """Seconds since the epoch, whatever resolution pandas stores datetimes in."""
    return (series - pd.Timestamp(0)).dt.total_seconds().to_numpy()


def _fmt(value) -> str:
    value = float(value)
    return f"{int(value):,}" if value == int(value) else f"{value:,.2f}"


# ------------------------------------------------------------------
# rules -- each returns {row position: hit}
# ------------------------------------------------------------------

def _hit(rule_id, rule, evidence, measured, threshold):
    return {"rule_id": rule_id, "class": rule["class"], "tier": 1,
            "evidence": evidence, "measured": measured, "threshold": threshold,
            "severity": rule.get("severity", "medium")}


def _grouped(df, keys, aggregations):
    """Per-group statistics and each row's group number (-1 = no group)."""
    g = df.groupby(keys, sort=False, dropna=True)
    stats = g.agg(**aggregations).reset_index()
    codes = g.ngroup().to_numpy()
    return stats, codes


def _assign(codes, group_hits):
    """{row position: hit} for every row whose group has a hit."""
    if not group_hits:
        return {}
    rows = np.flatnonzero(np.isin(codes, np.fromiter(group_hits, int)))
    return {int(i): group_hits[int(codes[i])] for i in rows}


def _portscan(df, rule, rid, window):
    stats, codes = _grouped(df, ["src_ip", "dst_ip", "win"],
                            {"ports": ("dst_port", "nunique"), "med_pkts": ("fwd_pkts", "median")})
    q = stats[(stats["ports"] >= rule["min_distinct_ports"])
              & (stats["med_pkts"] <= rule["max_median_fwd_packets"])]
    return _assign(codes, {int(k): _hit(
        rid, rule,
        f"{int(r.ports)} distinct destination ports from {r.src_ip} to {r.dst_ip} within "
        f"{window} s (threshold {rule['min_distinct_ports']}); median "
        f"{_fmt(r.med_pkts)} forward packets per flow.",
        int(r.ports), rule["min_distinct_ports"]) for k, r in q.iterrows()})


def _ddos(df, rule, rid, window):
    """Several sources, each flooding the same service in the same window.

    Counting distinct sources alone flags any busy server -- a popular web
    site has hundreds of clients a minute. What separates a distributed flood
    is that each contributing source is itself flooding.
    """
    per_source = df.groupby(["src_ip", "dst_ip", "dst_port", "win"], sort=False)["src_ip"].transform("size")
    flooding = per_source >= rule["per_source_min_flows"]
    if not flooding.any():
        return {}
    sub = df[flooding.to_numpy()]
    stats, codes = _grouped(sub, ["dst_ip", "dst_port", "win"],
                            {"sources": ("src_ip", "nunique"), "flows": ("src_ip", "size")})
    q = stats[stats["sources"] >= rule["min_flooding_sources"]]
    local = _assign(codes, {int(k): _hit(
        rid, rule,
        f"{int(r.sources)} sources each sent at least {rule['per_source_min_flows']} flows to "
        f"{r.dst_ip} port {int(r.dst_port)} within {window} s, {int(r.flows):,} flows in total "
        f"(threshold {rule['min_flooding_sources']} sources).",
        int(r.sources), rule["min_flooding_sources"]) for k, r in q.iterrows()})
    positions = np.flatnonzero(flooding.to_numpy())
    return {int(positions[j]): hit for j, hit in local.items()}


def _dos(df, rule, rid, window):
    eligible = ~df["dst_port"].isin(rule.get("exclude_ports", [])).to_numpy()
    if not eligible.any():
        return {}
    sub = df[eligible]
    stats, codes = _grouped(sub, ["src_ip", "dst_ip", "dst_port", "win"],
                            {"flows": ("src_ip", "size")})
    q = stats[stats["flows"] >= rule["min_flows"]]
    local = _assign(codes, {int(k): _hit(
        rid, rule,
        f"{int(r.flows):,} flows from {r.src_ip} to {r.dst_ip} port {int(r.dst_port)} within "
        f"{window} s (threshold {rule['min_flows']}).",
        int(r.flows), rule["min_flows"]) for k, r in q.iterrows()})
    positions = np.flatnonzero(eligible)
    return {int(positions[j]): hit for j, hit in local.items()}


def _max_concurrency(starts: np.ndarray, ends: np.ndarray) -> int:
    """Largest number of intervals open at once (touching ends do not overlap)."""
    times = np.concatenate([starts, ends])
    deltas = np.concatenate([np.ones(len(starts)), -np.ones(len(ends))])
    order = np.lexsort((deltas, times))           # at equal times, closes first
    return int(np.cumsum(deltas[order]).max()) if len(times) else 0


def _slowloris(df, rule, rid, window):
    candidate = (df["dst_port"].isin(rule["web_ports"])
                 & (df["duration"] >= rule["min_duration_seconds"] * 1e6)
                 & (df["fwd_len_mean"] <= rule["max_fwd_packet_mean_bytes"])
                 & df["ts"].notna())
    hits = {}
    if not candidate.any():
        return hits
    sub = df[candidate]
    start = _seconds(sub["ts"])
    end = start + sub["duration"].to_numpy() / 1e6
    positions = np.flatnonzero(candidate.to_numpy())
    groups: Dict[Any, List[int]] = {}
    for j, key in enumerate(zip(sub["src_ip"], sub["dst_ip"], sub["dst_port"])):
        groups.setdefault(key, []).append(j)
    for (src, dst, port), members in groups.items():
        if len(members) < rule["min_concurrent_flows"]:
            continue
        idx = np.array(members)
        peak = _max_concurrency(start[idx], end[idx])
        if peak < rule["min_concurrent_flows"]:
            continue
        for j in members:
            hits[int(positions[j])] = _hit(
                rid, rule,
                f"{peak} connections from {src} to {dst} port {int(port)} open at the same time, "
                f"each lasting at least {rule['min_duration_seconds']} s with forward packets averaging "
                f"at most {rule['max_fwd_packet_mean_bytes']} bytes (threshold {rule['min_concurrent_flows']}).",
                peak, rule["min_concurrent_flows"])
    return hits


def _bruteforce(df, rule, rid, window):
    on_auth = df["dst_port"].isin(rule["auth_ports"]).to_numpy()
    if not on_auth.any():
        return {}
    sub = df[on_auth]
    stats, codes = _grouped(sub, ["src_ip", "dst_ip", "dst_port", "win"],
                            {"attempts": ("src_ip", "size"), "size_mean": ("fwd_bytes", "mean"),
                             "size_std": ("fwd_bytes", "std")})
    stats["size_cv"] = (stats["size_std"].fillna(0.0) / stats["size_mean"].where(stats["size_mean"] > 0)).fillna(0.0)
    q = stats[(stats["attempts"] >= rule["min_attempts"]) & (stats["size_cv"] <= rule["max_size_cv"])]
    local = _assign(codes, {int(k): _hit(
        rid, rule,
        f"{int(r.attempts)} connection attempts from {r.src_ip} to {r.dst_ip} port {int(r.dst_port)} "
        f"within {window} s with near-identical sizes (variation {r.size_cv:.2f}, limit "
        f"{rule['max_size_cv']}; threshold {rule['min_attempts']} attempts).",
        int(r.attempts), rule["min_attempts"]) for k, r in q.iterrows()})
    positions = np.flatnonzero(on_auth)
    return {int(positions[j]): hit for j, hit in local.items()}


def _c2(df, rule, rid, window):
    timed = df[df["ts"].notna()]
    hits = {}
    if timed.empty:
        return hits
    sizes = timed.groupby(["src_ip", "dst_ip", "dst_port"], sort=False)["src_ip"].transform("size")
    timed = timed[sizes >= rule["min_flows"]]
    for (src, dst, port), group in timed.groupby(["src_ip", "dst_ip", "dst_port"], sort=False):
        times = np.sort(_seconds(group["ts"]))
        gaps = np.diff(times)
        mean_gap = float(gaps.mean())
        if mean_gap < rule["min_mean_interval_seconds"]:
            continue
        cv = float(gaps.std() / mean_gap)
        mean_bytes = float((group["fwd_bytes"] + group["bwd_bytes"]).mean())
        if cv > rule["max_interval_cv"] or mean_bytes > rule["max_mean_bytes"]:
            continue
        for position in group.index:                      # df has a RangeIndex
            hits[int(position)] = _hit(
                rid, rule,
                f"{len(group)} flows from {src} to {dst} port {int(port)} at regular intervals of "
                f"about {mean_gap:,.1f} s (interval variation {cv:.2f}, limit {rule['max_interval_cv']}), "
                f"averaging {_fmt(round(mean_bytes))} bytes per flow.",
                len(group), rule["min_flows"])
    return hits


def _exfil(df, rule, rid, window):
    mask = (df["fwd_bytes"] >= rule["min_fwd_bytes"]) & (df["down_up"] <= rule["max_down_up_ratio"])
    hits = {}
    for i in np.flatnonzero(mask.fillna(False).to_numpy()):
        r = df.iloc[i]
        hits[int(i)] = _hit(rid, rule,
                       f"{_fmt(r.fwd_bytes)} bytes sent from {r.src_ip} to {r.dst_ip} port "
                       f"{int(r.dst_port)} with a download/upload ratio of {r.down_up:.2f} "
                       f"(thresholds {_fmt(rule['min_fwd_bytes'])} bytes and ratio "
                       f"{rule['max_down_up_ratio']}).",
                       float(r.fwd_bytes), rule["min_fwd_bytes"])
    return hits


def _dns(df, rule, rid, window):
    """DNS amplification: many DNS flows whose replies dwarf the queries.

    A flow is oriented by which side uses port 53. In a reflection attack the
    victim receives replies it never asked for, so the flow starts at the
    resolver (source port 53) and carries no query at all.
    """
    to_resolver = (df["dst_port"] == 53).to_numpy()
    from_resolver = (df["src_port"] == 53).to_numpy() & ~to_resolver
    dns = to_resolver | from_resolver
    if not dns.any():
        return {}
    sub = df[dns]
    fwd, bwd = sub["fwd_bytes"].fillna(0).to_numpy(), sub["bwd_bytes"].fillna(0).to_numpy()
    out_query = to_resolver[dns]
    sub = pd.DataFrame({
        "client": np.where(out_query, sub["src_ip"], sub["dst_ip"]),
        "resolver": np.where(out_query, sub["dst_ip"], sub["src_ip"]),
        "reply": np.where(out_query, bwd, fwd),
        "query": np.where(out_query, fwd, bwd),
        "win": sub["win"].to_numpy(),
    })
    sub["ratio"] = sub["reply"] / np.maximum(sub["query"], 1)
    stats, codes = _grouped(sub, ["client", "resolver", "win"],
                            {"flows": ("client", "size"), "ratio": ("ratio", "median"),
                             "reply": ("reply", "sum")})
    q = stats[(stats["flows"] >= rule["min_flows"]) & (stats["ratio"] >= rule["min_reply_ratio"])]
    local = _assign(codes, {int(k): _hit(
        rid, rule,
        f"{int(r.flows):,} DNS flows from {r.resolver} to {r.client} within {window} s with replies "
        f"a median {r.ratio:,.1f} times the query size, {_fmt(r.reply)} reply bytes in total "
        f"(thresholds {rule['min_flows']} flows and ratio {rule['min_reply_ratio']}).",
        int(r.flows), rule["min_flows"]) for k, r in q.iterrows()})
    positions = np.flatnonzero(dns)
    return {int(positions[j]): hit for j, hit in local.items()}


def _tls(df, rule, rid, window):
    """Repeated TLS connections reset after a few packets: failed handshakes."""
    if df["rst"].isna().all():
        return {}
    failed = (df["dst_port"].isin(rule["tls_ports"]) & (df["rst"] > 0)
              & ((df["fwd_pkts"] + df["bwd_pkts"].fillna(0)) <= rule["max_packets"]))
    if not failed.any():
        return {}
    sub = df[failed.to_numpy()]
    stats, codes = _grouped(sub, ["src_ip", "dst_ip", "dst_port", "win"],
                            {"flows": ("src_ip", "size")})
    q = stats[stats["flows"] >= rule["min_failed_handshakes"]]
    local = _assign(codes, {int(k): _hit(
        rid, rule,
        f"{int(r.flows)} connections from {r.src_ip} to {r.dst_ip} port {int(r.dst_port)} reset "
        f"after at most {rule['max_packets']} packets within {window} s "
        f"(threshold {rule['min_failed_handshakes']}).",
        int(r.flows), rule["min_failed_handshakes"]) for k, r in q.iterrows()})
    positions = np.flatnonzero(failed.to_numpy())
    return {int(positions[j]): hit for j, hit in local.items()}


RULE_FUNCTIONS = {
    "PortScan": _portscan, "DDoS": _ddos, "DoS": _dos, "Slowloris": _slowloris,
    "Bruteforce": _bruteforce, "C2Beaconing": _c2, "Exfiltration": _exfil,
    "DNS": _dns, "TLSSSL": _tls,
}


def _allowlisted(df, allow) -> np.ndarray:
    ips = set(allow.get("ips", []))
    mask = df["src_ip"].isin(ips) | df["dst_ip"].isin(ips)
    mask |= df["dst_port"].isin(allow.get("ports", []))
    return mask.to_numpy()


# ------------------------------------------------------------------
# public
# ------------------------------------------------------------------

def evaluate_frame(frame: pd.DataFrame,
                   config: Optional[Dict[str, Any]] = None) -> List[List[Dict[str, Any]]]:
    """Hits for every row of a flow table, in row order (empty list = none)."""
    config = config or load_config()
    df = normalise(frame).reset_index(drop=True)
    window = int(config["window_seconds"])
    df["win"] = df["ts"].dt.floor(f"{window}s")

    per_row: List[List[Dict[str, Any]]] = [[] for _ in range(len(df))]
    for rule_id, rule in config["rules"].items():
        if not rule.get("enabled", True):
            continue
        for position, hit in RULE_FUNCTIONS[rule["class"]](df, rule, rule_id, window).items():
            per_row[position].append(hit)

    allow = config.get("allowlist") or {}
    if allow.get("ips") or allow.get("ports"):
        for i in np.flatnonzero(_allowlisted(df, allow)):
            r = df.iloc[i]
            per_row[i] = [{"rule_id": "ALLOWLIST", "class": "Benign", "tier": 1,
                           "evidence": f"Flow from {r.src_ip} to {r.dst_ip} port "
                                       f"{_fmt(r.dst_port)} matches the allowlist of known-good traffic.",
                           "measured": None, "threshold": None, "severity": "info"}]

    return [sort_hits(hits, config) for hits in per_row]


def evaluate(flow_csv: str,
             findings: List[Dict[str, Any]]
             ) -> Optional[Dict[int, List[Dict[str, Any]]]]:
    """Rule hits per flow_index for the analysed capture.

    Returns None when the rules could not be evaluated (unreadable CSV,
    missing columns, or a row count that does not match the findings), so the
    recommendation says "not evaluated" rather than "no rule fired".
    """
    try:
        frame = pd.read_csv(flow_csv, low_memory=False)
        config = load_config()
        per_row = evaluate_frame(frame, config)
    except Exception as error:                              # noqa: BLE001
        print(f"[FORENXAI] Rule layer not evaluated ({type(error).__name__}: {error})", flush=True)
        return None

    if len(per_row) != len(findings):
        print(f"[FORENXAI] Rule layer not evaluated: {len(per_row)} flow records but "
              f"{len(findings)} classified flows.", flush=True)
        return None

    result = {}
    for finding, hits in zip(findings, per_row):
        index = finding.get("flow_index")
        if index is not None:
            result[int(index)] = hits

    fired: Dict[str, int] = {}
    for hits in per_row:
        for hit in hits:
            fired[hit["rule_id"]] = fired.get(hit["rule_id"], 0) + 1
    print(f"[FORENXAI] Rule layer ({config['version']}, sensitivity {config['sensitivity']}): "
          f"{sum(1 for h in per_row if h)} of {len(per_row)} flows flagged"
          + (f" -- {fired}" if fired else ""), flush=True)
    return result


def decide(finding: Dict[str, Any],
           hits: Optional[List[Dict[str, Any]]],
           config: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    """(verdict, source) for one flow from the model and the rule hits.

    source is agree, rule, ml, conflict or abstain. Rules decide only for the
    classes rules.json -> decision.trust names (measured precise on held-out
    data); elsewhere the model does, unless it abstained (below its class's
    confidence threshold or out of distribution), when a rule hit stands in
    and otherwise the verdict is Uncertain. `hits` is priority-ordered.
    """
    config = config or load_config()
    trust = config.get("decision", {}).get("trust", {})
    ml_class = str(finding.get("predicted_class", ""))
    abstained = bool(finding.get("abstained"))
    classes = [h.get("class") for h in (hits or []) if h.get("class")]
    rule_class = classes[0] if classes else None

    if rule_class and ml_class in classes and not abstained:
        return ml_class, "agree"
    if rule_class and trust.get(rule_class) == "rule":
        return rule_class, "rule"
    if abstained:
        return (rule_class, "rule") if rule_class else ("Uncertain", "abstain")
    if rule_class:
        return ml_class, "conflict"
    return ml_class, "ml"


def sort_hits(hits: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Most specific evidence first (rules.json -> priority)."""
    order = {c: i for i, c in enumerate(config.get("priority", []))}
    return sorted(hits, key=lambda h: order.get(h["class"], len(order)))
