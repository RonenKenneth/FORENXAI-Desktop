"""
Packets and per-connection totals, kept out of analysis.json.

A 100 MB capture holds about 1.4 million packets. Embedding them in
analysis.json made every tab download and parse all of them; here they are
written once to packets.json and served a page at a time, filtered on the
server. Each flow instead carries its connection's totals (bytes, packets,
TCP flags, first packet time), computed once from the same packets.
"""

import json
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PACKETS_FILE = "packets.json"
PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}
FLAG_NAMES = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR"}


def connection_key(protocol: str, a: Any, a_port: Any, b: Any, b_port: Any) -> str:
    """Direction-free 5-tuple: both directions of a connection share it."""
    one, two = f"{a}:{a_port}", f"{b}:{b_port}"
    return f"{protocol}|{one}|{two}" if one < two else f"{protocol}|{two}|{one}"


def flag_names(flags: str) -> List[str]:
    return [FLAG_NAMES[f] for f in flags or "" if f in FLAG_NAMES]


def connection_stats(packets: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    stats: Dict[str, Dict[str, Any]] = {}
    for p in packets:
        if p.get("source_port") is None:
            continue
        key = connection_key(p["protocol"], p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"])
        s = stats.get(key)
        if s is None:
            s = stats[key] = {"bytes": 0, "packets": 0, "flags": set(), "first_time": p["timestamp"]}
        s["bytes"] += p["packet_length"]
        s["packets"] += 1
        s["flags"].update(flag_names(p.get("tcp_flags", "")))
    return stats


def attach_connection_stats(findings: List[Dict[str, Any]], stats: Dict[str, Dict[str, Any]],
                            capture_addresses: Optional[set] = None) -> None:
    """finding["connection"] = totals of the connection the flow belongs to.

    finding["pseudo_flow"] = True when neither address occurs in the capture:
    CICFlowMeter folds non-IP frames (ARP) into one flow whose "addresses"
    are ARP header bytes (e.g. 8.6.0.1 -> 8.0.6.4)."""
    for finding in findings:
        m = finding.get("metadata") or {}
        if capture_addresses is not None:
            finding["pseudo_flow"] = (m.get("Src IP") not in capture_addresses
                                      and m.get("Dst IP") not in capture_addresses)
        protocol = PROTOCOL_NAMES.get(int(m.get("Protocol") or 0), "OTHER")
        s = stats.get(connection_key(protocol, m.get("Src IP"), m.get("Src Port"), m.get("Dst IP"), m.get("Dst Port")))
        if s is not None:
            finding["connection"] = {"bytes": s["bytes"], "packets": s["packets"],
                                     "flags": sorted(s["flags"]), "first_time": s["first_time"]}


def capture_coverage(packets: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """How much of the capture the flow records (CICFlowMeter, the ML and
    Tier 1 input) contain, measured from the packets.

    CICFlowMeter writes a flow only when it has more than one packet
    (FlowGenerator.java: `if (flow.packetCount() > 1)`), as it did for the
    training data. Single-packet conversations -- typically probes that got
    no reply -- therefore never reach the model or Tier 1; Tier 2 and
    Suricata still read them. This reports them instead of hiding them."""
    conversations: Dict[str, Dict[str, Any]] = {}
    non_port = 0
    for p in packets:
        if p.get("source_port") is None:
            non_port += 1
            continue
        key = connection_key(p["protocol"], p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"])
        c = conversations.get(key)
        if c is None:
            conversations[key] = {"packets": 1, "source": p["source_ip"], "destination": p["destination_ip"],
                                  "port": p["destination_port"], "flags": p.get("tcp_flags", "")}
        else:
            c["packets"] += 1
    in_flows = set()
    for f in findings:
        m = f.get("metadata") or {}
        protocol = PROTOCOL_NAMES.get(int(m.get("Protocol") or 0), "OTHER")
        in_flows.add(connection_key(protocol, m.get("Src IP"), m.get("Src Port"), m.get("Dst IP"), m.get("Dst Port")))
    missing = [c for k, c in conversations.items() if k not in in_flows]
    probes: Dict[tuple, set] = defaultdict(set)
    for c in missing:
        if c["packets"] == 1 and c["flags"] == "S":
            probes[(c["source"], c["destination"])].add(c["port"])
    return {
        "packet_conversations": len(conversations),
        "in_flow_records": len(conversations) - len(missing),
        "not_in_flow_records": len(missing),
        "single_packet_not_exported": sum(c["packets"] == 1 for c in missing),
        "packets_without_ports": non_port,
        "unanswered_syn_probes": [
            {"source": s, "destination": d, "ports": len(ports)}
            for (s, d), ports in sorted(probes.items(), key=lambda kv: -len(kv[1]))[:10]
        ],
        "reason": "CICFlowMeter exports only flows with more than one packet (as for the training data).",
    }


def write_packets(case_directory: Path, packets: List[Dict[str, Any]]) -> None:
    temporary = case_directory / (PACKETS_FILE + ".tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(packets, file, ensure_ascii=False, separators=(",", ":"))
    temporary.replace(case_directory / PACKETS_FILE)


@lru_cache(maxsize=2)
def _load(path: str, mtime_ns: int) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def load_packets(case_directory: Path, analysis: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """packets.json, or the packets embedded in an older analysis.json."""
    path = case_directory / PACKETS_FILE
    if path.exists():
        return _load(str(path), path.stat().st_mtime_ns)
    return list((analysis or {}).get("packets") or [])


@lru_cache(maxsize=2)
def _load_analysis(path: str, mtime_ns: int) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def read_analysis(analysis_file: Path) -> Dict[str, Any]:
    """Parsed analysis.json, cached until the file changes. Shared between
    requests: callers must not modify it."""
    return _load_analysis(str(analysis_file), analysis_file.stat().st_mtime_ns)


OPTION_LIMIT = 300  # most frequent addresses / ports offered as filter options


def _top(counter: Dict[Any, int]) -> Dict[str, int]:
    top = sorted(counter.items(), key=lambda kv: -kv[1])[:OPTION_LIMIT]
    return {str(k): v for k, v in sorted(top, key=lambda kv: str(kv[0]))}


def query_packets(packets: List[Dict[str, Any]], offset: int = 0, limit: int = 500,
                  protocol: str = "", flag: str = "", source: str = "", destination: str = "",
                  port: str = "", ip_version: str = "", interface: str = "",
                  min_length: Optional[int] = None, max_length: Optional[int] = None,
                  text: str = "") -> Dict[str, Any]:
    """One page of the packets matching every filter given, plus the filter
    options and columns this capture actually has. Addresses match IP or MAC
    on that side; `port` matches either side; words in `text` must all
    appear (any order, any case)."""
    words = [w.lower() for w in text.split()]
    wanted_port = int(port) if str(port).strip().isdigit() else None
    options = {name: defaultdict(int) for name in
               ("protocols", "flags", "sources", "destinations", "ports", "ip_versions", "interfaces")}
    present = set()
    rows = []
    matched = 0
    for p in packets:
        display = p.get("display_protocol") or p.get("protocol") or "OTHER"
        flags = flag_names(p.get("tcp_flags", ""))
        src = {v for v in (p.get("source_ip"), p.get("src_mac")) if v}
        dst = {v for v in (p.get("destination_ip"), p.get("dst_mac")) if v}
        ports = {v for v in (p.get("source_port"), p.get("destination_port")) if v is not None}
        options["protocols"][display] += 1
        for name in flags:
            options["flags"][name] += 1
        if p.get("source_ip"):
            options["sources"][p["source_ip"]] += 1
        if p.get("destination_ip"):
            options["destinations"][p["destination_ip"]] += 1
        for value in ports:
            options["ports"][value] += 1
        if p.get("ip_version"):
            options["ip_versions"][f"IPv{p['ip_version']}"] += 1
        if p.get("interface"):
            options["interfaces"][p["interface"]] += 1
        present.update(k for k, v in p.items() if v not in (None, ""))

        length = p.get("wire_length") or p.get("packet_length") or 0
        if ((protocol and display != protocol) or (flag and flag not in flags)
                or (source and source not in src) or (destination and destination not in dst)
                or (wanted_port is not None and wanted_port not in ports)
                or (ip_version and f"IPv{p.get('ip_version')}" != ip_version)
                or (interface and p.get("interface") != interface)
                or (min_length is not None and length < min_length)
                or (max_length is not None and length > max_length)):
            continue
        if words:
            haystack = " ".join(str(v) for v in p.values() if v is not None).lower()
            if not all(w in haystack for w in words):
                continue
        if offset <= matched < offset + limit:
            rows.append({**p, "display_protocol": display, "flags": flags})
        matched += 1
    result = {"total": len(packets), "matched": matched, "offset": offset, "rows": rows,
              "columns": sorted(present), "first_time": packets[0]["timestamp"] if packets else None}
    for name, counter in options.items():
        result[name] = _top(counter)
    return result


if __name__ == "__main__":
    # Self-check: both directions share a key, filters combine, paging holds.
    pk = [
        {"packet_number": 1, "timestamp": 1.0, "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "TCP",
         "source_port": 5000, "destination_port": 80, "packet_length": 74, "tcp_flags": "S", "display_protocol": "TCP", "info": ""},
        {"packet_number": 2, "timestamp": 1.1, "source_ip": "10.0.0.2", "destination_ip": "10.0.0.1", "protocol": "TCP",
         "source_port": 80, "destination_port": 5000, "packet_length": 60, "tcp_flags": "RA", "display_protocol": "TCP", "info": ""},
        {"packet_number": 3, "timestamp": 1.2, "source_ip": "aa:bb", "destination_ip": "ff:ff", "protocol": "ARP",
         "source_port": None, "destination_port": None, "packet_length": 42, "tcp_flags": "", "display_protocol": "ARP",
         "info": "Who has 10.0.0.2? Tell 10.0.0.1"},
    ]
    st = connection_stats(pk)
    assert len(st) == 1 and next(iter(st.values()))["bytes"] == 134 and next(iter(st.values()))["packets"] == 2
    finding = {"metadata": {"Src IP": "10.0.0.1", "Src Port": 5000, "Dst IP": "10.0.0.2", "Dst Port": 80, "Protocol": 6},
               "predicted_class": "PortScan"}
    attach_connection_stats([finding], st)
    assert finding["connection"]["flags"] == ["ACK", "RST", "SYN"]
    assert query_packets(pk, protocol="ARP", text="who 10.0.0.2")["matched"] == 1
    assert query_packets(pk, flag="RST")["matched"] == 1
    assert query_packets(pk, source="10.0.0.2")["matched"] == 1
    assert query_packets(pk, destination="ff:ff")["matched"] == 1      # ARP: the destination is a MAC
    assert query_packets(pk, port="80")["matched"] == 2                # either side
    assert query_packets(pk, min_length=60, max_length=70)["matched"] == 1
    page = query_packets(pk, offset=1, limit=1)
    assert page["matched"] == 3 and [r["packet_number"] for r in page["rows"]] == [2]
    assert "tcp_flags" in page["columns"] and page["ports"] == {"5000": 2, "80": 2}
    probe = dict(pk[0], packet_number=4, source_port=5001, destination_port=443)   # unanswered SYN
    cov = capture_coverage(pk + [probe], [finding])
    assert (cov["packet_conversations"], cov["in_flow_records"], cov["single_packet_not_exported"]) == (2, 1, 1)
    assert cov["packets_without_ports"] == 1
    assert cov["unanswered_syn_probes"] == [{"source": "10.0.0.1", "destination": "10.0.0.2", "ports": 1}]
    print("ALL CHECKS PASSED")
