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


def attach_connection_stats(findings: List[Dict[str, Any]], stats: Dict[str, Dict[str, Any]]) -> None:
    """finding["connection"] = totals of the connection the flow belongs to."""
    for finding in findings:
        m = finding.get("metadata") or {}
        protocol = PROTOCOL_NAMES.get(int(m.get("Protocol") or 0), "OTHER")
        s = stats.get(connection_key(protocol, m.get("Src IP"), m.get("Src Port"), m.get("Dst IP"), m.get("Dst Port")))
        if s is not None:
            finding["connection"] = {"bytes": s["bytes"], "packets": s["packets"],
                                     "flags": sorted(s["flags"]), "first_time": s["first_time"]}


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


def attack_by_connection(findings: List[Dict[str, Any]]) -> Dict[str, str]:
    """Connection -> the ML attack class of its first non-benign flow."""
    result: Dict[str, str] = {}
    for f in findings:
        m = f.get("metadata") or {}
        if f.get("predicted_class") in (None, "", "Benign"):
            continue
        protocol = PROTOCOL_NAMES.get(int(m.get("Protocol") or 0), "OTHER")
        result.setdefault(connection_key(protocol, m.get("Src IP"), m.get("Src Port"), m.get("Dst IP"), m.get("Dst Port")),
                          f["predicted_class"])
    return result


def query_packets(packets: List[Dict[str, Any]], attacks: Dict[str, str], offset: int = 0, limit: int = 500,
                  protocol: str = "", flag: str = "", attack: str = "", text: str = "") -> Dict[str, Any]:
    """One page of packets matching every filter given. Words in `text`
    must all appear (any order, any case)."""
    words = [w.lower() for w in text.split()]
    counts_protocol: Dict[str, int] = defaultdict(int)
    counts_flag: Dict[str, int] = defaultdict(int)
    counts_attack: Dict[str, int] = defaultdict(int)
    rows = []
    matched = 0
    for p in packets:
        display = p.get("display_protocol") or p.get("protocol") or "OTHER"
        flags = flag_names(p.get("tcp_flags", ""))
        key = (connection_key(p["protocol"], p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"])
               if p.get("source_port") is not None else "")
        packet_attack = attacks.get(key, "")
        counts_protocol[display] += 1
        for name in flags:
            counts_flag[name] += 1
        if packet_attack:
            counts_attack[packet_attack] += 1
        if protocol and display != protocol:
            continue
        if flag and flag not in flags:
            continue
        if attack and packet_attack != attack:
            continue
        if words:
            haystack = " ".join(str(v) for v in (p["packet_number"], p.get("source_ip"), p.get("source_port"),
                                                 p.get("destination_ip"), p.get("destination_port"), display,
                                                 p.get("info", ""), " ".join(flags), packet_attack)).lower()
            if not all(w in haystack for w in words):
                continue
        if offset <= matched < offset + limit:
            rows.append({**p, "display_protocol": display, "flags": flags, "attack": packet_attack})
        matched += 1
    return {"total": len(packets), "matched": matched, "offset": offset, "rows": rows,
            "protocols": dict(sorted(counts_protocol.items())), "flags": dict(sorted(counts_flag.items())),
            "attacks": dict(sorted(counts_attack.items()))}


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
    att = attack_by_connection([finding])
    assert query_packets(pk, att, attack="PortScan")["matched"] == 2
    assert query_packets(pk, att, protocol="ARP", text="who 10.0.0.2")["matched"] == 1
    assert query_packets(pk, att, flag="RST")["matched"] == 1
    page = query_packets(pk, att, offset=1, limit=1)
    assert page["matched"] == 3 and [r["packet_number"] for r in page["rows"]] == [2]
    print("ALL CHECKS PASSED")
