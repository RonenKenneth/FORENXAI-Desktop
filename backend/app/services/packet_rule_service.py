"""
packet_rule_service.py
----------------------
Tier 2 rule-based detection: what the packets carry, not only how many.

Tier 1 (rule_service.py) reads the CICFlowMeter CSV and so sees counts,
sizes and timing. Payload attacks, ARP spoofing and header tricks leave no
trace there, so Tier 2 reads the uploaded pcap itself, from two sources:

  scapy checks    run on every capture, in the same pass that already reads
                  the pcap for the traffic summary (PacketInspector.add):
                    T2-MITM-01        several MACs claim one IP / gratuitous ARP burst
                    T2-EVASION-01     NULL / XMAS / SYN+FIN flags, overlapping
                                      fragments, TTL changes inside one flow
                    T2-WEB-01         injection patterns in plain HTTP requests
                    T2-API-01         API call bursts, 401 / 403 / 429 bursts
                    T2-BRUTEFORCE-01  failed-login replies (FTP, SMTP, POP3, HTTP)
                    T2-DNS-01         long or random-looking query names (tunnelling)
                    T2-TLS-01         ClientHello offering SSL 2/3 or TLS 1.0 at most
                    T2-BOF-01         NOP sleds and long filler runs in payload
  Suricata        with the Emerging Threats Open ruleset, when installed
                  (run_suricata): its alerts are mapped to classes by the
                  ordered table in rules.json -> suricata.class_mapping.

Content checks (WEB, API, BRUTEFORCE, DNS, BOF) need unencrypted traffic.
Flows on TLS / SSH, or on the encrypted ports in rules.json, are marked
payload_encrypted so the interface says "content rules not applied" rather
than "clean". The TLS handshake itself is readable, so T2-TLS-01 still runs.

The scapy checks read one packet at a time and do not reassemble TCP
streams, so a pattern split across two segments is missed; Suricata does
reassemble. Hits use the Tier 1 format with tier 2, and are attached to the
CICFlowMeter rows by 5-tuple and time (attach), so the recommendation, the
verdict and the interface treat both tiers alike.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

import numpy as np
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from app.services import rule_service as rs

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")

# Conservative patterns: each names one attack technique, not a keyword that
# also appears in normal URLs. Matched on the URL-decoded, lower-cased text.
WEB_PATTERNS = [
    ("SQL injection", re.compile(r"union(\s|/\*.*?\*/|\+)+(all(\s|\+)+)?select\b")),
    ("SQL injection", re.compile(r"'\s*(or|and)\s+'?\w+'?\s*=\s*'?\w+")),
    ("SQL injection", re.compile(r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d")),
    ("SQL injection", re.compile(r"waitfor\s+delay\s+'|information_schema\.")),
    ("cross-site scripting", re.compile(r"<\s*script\b|javascript\s*:|<[^>]+\bon(error|load|mouseover)\s*=")),
    ("path traversal", re.compile(r"(\.\./){2,}|(\.\.\\){2,}|/etc/(passwd|shadow)\b|\bwin\.ini\b|\bboot\.ini\b")),
    ("command injection", re.compile(r"[;|`]\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b|\$\(\s*(id|whoami|cat)\b")),
]

FAILED_LOGIN = [                      # (server port, reply prefix, description)
    (21, b"530", "FTP 530 login incorrect"),
    (25, b"535", "SMTP 535 authentication failed"),
    (587, b"535", "SMTP 535 authentication failed"),
    (110, b"-ERR", "POP3 -ERR"),
    (23, b"Login incorrect", "Telnet login incorrect"),
]

# Written by update_suricata_rules.py; used when rules.json names no rules_file.
DEFAULT_RULES_FILE = Path(__file__).resolve().parents[3] / "tools" / "suricata" / "et-open.rules"

MAX_OPEN_REQUESTS = 100_000
MAX_TAILS = 200_000

TLS_VERSIONS = {0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0"}


def _key(proto, a_ip, a_port, b_ip, b_port):
    """Direction-free flow key, the same for both directions of a connection."""
    a, b = (str(a_ip), int(a_port or 0)), (str(b_ip), int(b_port or 0))
    return (int(proto),) + (a + b if a <= b else b + a)


def _entropy(text: str) -> float:
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values()) if n else 0.0


def _hit(rule_id, rule, evidence, measured, threshold, source="scapy"):
    return {"rule_id": rule_id, "class": rule["class"], "tier": 2, "source": source,
            "evidence": evidence, "measured": measured, "threshold": threshold,
            "severity": rule.get("severity", "medium")}


# ------------------------------------------------------------------
# scapy checks
# ------------------------------------------------------------------

class PacketInspector:
    """Collects Tier 2 observations one packet at a time; hits() judges them."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or rs.load_config()
        self.rules = self.config.get("packet_rules", {})
        self.window = int(self.config.get("window_seconds", 60))
        self.encrypted_ports = set(self.rules.get("encrypted_ports", []))
        self.max_payload = int(self.rules.get("max_payload_bytes", 4096))
        self.first_time: Optional[float] = None
        self.packets = 0
        self.encrypted_keys: set = set()
        self.api_flows: set = set()
        self.arp_macs: Dict[str, Dict[str, float]] = defaultdict(dict)   # ip -> mac -> first seen
        self.gratuitous: Dict[str, List[float]] = defaultdict(list)
        self.flags: Dict[tuple, List[Any]] = {}                         # key -> [count, names, t]
        self.ttl: Dict[tuple, List[Any]] = {}                           # directed -> [last, changes, key, t]
        self.fragments: Dict[tuple, List[Tuple[int, int]]] = defaultdict(list)
        self.fragment_overlaps: Dict[tuple, List[Any]] = {}
        self.web: List[Tuple[tuple, float, str, str, str, str]] = []
        self.groups: Dict[str, Dict[tuple, List[Any]]] = defaultdict(lambda: defaultdict(list))
        self.tls_weak: Dict[tuple, Tuple[float, str, str, str]] = {}
        self.bof: Dict[tuple, Tuple[float, str, int, str, str]] = {}
        self.errors = 0
        self.requests: Dict[tuple, List[Any]] = {}                      # open plain-HTTP requests
        self.paths: Dict[tuple, set] = defaultdict(set)                  # (client, server, window) -> paths
        self.tails: Dict[tuple, bytes] = {}                              # last bytes per direction (BOF)

    def _on(self, rule_id):
        return self.rules.get(rule_id, {}).get("enabled", False)

    # one packet --------------------------------------------------------
    def add(self, packet) -> None:
        try:
            self._add(packet)
        except Exception:                                   # noqa: BLE001
            self.errors += 1                                # one malformed packet never stops the case

    def _add(self, packet) -> None:
        t = float(packet.time)
        self.packets += 1
        if self.first_time is None or t < self.first_time:
            self.first_time = t

        if ARP in packet:
            if self._on("T2-MITM-01"):
                arp = packet[ARP]
                if int(arp.op) == 2 and arp.hwsrc not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    self.arp_macs[arp.psrc].setdefault(arp.hwsrc, t)
                if arp.psrc == arp.pdst and arp.psrc not in ("0.0.0.0",):
                    self.gratuitous[arp.psrc].append(t)
            return

        if IP in packet:
            ip = packet[IP]
            src, dst, proto, ttl = ip.src, ip.dst, int(ip.proto), int(ip.ttl)
        elif IPv6 in packet:
            ip = packet[IPv6]
            src, dst, proto, ttl = ip.src, ip.dst, int(ip.nh), int(ip.hlim)
        else:
            return

        sport = dport = 0
        layer = None
        if TCP in packet:
            layer, proto = packet[TCP], 6
        elif UDP in packet:
            layer, proto = packet[UDP], 17
        if layer is not None:
            sport, dport = int(layer.sport), int(layer.dport)
        key = _key(proto, src, sport, dst, dport)

        if IP in packet and self._on("T2-EVASION-01"):
            self._evasion_ip(packet[IP], key, t)
        if self._on("T2-EVASION-01") and layer is not None:
            directed = (src, sport, dst, dport, proto)
            state = self.ttl.get(directed)
            if state is None:
                self.ttl[directed] = [ttl, 0, key, t]
            elif ttl != state[0]:
                state[0], state[1] = ttl, state[1] + 1
        if proto == 6 and self._on("T2-EVASION-01"):
            flags = int(packet[TCP].flags)
            name = ("NULL" if flags == 0 else "XMAS" if flags & 0x29 == 0x29
                    else "SYN+FIN" if flags & 0x03 == 0x03 else None)
            if name:
                entry = self.flags.setdefault(key, [0, set(), t, src, dst])
                entry[0] += 1
                entry[1].add(name)

        if proto == 17 and 53 in (sport, dport):
            self._dns(packet, key, src, t)

        if layer is None:
            return
        payload = bytes(layer.payload)[: self.max_payload]
        if not payload:
            return
        if dport in self.encrypted_ports or sport in self.encrypted_ports:
            self.encrypted_keys.add(key)
        if self._tls(payload, key, src, dst, t) or payload.startswith(b"SSH-"):
            self.encrypted_keys.add(key)
            return
        if key in self.encrypted_keys:
            return
        self._http(payload, key, src, dst, sport, dport, t)
        self._failed_login(payload, key, src, dst, sport, t)
        self._bof(payload, key, (src, sport, dst, dport), src, dst, t)

    # per-check helpers -------------------------------------------------
    def _evasion_ip(self, ip, key, t):
        mf, offset = bool(int(ip.flags) & 0x1), int(ip.frag) * 8
        if not mf and offset == 0:
            return
        span = (offset, offset + len(ip.payload))
        fid = (ip.src, ip.dst, int(ip.id), int(ip.proto))
        if any(span[0] < end and start < span[1] for start, end in self.fragments[fid]):
            entry = self.fragment_overlaps.setdefault(fid, [0, key, t])
            entry[0] += 1
        self.fragments[fid].append(span)

    def _dns(self, packet, key, src, t):
        if not self._on("T2-DNS-01"):
            return
        if DNS not in packet or int(packet[DNS].qr) != 0 or DNSQR not in packet:
            return
        name = packet[DNSQR].qname
        name = (name.decode("ascii", "replace") if isinstance(name, bytes) else str(name)).rstrip(".")
        rule = self.rules["T2-DNS-01"]
        longest = max(name.split("."), key=len) if name else ""
        if len(name) > rule["min_name_length"] or _entropy(longest) > rule["min_label_entropy"]:
            self.groups["dns"][(src, int(t // self.window))].append((key, t, name))

    def _tls(self, payload, key, src, dst, t) -> bool:
        """True for a TLS / SSL record; records a weak ClientHello."""
        version = None
        if len(payload) >= 11 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03 \
                and payload[2] <= 0x04:
            if payload[0] == 0x16 and payload[5] == 0x01:
                version = payload[9] << 8 | payload[10]
        elif len(payload) >= 5 and payload[0] & 0x80 and payload[2] == 0x01 \
                and payload[3:5] in (b"\x00\x02", b"\x03\x00", b"\x03\x01"):
            version = 0x0002                                  # SSLv2-format ClientHello
        else:
            return False
        rule = self.rules.get("T2-TLS-01", {})
        if version is not None and self._on("T2-TLS-01") \
                and version <= int(str(rule.get("max_weak_version", "0x0301")), 16) \
                and key not in self.tls_weak:
            self.tls_weak[key] = (t, TLS_VERSIONS.get(version, f"0x{version:04x}"), src, dst)
        return True

    def _http(self, payload, key, src, dst, sport, dport, t):
        """HTTP requests and replies. A request is buffered until its reply
        (or max_payload_bytes), so a pattern split across TCP segments is
        still seen; segments are appended in arrival order."""
        window = int(t // self.window)
        directed = (src, sport, dst, dport)
        if payload.startswith(HTTP_METHODS):
            head = payload.partition(b"\r\n\r\n")[0]
            request_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = request_line.split(" ")
            path = parts[1] if len(parts) > 1 else ""
            self.paths[(src, dst, window)].add(path.split("?", 1)[0])
            if self._on("T2-API-01"):
                markers = self.rules["T2-API-01"]["api_path_markers"]
                if any(m in path.lower() for m in markers) or b"application/json" in head.lower():
                    self.api_flows.add(key)
                    self.groups["api_calls"][(src, dst, window)].append((key, t, path))
            if len(self.requests) > MAX_OPEN_REQUESTS:
                self.requests.clear()        # ponytail: drop buffers on floods; per-flow LRU if that loses real hits
            self.requests[directed] = [bytearray(payload[: self.max_payload]), False]
            self._match_request(directed, key, src, dst, t)
        elif directed in self.requests:
            buffer = self.requests[directed][0]
            buffer += payload[: self.max_payload - len(buffer)]
            self._match_request(directed, key, src, dst, t)
            if len(buffer) >= self.max_payload:
                del self.requests[directed]
        elif payload.startswith(b"HTTP/1.") and len(payload) >= 12:
            self.requests.pop((dst, dport, src, sport), None)
            try:
                status = int(payload[9:12])
            except ValueError:
                return
            client = dst                                      # a response goes back to the client
            if 400 <= status < 500:
                self.groups["http_4xx"][(client, src, window)].append((key, t, status))
            if status in (401, 403, 429) and key in self.api_flows and self._on("T2-API-01"):
                self.groups["api_fail"][(client, src, window)].append((key, t, status))
            elif status == 401 and self._on("T2-BRUTEFORCE-01"):
                self.groups["login_fail"][(client, src, window)].append((key, t, "HTTP 401"))

    def _match_request(self, directed, key, src, dst, t):
        state = self.requests.get(directed)
        if not self._on("T2-WEB-01") or state is None or state[1]:
            return
        head, _, body = bytes(state[0]).partition(b"\r\n\r\n")
        text = head.split(b"\r\n", 1)[0].decode("latin-1", "replace") + " " + body.decode("latin-1", "replace")
        decoded = unquote_plus(unquote_plus(text)).lower()
        for technique, pattern in WEB_PATTERNS:
            match = pattern.search(decoded)
            if match:
                state[1] = True                               # one match per request
                self.web.append((key, t, src, dst, technique, match.group(0)[:60]))
                return

    def _failed_login(self, payload, key, src, dst, sport, t):
        if not self._on("T2-BRUTEFORCE-01"):
            return
        for port, prefix, text in FAILED_LOGIN:
            if sport == port and prefix in payload[:64]:
                self.groups["login_fail"][(dst, src, int(t // self.window))].append((key, t, text))
                return

    def _bof(self, payload, key, directed, src, dst, t):
        """NOP / filler runs, including one split across two segments: the
        last bytes of the previous segment are searched with this one."""
        if not self._on("T2-BOF-01") or key in self.bof:
            return
        rule = self.rules["T2-BOF-01"]
        keep = max(rule["min_nop_run"], rule["min_filler_run"]) - 1
        if len(self.tails) > MAX_TAILS:
            self.tails.clear()               # ponytail: bounded memory on huge captures; LRU if split runs get missed
        payload = self.tails.get(directed, b"") + payload
        self.tails[directed] = payload[-keep:]
        if b"\x90" * rule["min_nop_run"] in payload:
            self.bof[key] = (t, "NOP (0x90)", rule["min_nop_run"], src, dst)
            return
        for value in rule.get("filler_bytes", []):
            byte = bytes([int(value, 16)])
            if byte != b"\x90" and byte * rule["min_filler_run"] in payload:
                self.bof[key] = (t, f"filler byte {value}", rule["min_filler_run"], src, dst)
                return

    # judgement ---------------------------------------------------------
    def hits(self) -> List[Dict[str, Any]]:
        """Every Tier 2 hit, each with the flows it concerns under "_flows"
        [(key, time)] or, for ARP, the contested address under "_ip"."""
        out: List[Dict[str, Any]] = []
        R, w = self.rules, self.window

        if self._on("T2-MITM-01"):
            rule = R["T2-MITM-01"]
            for ip, macs in self.arp_macs.items():
                if len(macs) >= rule["min_macs_per_ip"]:
                    hit = _hit("T2-MITM-01", rule,
                               f"{len(macs)} MAC addresses ({', '.join(sorted(macs))}) claimed {ip} "
                               f"in ARP replies (threshold {rule['min_macs_per_ip']}).",
                               len(macs), rule["min_macs_per_ip"])
                    hit["_ip"], hit["_since"] = ip, sorted(macs.values())[1]
                    out.append(hit)
            for ip, times in self.gratuitous.items():
                times = np.sort(np.asarray(times))
                if len(times) < rule["min_gratuitous_arp"]:
                    continue
                n = rule["min_gratuitous_arp"]
                spans = times[n - 1:] - times[: len(times) - n + 1]
                if (spans <= w).any():
                    peak = int(max(np.searchsorted(times, times + w, side="right") - np.arange(len(times))))
                    hit = _hit("T2-MITM-01", rule,
                               f"{peak} gratuitous ARP announcements for {ip} within {w} s "
                               f"(threshold {rule['min_gratuitous_arp']}).",
                               peak, rule["min_gratuitous_arp"])
                    hit["_ip"], hit["_since"] = ip, float(times[0])
                    out.append(hit)

        if self._on("T2-EVASION-01"):
            rule = R["T2-EVASION-01"]
            for key, (count, names, t, src, dst) in self.flags.items():
                if count >= rule["min_illegal_flag_packets"]:
                    hit = _hit("T2-EVASION-01", rule,
                               f"{count} TCP packets from {src} to {dst} with illegal flag sets "
                               f"({', '.join(sorted(names))}) (threshold {rule['min_illegal_flag_packets']}).",
                               count, rule["min_illegal_flag_packets"])
                    hit["_flows"] = [(key, t)]
                    out.append(hit)
            for (src, dst, _, _), (count, key, t) in self.fragment_overlaps.items():
                if count >= rule["min_overlapping_fragments"]:
                    hit = _hit("T2-EVASION-01", rule,
                               f"{count} overlapping IP fragments from {src} to {dst} "
                               f"(threshold {rule['min_overlapping_fragments']}).",
                               count, rule["min_overlapping_fragments"])
                    hit["_flows"] = [(key, t)]
                    out.append(hit)
            for (src, _, dst, _, _), (_, changes, key, t) in self.ttl.items():
                if changes >= rule["min_ttl_changes"]:
                    hit = _hit("T2-EVASION-01", rule,
                               f"The TTL of packets from {src} to {dst} changed {changes} times inside "
                               f"one flow (threshold {rule['min_ttl_changes']}).",
                               changes, rule["min_ttl_changes"])
                    hit["_flows"] = [(key, t)]
                    out.append(hit)

        if self._on("T2-WEB-01"):
            rule = R["T2-WEB-01"]
            by_flow: Dict[tuple, List[Any]] = defaultdict(list)
            for key, t, src, dst, technique, text in self.web:
                by_flow[key].append((t, src, dst, technique, text))
            for key, matches in by_flow.items():
                if len(matches) < rule["min_matches"]:
                    continue
                t, src, dst, technique, text = matches[0]
                techniques = sorted({m[3] for m in matches})
                hit = _hit("T2-WEB-01", rule,
                           f"{len(matches)} HTTP request(s) from {src} to {dst} matched "
                           f"{', '.join(techniques)} patterns, e.g. \"{text}\" "
                           f"(threshold {rule['min_matches']}).",
                           len(matches), rule["min_matches"])
                hit["_flows"] = [(key, t)]
                out.append(hit)

        def grouped(name, rule_id, threshold_key, describe):
            if not self._on(rule_id):
                return
            rule = R[rule_id]
            for group, events in self.groups[name].items():
                if len(events) >= rule[threshold_key]:
                    hit = _hit(rule_id, rule, describe(group, events, rule), len(events), rule[threshold_key])
                    hit["_flows"] = [(e[0], e[1]) for e in events]
                    out.append(hit)

        grouped("api_calls", "T2-API-01", "min_calls", lambda g, e, r:
                f"{len(e)} API requests from {g[0]} to {g[1]} within {w} s "
                f"(threshold {r['min_calls']}).")
        grouped("api_fail", "T2-API-01", "min_auth_failures", lambda g, e, r:
                f"{len(e)} API replies {'/'.join(str(s) for s in sorted({x[2] for x in e}))} from {g[1]} "
                f"to {g[0]} within {w} s (threshold {r['min_auth_failures']}).")
        grouped("login_fail", "T2-BRUTEFORCE-01", "min_failed_logins", lambda g, e, r:
                f"{len(e)} failed-login replies ({', '.join(sorted({x[2] for x in e}))}) from {g[1]} "
                f"to {g[0]} within {w} s (threshold {r['min_failed_logins']}).")
        if self._on("T2-WEB-01"):
            rule = R["T2-WEB-01"]
            for (client, server, window), events in self.groups["http_4xx"].items():
                paths = len(self.paths.get((client, server, window), ()))
                if len(events) >= rule["min_error_replies"] and paths >= rule["min_distinct_paths"]:
                    hit = _hit("T2-WEB-01", rule,
                               f"{len(events)} HTTP 4xx replies from {server} to {client} covering {paths} "
                               f"distinct paths within {w} s (thresholds {rule['min_error_replies']} replies "
                               f"and {rule['min_distinct_paths']} paths).",
                               len(events), rule["min_error_replies"])
                    hit["_flows"] = [(e[0], e[1]) for e in events]
                    out.append(hit)

        grouped("dns", "T2-DNS-01", "min_queries", lambda g, e, r:
                f"{len(e)} DNS queries from {g[0]} within {w} s with names longer than "
                f"{r['min_name_length']} characters or label entropy above {r['min_label_entropy']}, "
                f"e.g. {e[0][2][:80]} (threshold {r['min_queries']}).")

        if self._on("T2-TLS-01"):
            rule = R["T2-TLS-01"]
            for key, (t, version, src, dst) in self.tls_weak.items():
                hit = _hit("T2-TLS-01", rule,
                           f"TLS ClientHello from {src} to {dst} offers {version} as its highest version.",
                           version, "TLS 1.2")
                hit["_flows"] = [(key, t)]
                out.append(hit)

        if self._on("T2-BOF-01"):
            rule = R["T2-BOF-01"]
            for key, (t, kind, run, src, dst) in self.bof.items():
                hit = _hit("T2-BOF-01", rule,
                           f"Payload from {src} to {dst} contains a run of at least {run} {kind} bytes.",
                           run, run)
                hit["_flows"] = [(key, t)]
                out.append(hit)
        return out


# ------------------------------------------------------------------
# Suricata
# ------------------------------------------------------------------

def _suricata_binary(cfg: Dict[str, Any]) -> Optional[str]:
    backend = Path(__file__).resolve().parents[2]
    candidates = [os.environ.get("FORENXAI_SURICATA"), cfg.get("binary"),
                  backend.parent / "tools" / "suricata" / "suricata.exe",
                  backend.parent / "tools" / "suricata" / "suricata",
                  shutil.which("suricata"),
                  "C:/Program Files/Suricata/suricata.exe"]
    for c in candidates:
        if c and Path(c).is_file():
            return str(c)
    return None


def _epoch(stamp: str) -> Optional[float]:
    try:
        return datetime.fromisoformat(re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", stamp)).timestamp()
    except (TypeError, ValueError):
        return None


def map_alert(signature: str, category: str, mapping: List[Dict[str, Any]]) -> Optional[str]:
    """First mapping entry whose prefix or category matches (and whose
    'contains' words, if any, appear in the signature)."""
    sig, cat = signature or "", (category or "").lower()
    lower = sig.lower()
    for entry in mapping:
        named = any(sig.startswith(p) for p in entry.get("prefixes", []))
        categorised = cat and any(cat == c.lower() for c in entry.get("categories", []))
        if not (named or categorised):
            continue
        words = entry.get("contains")
        if words and not any(w in lower for w in words):
            continue
        return entry["class"]
    return None


def run_suricata(pcap: Path, out_dir: Path,
                 config: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Suricata alerts on the capture as Tier 2 hits, and what happened."""
    cfg = (config or rs.load_config()).get("suricata", {})
    status: Dict[str, Any] = {"ran": False, "alerts": 0, "mapped": 0, "unmapped_signatures": []}
    if not cfg.get("enabled", True):
        status["reason"] = "disabled in rules.json"
        return [], status
    binary = _suricata_binary(cfg)
    if binary is None:
        status["reason"] = ("Suricata is not installed; signature classes rely on the "
                            "scapy checks only.")
        return [], status
    out_dir.mkdir(parents=True, exist_ok=True)
    command = [binary, "-r", str(pcap), "-l", str(out_dir), "-k", "none"]
    config_file = cfg.get("config") or next(
        (str(p) for p in (Path(binary).parent / "suricata.yaml",) if p.is_file()), "")
    if config_file:
        command += ["-c", config_file]
    rules_file = cfg.get("rules_file") or (str(DEFAULT_RULES_FILE) if DEFAULT_RULES_FILE.is_file() else "")
    if rules_file:
        command += ["-S", rules_file]
    status["rules_file"] = rules_file or "suricata.yaml default"
    status["binary"] = binary
    try:
        finished = subprocess.run(command, capture_output=True, text=True, cwd=str(Path(binary).parent),
                                  timeout=int(cfg.get("timeout_seconds", 900)))
    except (OSError, subprocess.SubprocessError) as error:
        status["reason"] = f"Suricata failed to run: {type(error).__name__}: {error}"
        return [], status
    eve = out_dir / "eve.json"
    if finished.returncode != 0 or not eve.exists():
        status["reason"] = (f"Suricata exited with code {finished.returncode}: "
                            f"{(finished.stderr or finished.stdout)[-300:].strip()}")
        return [], status
    status["ran"] = True
    return parse_eve(eve, cfg, status), status


def parse_eve(eve: Path, cfg: Dict[str, Any], status: Dict[str, Any]) -> List[Dict[str, Any]]:
    mapping = cfg.get("class_mapping", [])
    worst = int(cfg.get("min_severity", 3))
    ignored = cfg.get("ignore_signatures_containing", [])
    grouped: Dict[Tuple[int, tuple], Dict[str, Any]] = {}
    unmapped = Counter()
    with eve.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event_type") != "alert":
                continue
            status["alerts"] += 1
            alert = event.get("alert", {})
            severity = int(alert.get("severity", 3))
            if severity > worst:
                continue
            signature = str(alert.get("signature", ""))
            if any(w.lower() in signature.lower() for w in ignored):
                status["ignored"] = status.get("ignored", 0) + 1
                continue
            cls = map_alert(signature, alert.get("category", ""), mapping)
            if cls is None:
                unmapped[signature] += 1
                continue
            proto = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(str(event.get("proto", "")).upper(), 0)
            key = _key(proto, event.get("src_ip", ""), event.get("src_port", 0),
                       event.get("dest_ip", ""), event.get("dest_port", 0))
            sid = int(alert.get("signature_id", 0))
            entry = grouped.get((sid, key))
            if entry is None:
                rule = {"class": cls, "severity": {1: "high", 2: "medium"}.get(severity, "low")}
                entry = _hit(f"T2-SURICATA-{sid}", rule, "", 0, 1, source="suricata")
                entry.update(_flows=[], _sig=signature, _cat=alert.get("category", ""),
                             _src=f"{event.get('src_ip')}:{event.get('src_port', '')}",
                             _dst=f"{event.get('dest_ip')}:{event.get('dest_port', '')}")
                grouped[(sid, key)] = entry
            entry["measured"] += 1
            entry["_flows"].append((key, _epoch(event.get("timestamp", ""))))
    hits = []
    for (sid, _), h in grouped.items():
        h["evidence"] = (f"Suricata signature {sid} matched {h['measured']} time(s): {h.pop('_sig')} "
                         f"(category {h.pop('_cat') or 'none'}) from {h.pop('_src')} to {h.pop('_dst')}.")
        hits.append(h)
    status["mapped"] = sum(h["measured"] for h in hits)
    status["unmapped_signatures"] = [s for s, _ in unmapped.most_common(10)]
    return hits


# ------------------------------------------------------------------
# attaching packet hits to CICFlowMeter rows
# ------------------------------------------------------------------

def attach(frame, hits: List[Dict[str, Any]], first_packet_time: Optional[float],
           encrypted_keys: set, encrypted_ports) -> Tuple[List[List[Dict[str, Any]]], List[bool], List[Dict[str, Any]]]:
    """Per CSV row: its Tier 2 hits and whether its payload is encrypted;
    plus the hits that matched no row (capture-level)."""
    df = rs.normalise(frame).reset_index(drop=True)
    n = len(df)
    start = rs._seconds(df["ts"])
    # CICFlowMeter writes local wall-clock time; packets carry UTC epochs.
    # The offset is the time zone, so round the gap to a quarter hour.
    finite = start[np.isfinite(start)]
    offset = 0.0
    if first_packet_time is not None and len(finite):
        offset = round((finite.min() - first_packet_time) / 900.0) * 900.0
    end = start + np.nan_to_num(df["duration"].to_numpy(dtype=float)) / 1e6

    index: Dict[tuple, List[int]] = defaultdict(list)
    keys = []
    for i, (p, a, ap, b, bp) in enumerate(zip(df["proto"].fillna(0), df["src_ip"], df["src_port"].fillna(0),
                                              df["dst_ip"], df["dst_port"].fillna(0))):
        k = _key(p, a, ap, b, bp)
        keys.append(k)
        index[k].append(i)
    ports = set(encrypted_ports)
    encrypted = [k in encrypted_keys or k[2] in ports or k[4] in ports for k in keys]

    per_row: List[List[Dict[str, Any]]] = [[] for _ in range(n)]
    unattached = []

    def row_for(key, t):
        rows = index.get(key)
        if not rows:
            return None
        if len(rows) == 1 or t is None:
            return rows[0]
        local = t + offset
        inside = [r for r in rows if start[r] - 1 <= local <= end[r] + 1]
        pool = inside or rows
        return min(pool, key=lambda r: abs(start[r] - local) if np.isfinite(start[r]) else math.inf)

    for hit in hits:
        public = {k: v for k, v in hit.items() if not k.startswith("_")}
        rows = set()
        if "_ip" in hit:                                  # MITM: traffic to or from the contested address
            since = hit.get("_since", -math.inf) + offset
            rows = {i for i in range(n) if (df.at[i, "src_ip"] == hit["_ip"] or df.at[i, "dst_ip"] == hit["_ip"])
                    and not (np.isfinite(end[i]) and end[i] < since)}
        for key, t in hit.get("_flows", []):
            r = row_for(key, t)
            if r is not None:
                rows.add(r)
        for r in rows:
            if not any(h["rule_id"] == public["rule_id"] for h in per_row[r]):
                per_row[r].append(public)
        if not rows:
            unattached.append(public)
    return per_row, encrypted, unattached


# ------------------------------------------------------------------
# public
# ------------------------------------------------------------------

def evaluate(pcap: Path, flow_csv: str, findings: List[Dict[str, Any]],
             inspector: PacketInspector, work_dir: Path):
    """Tier 2 hits per flow_index, encrypted flags per flow_index, and a
    capture-level summary. Hits are None when the flows could not be matched."""
    import pandas as pd

    summary: Dict[str, Any] = {"packets_inspected": inspector.packets,
                               "malformed_packets_skipped": inspector.errors}
    hits = inspector.hits()
    suricata_hits, summary["suricata"] = run_suricata(Path(pcap), Path(work_dir) / "suricata",
                                                      inspector.config)
    hits += suricata_hits
    try:
        frame = pd.read_csv(flow_csv, low_memory=False)
        per_row, encrypted, unattached = attach(
            frame, hits, inspector.first_time, inspector.encrypted_keys,
            inspector.rules.get("encrypted_ports", []))
    except Exception as error:                              # noqa: BLE001
        print(f"[FORENXAI] Tier 2 not attached ({type(error).__name__}: {error})", flush=True)
        summary["error"] = f"{type(error).__name__}: {error}"
        return None, None, summary
    if len(per_row) != len(findings):
        summary["error"] = f"{len(per_row)} flow records but {len(findings)} classified flows"
        return None, None, summary

    by_index, enc_by_index = {}, {}
    for finding, row_hits, enc in zip(findings, per_row, encrypted):
        index = finding.get("flow_index")
        if index is not None:
            by_index[int(index)] = row_hits
            enc_by_index[int(index)] = bool(enc)

    fired = Counter(h["rule_id"] for row in per_row for h in row)
    summary.update({
        "flows_flagged": sum(1 for row in per_row if row),
        "rules_fired": dict(fired),
        "encrypted_flows": int(sum(encrypted)),
        "inspectable_share": round(1 - sum(encrypted) / len(encrypted), 4) if encrypted else None,
        "capture_level_hits": unattached,
    })
    print(f"[FORENXAI] Tier 2: {summary['flows_flagged']} of {len(per_row)} flows flagged"
          + (f" -- {dict(fired)}" if fired else "")
          + f"; {summary['encrypted_flows']} encrypted; Suricata "
          + ("ran" if summary["suricata"]["ran"] else f"not run ({summary['suricata'].get('reason')})"),
          flush=True)
    return by_index, enc_by_index, summary
