"""
test_packet_rules.py
--------------------
Checks the Tier 2 packet rules (packet_rule_service.py) and decide() on
synthetic packets: each rule fires on a small hand-made attack and stays
silent on a near-miss, hits land on the right CICFlowMeter row, encrypted
flows are marked, and Suricata alerts map to classes.

    python test_packet_rules.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pandas as pd
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from app.services import packet_rule_service as ps
from app.services import rule_service as rs
from app.services.pcap_service import extract_packets

FAILED = []
T0 = 1_790_000_000.0                      # epoch seconds
A, S = "10.0.0.5", "10.0.0.20"            # attacker / client, server


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILED.append(name)


def pkt(p, t):
    p.time = t
    return p


def tcp(payload, t, sport=40000, dport=80, src=A, dst=S, flags="PA"):
    return pkt(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(payload), t)


def inspect(packets):
    inspector = ps.PacketInspector()
    for p in packets:
        inspector.add(p)
    return inspector, inspector.hits()


def fired(hits, rule_id):
    return [h for h in hits if h["rule_id"] == rule_id]


def main():
    print("1. each Tier 2 rule fires on its attack and not on a near-miss")

    # MITM: two MACs claim the gateway
    arp = [pkt(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:01", pdst=A), T0),
           pkt(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:02", pdst=A), T0 + 5)]
    check("MITM: two MACs for one IP fires", len(fired(inspect(arp)[1], "T2-MITM-01")) == 1)
    check("MITM: one MAC repeated does not", not fired(inspect(arp[:1] * 3)[1], "T2-MITM-01"))
    garp = [pkt(Ether() / ARP(op=1, psrc="10.0.0.9", pdst="10.0.0.9", hwsrc="aa:aa:aa:aa:aa:09"), T0 + i)
            for i in range(6)]
    check("MITM: gratuitous ARP burst fires", len(fired(inspect(garp)[1], "T2-MITM-01")) == 1)
    check("MITM: 4 gratuitous ARPs do not", not fired(inspect(garp[:4])[1], "T2-MITM-01"))

    # Evasion
    xmas = [pkt(Ether() / IP(src=A, dst=S) / TCP(sport=41000, dport=22, flags="FPU"), T0)]
    check("Evasion: XMAS flags fire", "XMAS" in fired(inspect(xmas)[1], "T2-EVASION-01")[0]["evidence"])
    check("Evasion: a normal SYN does not",
          not fired(inspect([pkt(Ether() / IP(src=A, dst=S) / TCP(flags="S"), T0)])[1], "T2-EVASION-01"))
    frag = [pkt(Ether() / IP(src=A, dst=S, id=7, flags="MF", frag=0, proto=17) / Raw(b"x" * 64), T0),
            pkt(Ether() / IP(src=A, dst=S, id=7, frag=4, proto=17) / Raw(b"y" * 64), T0 + 0.1)]
    check("Evasion: overlapping fragments fire",
          "overlapping" in fired(inspect(frag)[1], "T2-EVASION-01")[0]["evidence"])
    ttl = [pkt(Ether() / IP(src=A, dst=S, ttl=v) / TCP(sport=42000, dport=80, flags="A"), T0 + i)
           for i, v in enumerate([64, 50, 64, 50])]
    check("Evasion: 3 TTL changes in a flow fire", len(fired(inspect(ttl)[1], "T2-EVASION-01")) == 1)
    check("Evasion: 2 TTL changes do not", not fired(inspect(ttl[:3])[1], "T2-EVASION-01"))

    # WebBased
    sqli = tcp(b"GET /item.php?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users-- HTTP/1.1\r\nHost: s\r\n\r\n", T0)
    hit = fired(inspect([sqli])[1], "T2-WEB-01")
    check("WebBased: URL-encoded UNION SELECT fires", hit and "SQL injection" in hit[0]["evidence"])
    trav = tcp(b"GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\n\r\n", T0)
    check("WebBased: path traversal fires", "path traversal" in fired(inspect([trav])[1], "T2-WEB-01")[0]["evidence"])
    xss = tcp(b"POST /comment HTTP/1.1\r\n\r\nbody=%3Cscript%3Ealert(1)%3C/script%3E", T0)
    check("WebBased: XSS in the body fires", "cross-site" in fired(inspect([xss])[1], "T2-WEB-01")[0]["evidence"])
    normal = tcp(b"GET /search?q=select+a+union+rep&page=2 HTTP/1.1\r\nHost: s\r\n\r\n", T0)
    check("WebBased: ordinary words 'select' and 'union' do not", not fired(inspect([normal])[1], "T2-WEB-01"))
    check("WebBased: same attack over port 443 is not inspected (encrypted)",
          not fired(inspect([tcp(sqli[Raw].load, T0, dport=443)])[1], "T2-WEB-01"))

    # API
    api = [tcp(f"GET /api/users/{i} HTTP/1.1\r\n\r\n".encode(), T0 + i * 0.1, sport=43000) for i in range(10)]
    api += [tcp(b"HTTP/1.1 401 Unauthorized\r\n\r\n", T0 + i * 0.1 + 0.05, sport=80, dport=43000, src=S, dst=A)
            for i in range(10)]
    hit = fired(inspect(api)[1], "T2-API-01")
    check("API: 10 x 401 on API paths fires", hit and "401" in hit[0]["evidence"])
    check("API: 9 do not", not fired(inspect(api[:9] + api[10:19])[1], "T2-API-01"))

    # Bruteforce (failed logins)
    ftp = [tcp(b"530 Login incorrect.\r\n", T0 + i, sport=21, dport=44000, src=S, dst=A) for i in range(5)]
    hit = fired(inspect(ftp)[1], "T2-BRUTEFORCE-01")
    check("Bruteforce: 5 FTP 530 replies fire", hit and "FTP 530" in hit[0]["evidence"])
    check("Bruteforce: 4 do not", not fired(inspect(ftp[:4])[1], "T2-BRUTEFORCE-01"))

    # DNS tunnelling
    q = [pkt(Ether() / IP(src=A, dst="8.8.8.8") / UDP(sport=50000 + i, dport=53)
             / DNS(rd=1, qd=DNSQR(qname=f"a9f3k2l1q8z7x6c5v4b3n2m1p0o9i8u{i:02d}.tunnel.example.com")), T0 + i)
         for i in range(10)]
    check("DNS: 10 long random query names fire", len(fired(inspect(q)[1], "T2-DNS-01")) == 1)
    plain = [pkt(Ether() / IP(src=A, dst="8.8.8.8") / UDP(sport=50000 + i, dport=53)
                 / DNS(rd=1, qd=DNSQR(qname="www.example.com")), T0 + i) for i in range(20)]
    check("DNS: 20 ordinary queries do not", not fired(inspect(plain)[1], "T2-DNS-01"))

    # TLS
    def hello(version):
        body = bytes([0x01, 0, 0, 40]) + version.to_bytes(2, "big") + b"\x00" * 38
        return b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body
    old = tcp(hello(0x0301), T0, dport=443)
    check("TLSSSL: TLS 1.0 ClientHello fires",
          "TLS 1.0" in fired(inspect([old])[1], "T2-TLS-01")[0]["evidence"])
    check("TLSSSL: TLS 1.2 ClientHello does not",
          not fired(inspect([tcp(hello(0x0303), T0, dport=443)])[1], "T2-TLS-01"))

    # BufferOverflow
    nop = tcp(b"USER " + b"\x90" * 80 + b"\xcc" * 8, T0, dport=21)
    check("BufferOverflow: 80-byte NOP sled fires", len(fired(inspect([nop])[1], "T2-BOF-01")) == 1)
    check("BufferOverflow: 32 NOP bytes do not",
          not fired(inspect([tcp(b"\x90" * 32, T0, dport=21)])[1], "T2-BOF-01"))

    print("\n2. extract_packets feeds the inspector in its single pass")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "t.pcap"
        wrpcap(str(path), arp + [sqli])
        inspector = ps.PacketInspector()
        packets = extract_packets(path, on_packet=inspector.add)
        check("IP packets still returned as before (ARP excluded)", len(packets) == 1)
        check("inspector saw ARP and IP packets", inspector.packets == 3)
        check("and found both attacks",
              {h["rule_id"] for h in inspector.hits()} == {"T2-MITM-01", "T2-WEB-01"})

    print("\n3. hits attach to the right CICFlowMeter row (local-time timestamps)")
    local = pd.Timestamp(T0, unit="s") + pd.Timedelta(hours=8)          # CICFlowMeter writes local time
    fmt = lambda ts: ts.strftime("%d/%m/%Y %I:%M:%S %p")
    rows = pd.DataFrame({
        "Src IP": [A, A, A, "10.0.0.7"], "Src Port": [40000, 40000, 45000, 5555],
        "Dst IP": [S, S, S, "10.0.0.1"], "Dst Port": [80, 80, 443, 80], "Protocol": [6, 6, 6, 6],
        "Timestamp": [fmt(local + pd.Timedelta(minutes=30)), fmt(local), fmt(local), fmt(local + pd.Timedelta(minutes=1))],
        "Flow Duration": [1e6, 2e6, 1e6, 1e6], "Total Fwd Packet": [3] * 4,
        "Total Length of Fwd Packet": [100] * 4, "Total Length of Bwd Packet": [100] * 4,
        "Fwd Packet Length Mean": [30] * 4, "Down/Up Ratio": [1] * 4,
    })
    inspector, hits = inspect(arp + [sqli, tcp(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03", T0, sport=45000, dport=443)])
    per_row, encrypted, unattached = ps.attach(rows, hits, inspector.first_time, inspector.encrypted_keys,
                                               inspector.rules["encrypted_ports"])
    check("SQL injection lands on the row at the same time, not the one 30 min later",
          [h["rule_id"] for h in per_row[1]] == ["T2-WEB-01"] and not per_row[0])
    check("MITM lands on the later flow to the contested address 10.0.0.1",
          [h["rule_id"] for h in per_row[3]] == ["T2-MITM-01"])
    before = rows.copy()
    before.loc[3, "Timestamp"] = fmt(local)                   # ended before the second MAC appeared
    check("but not on a flow that ended before the spoofing began",
          not ps.attach(before, hits, inspector.first_time, set(), [])[0][3])
    check("port 443 flow marked encrypted, port 80 flows not", encrypted == [False, False, True, False])
    check("no hit left unattached", unattached == [])
    check("attached hits carry no internal fields", all(not k.startswith("_") for h in per_row[1] for k in h))

    print("\n4. Suricata")
    mapping = rs.load_config()["suricata"]["class_mapping"]
    cases = [("ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT", "Web Application Attack", "WebBased"),
             ("ET EXPLOIT Apache Struts RCE", "Attempted Administrator Privilege Gain", "Exploitation"),
             ("ET SHELLCODE x86 NOOP", "Executable code was detected", "BufferOverflow"),
             ("ET SCAN Potential SSH Scan", "Attempted Information Leak", "PortScan"),
             ("ET SCAN SSH BruteForce Tool", "Attempted Information Leak", "Bruteforce"),
             ("ET DOS Slowloris HTTP Attack", "Attempted Denial of Service", "Slowloris"),
             ("SURICATA FRAG IPv4 Fragmentation overlap", "Generic Protocol Command Decode", "Evasion"),
             ("ET INFO Session Traversal Utilities", "Misc activity", None)]
    for signature, category, expected in cases:
        check(f"'{signature[:40]}' -> {expected}", ps.map_alert(signature, category, mapping) == expected)
    with tempfile.TemporaryDirectory() as tmp:
        eve = Path(tmp) / "eve.json"
        alert = {"timestamp": "2026-09-26T14:00:00.000000+0800", "event_type": "alert", "proto": "TCP",
                 "src_ip": A, "src_port": 40000, "dest_ip": S, "dest_port": 80,
                 "alert": {"signature_id": 2006445, "severity": 1, "category": "Web Application Attack",
                           "signature": "ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM"}}
        eve.write_text("\n".join([json.dumps(alert)] * 2 + [json.dumps({"event_type": "http"})]), encoding="utf-8")
        status = {"alerts": 0, "mapped": 0}
        hits = ps.parse_eve(eve, rs.load_config()["suricata"], status)
        check("two identical alerts on one flow become one hit counted twice",
              len(hits) == 1 and hits[0]["measured"] == 2 and hits[0]["class"] == "WebBased")
        check("evidence names the signature id", "2006445" in hits[0]["evidence"])
        check("eve timestamp with +0800 parsed", hits[0]["_flows"][0][1] == 1790402400.0)
        offload = dict(alert, alert=dict(alert["alert"], signature_id=2200074,
                                         signature="SURICATA TCPv4 invalid checksum"))
        eve.write_text(json.dumps(offload), encoding="utf-8")
        status = {"alerts": 0, "mapped": 0}
        check("checksum-offload alerts are ignored, and counted",
              ps.parse_eve(eve, rs.load_config()["suricata"], status) == [] and status["ignored"] == 1)
    missing = ps.run_suricata(Path("x.pcap"), Path(tempfile.gettempdir()) / "fx_suri",
                              {"suricata": {"enabled": True, "binary": "Z:/none/suricata.exe"}})
    check("missing Suricata is reported, not raised",
          missing[0] == [] and missing[1]["ran"] is False and "reason" in missing[1])

    print("\n5. decide()")
    cfg = rs.load_config()
    h = lambda c: [{"class": c}]
    f = lambda c, ab=False: {"predicted_class": c, "abstained": ab}
    check("same class -> agree", rs.decide(f("DoS"), h("DoS"), cfg) == ("DoS", "agree"))
    check("trusted rule overrides the model -> rule", rs.decide(f("Benign"), h("PortScan"), cfg) == ("PortScan", "rule"))
    check("untrusted rule, model confident -> model class, conflict",
          rs.decide(f("Benign"), h("WebBased"), cfg) == ("Benign", "conflict"))
    check("no rule, model confident -> ml", rs.decide(f("DoS"), [], cfg) == ("DoS", "ml"))
    check("model abstained, rule fired -> rule", rs.decide(f("DoS", True), h("WebBased"), cfg) == ("WebBased", "rule"))
    check("model abstained, no rule -> Uncertain", rs.decide(f("DoS", True), [], cfg) == ("Uncertain", "abstain"))
    check("rules not evaluated behaves as no rule", rs.decide(f("DoS"), None, cfg) == ("DoS", "ml"))

    print(f"\n{'ALL CHECKS PASSED' if not FAILED else f'{len(FAILED)} FAILED: {FAILED}'}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
