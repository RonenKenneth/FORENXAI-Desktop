"""
Packet parsing checks: Wireshark-style protocol and info, Ethernet padding
is not payload, and a flow is "encrypted" only on evidence.

Run: .venv\\Scripts\\python.exe test_packet_parsing.py
"""

import subprocess
import sys

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Padding, Raw

from app.services.packet_rule_service import PacketInspector, _l4_payload
from app.services.pcap_service import describe

# Ethernet pads a 54-byte SYN to 60 bytes; scapy files the pad under TCP.
syn = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=443, flags="S") / Padding(load=b"\x00" * 6)
assert _l4_payload(syn[TCP]) == b"", "padding counted as payload"

tls = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5001, dport=443, flags="PA")
       / Raw(load=bytes([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0])))
assert describe(tls, "TCP", 5001, 443, "PA") == ("TLS", "Client Hello")

arp = Ether() / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2")
assert describe(arp, "ARP", None, None, "") == ("ARP", "Who has 10.0.0.2? Tell 10.0.0.1")

dns = Ether() / IP() / UDP(sport=5353, dport=53) / DNS(id=7, qd=DNSQR(qname="example.com"))
assert describe(dns, "UDP", 5353, 53, "")[0] == "DNS"

ping = Ether() / IP() / ICMP(type=8, id=1, seq=2)
assert describe(ping, "ICMP", None, None, "")[1].startswith("Echo (ping) request")

tcp = describe(syn, "TCP", 5000, 443, "S")
assert tcp[0] == "TCP" and "[SYN]" in tcp[1] and "Len=0" in tcp[1]

# A bare probe to port 443 is not encrypted traffic; a TLS record is.
inspector = PacketInspector()
inspector.add(syn)
inspector.add(tls)
assert any(5001 in (k[2], k[4]) for k in inspector.encrypted_keys), "TLS flow not marked encrypted"
assert not any(5000 in (k[2], k[4]) for k in inspector.encrypted_keys), "empty 443 probe marked encrypted"

# packet store self-check (connection totals, filters, paging)
result = subprocess.run([sys.executable, "-m", "app.services.packet_store"], capture_output=True, text=True)
assert result.returncode == 0, result.stdout + result.stderr

print("ALL CHECKS PASSED")
