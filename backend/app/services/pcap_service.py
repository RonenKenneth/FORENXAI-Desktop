from pathlib import Path

from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    PcapReader,
    PcapNgReader,
    Ether,
    ARP
)
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.packet import Padding


# ============================================================
# WIRESHARK-STYLE PROTOCOL AND INFO
#
# "protocol" stays the transport (TCP / UDP / ICMP / ARP / OTHER):
# flows and rules key on it. "display_protocol" is the highest layer
# recognised in the packet and "info" a one-line summary of its
# contents, as in Wireshark's packet list.
# ============================================================

TCP_FLAG_NAMES = [("S", "SYN"), ("A", "ACK"), ("F", "FIN"), ("R", "RST"),
                  ("P", "PSH"), ("U", "URG"), ("E", "ECE"), ("C", "CWR")]
TLS_RECORDS = {0x14: "Change Cipher Spec", 0x15: "Alert", 0x16: "Handshake", 0x17: "Application Data"}
TLS_HANDSHAKES = {1: "Client Hello", 2: "Server Hello", 11: "Certificate", 12: "Server Key Exchange",
                  14: "Server Hello Done", 16: "Client Key Exchange", 20: "Finished"}
ICMP_TYPES = {0: "Echo (ping) reply", 3: "Destination unreachable", 5: "Redirect",
              8: "Echo (ping) request", 11: "Time-to-live exceeded"}
DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
# Well-known services, named by port when no content is recognised (as
# Wireshark's port heuristics do).
PORT_NAMES = {137: "NBNS", 138: "NBDS", 5353: "MDNS", 5355: "LLMNR", 1900: "SSDP",
              123: "NTP", 161: "SNMP", 514: "Syslog", 69: "TFTP", 3702: "WS-Discovery"}
# IP protocols other than TCP/UDP/ICMP. ESP and AH are IPsec: encrypted
# or authenticated traffic whose content cannot be inspected.
IP_PROTOCOLS = {2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"HTTP/1.")


def _l4_payload(layer) -> bytes:
    """Application bytes, without the Ethernet pad scapy files under L4."""
    data = bytes(layer.payload)
    pad = layer.getlayer(Padding)
    return data[: len(data) - len(bytes(pad))] if pad is not None else data


def _flag_names(flags: str) -> str:
    return ", ".join(name for letter, name in TCP_FLAG_NAMES if letter in flags)


def _dns_info(dns) -> str:
    name = dns.qd.qname.decode(errors="replace").rstrip(".") if dns.qd is not None else ""
    qtype = DNS_QTYPES.get(int(dns.qd.qtype), str(dns.qd.qtype)) if dns.qd is not None else ""
    if dns.qr == 0:
        return f"Standard query 0x{int(dns.id):04x} {qtype} {name}".strip()
    return f"Standard query response 0x{int(dns.id):04x} {qtype} {name} ({int(dns.ancount)} answers)".strip()


def _app_layer(payload: bytes, sport: int, dport: int):
    """(protocol, info) for recognisable application data, else None."""
    if len(payload) > 5 and payload[0] in TLS_RECORDS and payload[1] == 3:
        record = TLS_RECORDS[payload[0]]
        if payload[0] == 0x16 and len(payload) > 5:
            record = TLS_HANDSHAKES.get(payload[5], "Handshake")
        return "TLS", record
    if payload.startswith(b"SSH-"):
        return "SSH", payload.split(b"\r\n")[0].decode(errors="replace")[:60]
    if payload.startswith(HTTP_METHODS):
        return "HTTP", payload.split(b"\r\n")[0].decode(errors="replace")[:80]
    return None


def describe(packet, transport: str, sport, dport, tcp_flags: str):
    """Wireshark-style (display_protocol, info) for one packet."""
    if ARP in packet:
        arp = packet[ARP]
        if int(arp.op) == 1:
            return "ARP", f"Who has {arp.pdst}? Tell {arp.psrc}"
        if int(arp.op) == 2:
            return "ARP", f"{arp.psrc} is at {arp.hwsrc}"
        return "ARP", f"ARP op {int(arp.op)}"
    if ICMP in packet:
        icmp = packet[ICMP]
        kind = ICMP_TYPES.get(int(icmp.type), f"Type {int(icmp.type)}")
        extra = f" id=0x{int(icmp.id):04x} seq={int(icmp.seq)}" if int(icmp.type) in (0, 8) else f" (code {int(icmp.code)})"
        return "ICMP", kind + extra
    if IPv6 in packet and "ICMPv6" in type(packet.lastlayer()).__name__:
        return "ICMPv6", packet.lastlayer().name
    if DHCP in packet:
        kind = ""
        for option in packet[DHCP].options:
            if isinstance(option, tuple) and option[0] == "message-type":
                kind = DHCP_TYPES.get(option[1], str(option[1]))
        return "DHCP", f"DHCP {kind}".strip()
    if DNS in packet:
        try:
            return "DNS", _dns_info(packet[DNS])
        except Exception:  # noqa: BLE001 -- malformed DNS still gets a row
            return "DNS", "DNS (malformed)"
    if TCP in packet:
        tcp = packet[TCP]
        payload = _l4_payload(tcp)
        app = _app_layer(payload, sport, dport)
        if app:
            return app
        return "TCP", (f"{sport} → {dport} [{_flag_names(tcp_flags)}] Seq={int(tcp.seq)} "
                       f"Ack={int(tcp.ack)} Win={int(tcp.window)} Len={len(payload)}")
    if UDP in packet:
        payload = _l4_payload(packet[UDP])
        app = _app_layer(payload, sport, dport)
        if app:
            return app
        service = PORT_NAMES.get(dport) or PORT_NAMES.get(sport)
        return service or "UDP", f"{sport} → {dport} Len={len(payload)}"
    if IP in packet or IPv6 in packet:
        number = int(packet[IP].proto) if IP in packet else int(packet[IPv6].nh)
        name = IP_PROTOCOLS.get(number, f"IP proto {number}")
        return name, f"{name} (IP protocol {number})"
    last = packet.lastlayer()
    return last.name if last is not None else "OTHER", packet.summary()


def extract_packets(
    pcap_path: Path,
    on_packet=None
) -> list[dict]:
    """IP packets as dicts. on_packet, when given, sees every packet
    (ARP included) in the same pass -- the Tier 2 packet rules use it."""

    if not pcap_path.exists():
        raise FileNotFoundError(
            f"PCAP file does not exist: {pcap_path}"
        )

    packets_data = []

    packet_number = 0

    # PCAPNG requires Scapy's native reader.  PcapReader may open the file
    # without raising, but yield no packets for some PCAPNG captures.
    reader_type = PcapNgReader if pcap_path.suffix.lower() == ".pcapng" else PcapReader
    with reader_type(str(pcap_path)) as reader:

        for packet in reader:

            packet_number += 1

            if on_packet is not None:
                on_packet(packet)

            source_ip = None
            destination_ip = None
            protocol_number = 0

            # -----------------------------
            # IPv4
            # -----------------------------

            if IP in packet:

                source_ip = str(
                    packet[IP].src
                )

                destination_ip = str(
                    packet[IP].dst
                )

                protocol_number = int(
                    packet[IP].proto
                )

            # -----------------------------
            # IPv6
            # -----------------------------

            elif IPv6 in packet:

                source_ip = str(
                    packet[IPv6].src
                )

                destination_ip = str(
                    packet[IPv6].dst
                )

                protocol_number = int(
                    packet[IPv6].nh
                )

            else:
                # Keep link-layer packets (for example ARP) in the packet
                # list used by Investigation. They are not IP flows, so
                # flow_service will ignore them because they have no ports.
                if Ether in packet:
                    source_ip = str(packet[Ether].src)
                    destination_ip = str(packet[Ether].dst)
                protocol = "ARP" if ARP in packet else "OTHER"
                display_protocol, info = describe(packet, protocol, None, None, "")
                packet_data = {
                    "packet_number": int(packet_number),
                    "timestamp": float(packet.time),
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "protocol": protocol,
                    "protocol_number": 0,
                    "source_port": None,
                    "destination_port": None,
                    "packet_length": int(len(packet)),
                    "tcp_flags": "",
                    "display_protocol": display_protocol,
                    "info": info
                }
                packets_data.append(packet_data)
                continue


            protocol = "OTHER"

            source_port = None
            destination_port = None

            tcp_flags = ""


            # -----------------------------
            # TCP
            # -----------------------------

            if TCP in packet:

                protocol = "TCP"

                protocol_number = 6

                source_port = int(
                    packet[TCP].sport
                )

                destination_port = int(
                    packet[TCP].dport
                )

                tcp_flags = str(
                    packet[TCP].flags
                )


            # -----------------------------
            # UDP
            # -----------------------------

            elif ICMP in packet:

                protocol = "ICMP"

            elif UDP in packet:

                protocol = "UDP"

                protocol_number = 17

                source_port = int(
                    packet[UDP].sport
                )

                destination_port = int(
                    packet[UDP].dport
                )


            display_protocol, info = describe(packet, protocol, source_port, destination_port, tcp_flags)

            packet_data = {

                "packet_number":
                    int(packet_number),

                "timestamp":
                    float(packet.time),

                "source_ip":
                    source_ip,

                "destination_ip":
                    destination_ip,

                "protocol":
                    protocol,

                "protocol_number":
                    protocol_number,

                "source_port":
                    source_port,

                "destination_port":
                    destination_port,

                "packet_length":
                    int(len(packet)),

                "tcp_flags":
                    tcp_flags,

                "display_protocol":
                    display_protocol,

                "info":
                    info
            }


            packets_data.append(
                packet_data
            )


    return packets_data
