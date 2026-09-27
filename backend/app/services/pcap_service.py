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
from scapy.layers.l2 import Dot1Q
from scapy.layers.dns import DNS
from scapy.packet import Padding
from scapy.layers.inet import IPerror, TCPerror, UDPerror


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
ICMP_TYPES = {0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect",
              8: "Echo (ping) request", 11: "Time-to-live exceeded", 12: "Parameter problem",
              13: "Timestamp request", 14: "Timestamp reply"}
# Code names as Wireshark shows them (RFC 792, RFC 1812).
ICMP_CODES = {
    3: {0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable", 3: "Port unreachable",
        4: "Fragmentation needed", 5: "Source route failed", 6: "Destination network unknown",
        7: "Destination host unknown", 9: "Network administratively prohibited",
        10: "Host administratively prohibited", 13: "Communication administratively filtered"},
    5: {0: "Redirect for network", 1: "Redirect for host"},
    11: {0: "Time to live exceeded in transit", 1: "Fragment reassembly time exceeded"},
}
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


ETHER_TYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN", 0x88CC: "LLDP", 0x8863: "PPPoE-D",
               0x8864: "PPPoE-S", 0x888E: "EAPOL"}


def header_fields(packet) -> dict:
    """Every header field the frame carries, as Wireshark's packet details
    show them. A field a packet does not have is None, so the Dashboard can
    hide columns that are empty for the whole capture."""
    f = {
        "captured_length": int(len(packet)),
        "wire_length": int(getattr(packet, "wirelen", None) or len(packet)),
        "interface": str(getattr(packet, "sniffed_on", "") or "") or None,
        "comment": (packet.comment.decode(errors="replace") if isinstance(getattr(packet, "comment", None), bytes)
                    else getattr(packet, "comment", None)) or None,
        "src_mac": None, "dst_mac": None, "ether_type": None, "vlan": None,
        "ip_version": None, "ttl": None, "ip_id": None, "ip_flags": None, "fragment_offset": None,
        "dscp": None, "ecn": None, "ip_header_length": None, "ip_total_length": None,
        "tcp_seq": None, "tcp_ack": None, "tcp_window": None, "tcp_header_length": None, "tcp_options": None,
        "udp_length": None, "icmp_type": None, "icmp_code": None, "payload_length": None,
    }
    if Ether in packet:
        eth = packet[Ether]
        f["src_mac"], f["dst_mac"] = str(eth.src), str(eth.dst)
        f["ether_type"] = ETHER_TYPES.get(int(eth.type), f"0x{int(eth.type):04x}")
    if Dot1Q in packet:
        f["vlan"] = int(packet[Dot1Q].vlan)
    if IP in packet:
        ip = packet[IP]
        f.update(ip_version=4, ttl=int(ip.ttl), ip_id=int(ip.id), ip_flags=str(ip.flags) or None,
                 fragment_offset=int(ip.frag), dscp=int(ip.tos) >> 2, ecn=int(ip.tos) & 3,
                 ip_header_length=int(ip.ihl or 5) * 4, ip_total_length=int(ip.len) if ip.len is not None else None)
    elif IPv6 in packet:
        ip6 = packet[IPv6]
        f.update(ip_version=6, ttl=int(ip6.hlim), dscp=int(ip6.tc) >> 2, ecn=int(ip6.tc) & 3,
                 ip_header_length=40, ip_total_length=40 + int(ip6.plen or 0))
    if TCP in packet:
        tcp = packet[TCP]
        f.update(tcp_seq=int(tcp.seq), tcp_ack=int(tcp.ack), tcp_window=int(tcp.window),
                 tcp_header_length=int(tcp.dataofs or 5) * 4, payload_length=len(_l4_payload(tcp)))
        options = []
        for name, value in tcp.options or []:
            options.append(f"{name}={value}" if name in ("MSS", "WScale") else name)
        f["tcp_options"] = ", ".join(options) or None
    elif UDP in packet:
        f.update(udp_length=int(packet[UDP].len) if packet[UDP].len is not None else None,
                 payload_length=len(_l4_payload(packet[UDP])))
    if ICMP in packet:
        f.update(icmp_type=int(packet[ICMP].type), icmp_code=int(packet[ICMP].code))
    return f


def _quoted(packet) -> str:
    """The packet an ICMP error refers to (it carries that packet's IP
    header and first 8 bytes), e.g. ' for TCP 10.0.0.1:4242 > 10.0.0.2:80'."""
    if IPerror not in packet:
        return ""
    inner = packet[IPerror]
    for layer, name in ((TCPerror, "TCP"), (UDPerror, "UDP")):
        if layer in packet:
            q = packet[layer]
            return f" for {name} {inner.src}:{int(q.sport)} > {inner.dst}:{int(q.dport)}"
    return f" for IP protocol {int(inner.proto)} {inner.src} > {inner.dst}"


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
        if int(icmp.type) in (0, 8):
            return "ICMP", kind + f" id=0x{int(icmp.id):04x} seq={int(icmp.seq)}"
        code = ICMP_CODES.get(int(icmp.type), {}).get(int(icmp.code), f"code {int(icmp.code)}")
        return "ICMP", f"{kind} ({code})" + _quoted(packet)
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
                    "info": info,
                    **header_fields(packet)
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
                    info,

                **header_fields(packet)
            }


            packets_data.append(
                packet_data
            )


    return packets_data
