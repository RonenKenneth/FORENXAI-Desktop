from pathlib import Path

from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    PcapReader
)


def extract_packets(
    pcap_path: Path
) -> list[dict]:

    if not pcap_path.exists():
        raise FileNotFoundError(
            f"PCAP file does not exist: {pcap_path}"
        )

    packets_data = []

    packet_number = 0

    with PcapReader(str(pcap_path)) as reader:

        for packet in reader:

            packet_number += 1

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

            elif UDP in packet:

                protocol = "UDP"

                protocol_number = 17

                source_port = int(
                    packet[UDP].sport
                )

                destination_port = int(
                    packet[UDP].dport
                )


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
                    tcp_flags
            }


            packets_data.append(
                packet_data
            )


    return packets_data