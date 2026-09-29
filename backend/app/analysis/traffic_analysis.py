from collections import Counter


def build_traffic_summary(
    packets: list[dict]
) -> dict:

    total_packets = len(packets)

    total_bytes = sum(
        packet["packet_length"]
        for packet in packets
    )

    protocol_counter = Counter(
        packet["protocol"]
        for packet in packets
    )

    # Non-IP frames (ARP and other link-layer packets) are kept in the
    # packet list for the Investigation view, with MAC addresses in their
    # address fields and protocol_number 0. The top-IP lists count IP
    # packets only.
    ip_packets = [
        packet
        for packet in packets
        if packet.get("protocol_number")
    ]

    source_counter = Counter(
        packet["source_ip"]
        for packet in ip_packets
        if packet["source_ip"]
    )

    destination_counter = Counter(
        packet["destination_ip"]
        for packet in ip_packets
        if packet["destination_ip"]
    )

    return {

        "total_packets":
            total_packets,

        "total_bytes":
            total_bytes,

        "protocols":
            dict(protocol_counter),

        "top_source_ips":
            source_counter.most_common(5),

        "top_destination_ips":
            destination_counter.most_common(5)
    }