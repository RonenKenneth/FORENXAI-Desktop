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

    source_counter = Counter(
        packet["source_ip"]
        for packet in packets
        if packet["source_ip"]
    )

    destination_counter = Counter(
        packet["destination_ip"]
        for packet in packets
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