from statistics import mean


def _create_flow_key(
    packet: dict
) -> tuple:

    source = (
        packet["source_ip"],
        packet["source_port"]
    )

    destination = (
        packet["destination_ip"],
        packet["destination_port"]
    )

    protocol = packet[
        "protocol_number"
    ]

    # Normalize both directions into
    # one bidirectional flow.
    if source <= destination:

        return (
            source,
            destination,
            protocol
        )

    return (
        destination,
        source,
        protocol
    )


def build_flows(
    packets: list[dict]
) -> list[dict]:

    flow_table = {}


    # =====================================
    # BUILD INTERNAL FLOW TABLE
    # =====================================

    for packet in packets:

        # Ignore traffic without ports
        # for this first version.
        if (
            packet["source_port"] is None
            or
            packet["destination_port"] is None
        ):
            continue


        flow_key = _create_flow_key(
            packet
        )


        # ---------------------------------
        # New flow
        # ---------------------------------

        if flow_key not in flow_table:

            flow_table[flow_key] = {

                "source_ip":
                    packet["source_ip"],

                "destination_ip":
                    packet["destination_ip"],

                "source_port":
                    packet["source_port"],

                "destination_port":
                    packet["destination_port"],

                "protocol":
                    packet["protocol"],

                "protocol_number":
                    packet[
                        "protocol_number"
                    ],

                "start_time":
                    packet["timestamp"],

                "end_time":
                    packet["timestamp"],

                "forward_packets":
                    0,

                "backward_packets":
                    0,

                "forward_bytes":
                    0,

                "backward_bytes":
                    0,

                "packet_lengths":
                    [],

                "syn_count":
                    0,

                "ack_count":
                    0,

                "fin_count":
                    0,

                "rst_count":
                    0,

                "psh_count":
                    0
            }


        flow = flow_table[
            flow_key
        ]


        # ---------------------------------
        # Update timestamps
        # ---------------------------------

        flow["start_time"] = min(
            flow["start_time"],
            packet["timestamp"]
        )

        flow["end_time"] = max(
            flow["end_time"],
            packet["timestamp"]
        )


        # ---------------------------------
        # Determine direction
        # ---------------------------------

        is_forward = (

            packet["source_ip"]
            ==
            flow["source_ip"]

            and

            packet["source_port"]
            ==
            flow["source_port"]

            and

            packet["destination_ip"]
            ==
            flow["destination_ip"]

            and

            packet["destination_port"]
            ==
            flow["destination_port"]
        )


        if is_forward:

            flow[
                "forward_packets"
            ] += 1

            flow[
                "forward_bytes"
            ] += packet[
                "packet_length"
            ]

        else:

            flow[
                "backward_packets"
            ] += 1

            flow[
                "backward_bytes"
            ] += packet[
                "packet_length"
            ]


        # ---------------------------------
        # Packet lengths
        # ---------------------------------

        flow[
            "packet_lengths"
        ].append(
            packet[
                "packet_length"
            ]
        )


        # ---------------------------------
        # TCP flags
        # ---------------------------------

        flags = packet.get(
            "tcp_flags",
            ""
        )


        if "S" in flags:
            flow["syn_count"] += 1

        if "A" in flags:
            flow["ack_count"] += 1

        if "F" in flags:
            flow["fin_count"] += 1

        if "R" in flags:
            flow["rst_count"] += 1

        if "P" in flags:
            flow["psh_count"] += 1


    # =====================================
    # CONVERT INTO FORENXAI FEATURES
    # =====================================

    extracted_flows = []

    flow_number = 0


    for flow in flow_table.values():

        flow_number += 1


        duration_seconds = (
            flow["end_time"]
            -
            flow["start_time"]
        )


        # CIC-style duration is commonly
        # represented in microseconds.
        flow_duration = int(
            duration_seconds
            * 1_000_000
        )


        total_packets = (

            flow[
                "forward_packets"
            ]

            +

            flow[
                "backward_packets"
            ]
        )


        total_bytes = (

            flow[
                "forward_bytes"
            ]

            +

            flow[
                "backward_bytes"
            ]
        )


        # Prevent division by zero.
        if duration_seconds > 0:

            flow_bytes_per_second = (
                total_bytes
                /
                duration_seconds
            )

            flow_packets_per_second = (
                total_packets
                /
                duration_seconds
            )

        else:

            flow_bytes_per_second = 0.0
            flow_packets_per_second = 0.0


        packet_lengths = flow[
            "packet_lengths"
        ]


        if packet_lengths:

            packet_length_mean = float(
                mean(
                    packet_lengths
                )
            )

            packet_length_min = int(
                min(
                    packet_lengths
                )
            )

            packet_length_max = int(
                max(
                    packet_lengths
                )
            )

        else:

            packet_length_mean = 0.0
            packet_length_min = 0
            packet_length_max = 0


        result = {

            "flow_id":
                flow_number,

            "source_ip":
                flow["source_ip"],

            "source_port":
                flow["source_port"],

            "destination_ip":
                flow[
                    "destination_ip"
                ],

            "destination_port":
                flow[
                    "destination_port"
                ],

            "protocol":
                flow["protocol"],

            "protocol_number":
                flow[
                    "protocol_number"
                ],

            "flow_duration":
                flow_duration,

            "total_forward_packets":
                flow[
                    "forward_packets"
                ],

            "total_backward_packets":
                flow[
                    "backward_packets"
                ],

            "total_forward_bytes":
                flow[
                    "forward_bytes"
                ],

            "total_backward_bytes":
                flow[
                    "backward_bytes"
                ],

            "flow_bytes_per_second":
                flow_bytes_per_second,

            "flow_packets_per_second":
                flow_packets_per_second,

            "packet_length_mean":
                packet_length_mean,

            "packet_length_min":
                packet_length_min,

            "packet_length_max":
                packet_length_max,

            "syn_flag_count":
                flow["syn_count"],

            "ack_flag_count":
                flow["ack_count"],

            "fin_flag_count":
                flow["fin_count"],

            "rst_flag_count":
                flow["rst_count"],

            "psh_flag_count":
                flow["psh_count"],

            "total_packets":
                total_packets,

            "total_bytes":
                total_bytes
        }


        extracted_flows.append(
            result
        )


    return extracted_flows