from pathlib import Path

from app.services.model_service import (
    classify_flow_csv
)


CSV_PATH = Path(
    r"C:\Tools\CICFlowMeter"
    r"\CICFlowMeter-master"
    r"\data"
    r"\out"
    r"\testtest.pcap_Flow.csv"
)


print(
    "\n=============================="
)

print(
    "FORENXAI MODEL SERVICE TEST"
)

print(
    "=============================="
)


result = classify_flow_csv(
    CSV_PATH
)


summary = result[
    "summary"
]


print(
    "\nSUMMARY"
)

print(
    "------------------------------"
)


print(
    f"Total flows: "
    f"{summary['total_flows']}"
)

print(
    f"Benign flows: "
    f"{summary['benign_flows']}"
)

print(
    f"Threat flows: "
    f"{summary['threat_flows']}"
)

print(
    f"Threat percentage: "
    f"{summary['threat_percentage']}%"
)


print(
    "\nCLASS COUNTS"
)

print(
    "------------------------------"
)


for class_name, count in (
    summary[
        "class_counts"
    ].items()
):

    print(
        f"{class_name}: "
        f"{count}"
    )


print(
    "\nFIRST 5 FINDINGS"
)

print(
    "------------------------------"
)


for finding in result[
    "findings"
][:5]:

    print(
        f"Flow "
        f"{finding['flow_index'] + 1}: "
        f"{finding['predicted_class']} "
        f"confidence="
        f"{finding['confidence']:.4f}"
    )

    print(
        f"  Metadata: "
        f"{finding['metadata']}"
    )


print(
    "\n=============================="
)

print(
    "MODEL SERVICE TEST COMPLETE"
)

print(
    "=============================="
)