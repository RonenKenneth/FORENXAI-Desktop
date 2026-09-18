from pathlib import Path

import pandas as pd

from app.services.shap_service import (
    explain_flow_dataframe
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
    "FORENXAI SHAP SERVICE TEST"
)

print(
    "=============================="
)


df = pd.read_csv(
    CSV_PATH
)


result = explain_flow_dataframe(
    df,
    top_features=5
)


print(
    f"\nTotal explanations: "
    f"{result['total_flows']}"
)


print(
    "\nFIRST 3 EXPLANATIONS"
)

print(
    "------------------------------"
)


for explanation in (
    result[
        "explanations"
    ][:3]
):

    print(
        f"\nFlow "
        f"{explanation['flow_index'] + 1}"
    )

    print(
        f"Prediction: "
        f"{explanation['predicted_class']}"
    )

    print(
        f"Confidence: "
        f"{explanation['confidence']:.4f}"
    )

    for contributor in (
        explanation[
            "contributors"
        ]
    ):

        print(
            f"- "
            f"{contributor['feature']}: "
            f"{contributor['shap_value']:.6f} "
            f"("
            f"{contributor['direction']}"
            f")"
        )


print(
    "\n=============================="
)

print(
    "SHAP SERVICE TEST COMPLETE"
)

print(
    "=============================="
)