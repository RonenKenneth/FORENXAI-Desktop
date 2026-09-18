from pathlib import Path
import json

from app.services.review_service import (
    load_investigator_reviews
)


def build_case_report(
    case_directory: Path
) -> dict:
    """
    Build a structured forensic report object
    from an existing FORENXAI case.
    """

    if not case_directory.exists():
        raise FileNotFoundError(
            f"Case directory does not exist: "
            f"{case_directory}"
        )


    analysis_file = (
        case_directory
        / "analysis.json"
    )


    if not analysis_file.exists():
        raise FileNotFoundError(
            "analysis.json was not found "
            "for this case."
        )


    if analysis_file.stat().st_size == 0:
        raise ValueError(
            "analysis.json is empty."
        )


    # ========================================================
    # LOAD ANALYSIS
    # ========================================================

    try:

        with analysis_file.open(
            "r",
            encoding="utf-8"
        ) as file:

            analysis_data = (
                json.load(
                    file
                )
            )

    except json.JSONDecodeError as error:

        raise ValueError(
            "analysis.json contains invalid JSON: "
            f"{error}"
        )


    # ========================================================
    # LOAD REVIEWS
    # ========================================================

    reviews = (
        load_investigator_reviews(
            case_directory
        )
    )


    # ========================================================
    # BASIC CASE INFORMATION
    # ========================================================

    case_id = (
        analysis_data.get(
            "case_id",
            ""
        )
    )


    file_name = (
        analysis_data.get(
            "file_name",
            ""
        )
    )


    sha256_value = (
        analysis_data.get(
            "sha256",
            ""
        )
    )


    file_size = (
        analysis_data.get(
            "file_size",
            0
        )
    )


    # ========================================================
    # TRAFFIC INFORMATION
    # ========================================================

    traffic_summary = (
        analysis_data.get(
            "traffic_summary",
            {}
        )
    )


    flow_summary = (
        analysis_data.get(
            "flow_summary",
            {}
        )
    )


    # ========================================================
    # ML INFORMATION
    # ========================================================

    ml_analysis = (
        analysis_data.get(
            "ml_analysis",
            {}
        )
    )


    ml_summary = (
        ml_analysis.get(
            "summary",
            {}
        )
    )


    findings = (
        ml_analysis.get(
            "findings",
            []
        )
    )


    if not isinstance(
        findings,
        list
    ):
        raise ValueError(
            "ML findings are not "
            "in the expected list format."
        )


    # ========================================================
    # SHAP INFORMATION
    # ========================================================

    shap_analysis = (
        analysis_data.get(
            "shap_analysis",
            {}
        )
    )


    shap_explanations = (
        shap_analysis.get(
            "explanations",
            []
        )
    )


    if not isinstance(
        shap_explanations,
        list
    ):
        raise ValueError(
            "SHAP explanations are not "
            "in the expected list format."
        )


    # ========================================================
    # BUILD REVIEW LOOKUP
    # ========================================================

    review_lookup = {

        review.get(
            "flow_index"
        ):
            review

        for review in reviews

        if isinstance(
            review,
            dict
        )
    }


    # ========================================================
    # BUILD SHAP LOOKUP
    # ========================================================

    shap_lookup = {

        explanation.get(
            "flow_index"
        ):
            explanation

        for explanation
        in shap_explanations

        if isinstance(
            explanation,
            dict
        )
    }


    # ========================================================
    # BUILD THREAT FINDINGS SECTION
    # ========================================================

    threat_findings = []


    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue


        if not finding.get(
            "is_threat",
            False
        ):
            continue


        flow_index = (
            finding.get(
                "flow_index"
            )
        )


        report_finding = {

            "flow_index":
                flow_index,

            "predicted_class":
                finding.get(
                    "predicted_class",
                    ""
                ),

            "confidence":
                finding.get(
                    "confidence",
                    0.0
                ),

            "metadata":
                finding.get(
                    "metadata",
                    {}
                ),

            "recommendation":
                finding.get(
                    "recommendation"
                ),

            "shap_explanation":
                shap_lookup.get(
                    flow_index
                ),

            "investigator_review":
                review_lookup.get(
                    flow_index
                )
        }


        threat_findings.append(
            report_finding
        )


    # ========================================================
    # REVIEW SUMMARY
    # ========================================================

    review_summary = {

        "total_reviews":
            len(reviews),

        "confirmed":
            0,

        "rejected":
            0,

        "inconclusive":
            0
    }


    for review in reviews:

        decision = (
            review.get(
                "decision",
                ""
            )
        )


        if decision == "Confirmed":
            review_summary[
                "confirmed"
            ] += 1

        elif decision == "Rejected":
            review_summary[
                "rejected"
            ] += 1

        elif decision == "Inconclusive":
            review_summary[
                "inconclusive"
            ] += 1


    # ========================================================
    # FINAL REPORT OBJECT
    # ========================================================

    report = {

        "report_type":
            "FORENXAI Forensic Analysis Report",

        "case": {

            "case_id":
                case_id,

            "evidence_file":
                file_name,

            "sha256":
                sha256_value,

            "file_size":
                file_size
        },


        "traffic_summary":
            traffic_summary,


        "flow_summary":
            flow_summary,


        "ml_summary":
            ml_summary,


        "review_summary":
            review_summary,


        "threat_findings":
            threat_findings,


        "investigator_reviews":
            reviews
    }


    return report