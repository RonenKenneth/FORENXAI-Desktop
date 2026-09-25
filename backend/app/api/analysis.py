from collections import Counter
from pathlib import Path
from hashlib import sha256
import json
import os
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.pcap_service import extract_packets
from app.services.flow_service import build_flows
from app.services.cicflowmeter_service import generate_flow_csv
from app.services.model_service import classify_flow_csv
from app.services.shap_service import explain_flow_csv
from app.services.rule_service import evaluate as evaluate_rules
from app.services.rule_service import decide, load_config as load_rule_config, sort_hits
from app.services.packet_rule_service import (
    PacketInspector,
    evaluate as evaluate_packet_rules,
)
from app.services.recommendation_service import (
    get_recommendation,
    warm_recommendations,
)

from app.services.narration_service import (
    generate_flow_narration
)

from app.services.review_service import (
    save_investigator_review,
    load_investigator_reviews
)

from app.services.report_service import (
    build_case_report
)

from app.analysis.traffic_analysis import (
    build_traffic_summary
)
from app.utils.runtime_paths import (
    get_backend_directory,
    get_cases_directory,
)


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"]
)


# ============================================================
# REQUEST MODELS
# ============================================================

class AnalysisRequest(BaseModel):
    case_id: str
    file_name: str


class InvestigatorReviewRequest(BaseModel):
    flow_index: int
    decision: str
    notes: str = ""

# ============================================================
# SHA-256
# ============================================================

def summarise_rule_hits(findings, tier):
    """Flows flagged per class and per rule for one tier (a flow counts
    once per class, even when several rules of that class fired)."""
    by_class, by_rule, by_source = Counter(), Counter(), Counter()
    flagged = 0
    for finding in findings:
        hits = [
            h for h in (finding.get("rule_findings") or [])
            if h.get("tier") == tier and h.get("rule_id") != "ALLOWLIST"
        ]
        if not hits:
            continue
        flagged += 1
        by_class.update({h.get("class", "?") for h in hits})
        by_rule.update({h.get("rule_id", "?") for h in hits})
        by_source.update({h.get("source", "flow") for h in hits})
    return {
        "flows_flagged": flagged,
        "by_class": dict(by_class.most_common()),
        "by_rule": dict(by_rule.most_common()),
        "by_source": dict(by_source),
    }


def calculate_sha256(
    file_path: Path
) -> str:

    hasher = sha256()

    with file_path.open(
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            hasher.update(
                chunk
            )

    return hasher.hexdigest().upper()


# ============================================================
# START ANALYSIS
# ============================================================

@router.post("/start")
def start_analysis(
    request: AnalysisRequest
):

    print(
        "\n==============================",
        flush=True
    )

    print(
        "[FORENXAI] ANALYSIS STARTED",
        flush=True
    )

    print(
        f"[FORENXAI] Case ID: "
        f"{request.case_id}",
        flush=True
    )

    print(
        f"[FORENXAI] File: "
        f"{request.file_name}",
        flush=True
    )


    try:

        # =====================================================
        # VALIDATE CASE ID
        # =====================================================

        if not re.fullmatch(
            r"FX-\d{8}-\d{6}",
            request.case_id
        ):

            raise HTTPException(
                status_code=400,
                detail="Invalid case ID."
            )


        # =====================================================
        # SECURE FILENAME
        # =====================================================

        safe_file_name = Path(
            request.file_name
        ).name


        if (
            safe_file_name
            != request.file_name
        ):

            raise HTTPException(
                status_code=400,
                detail="Invalid evidence filename."
            )


        # =====================================================
        # LOCATE BACKEND
        # =====================================================

        backend_directory = (
            get_backend_directory()
        )


        print(
            f"[FORENXAI] Backend: "
            f"{backend_directory}",
            flush=True
        )


        # =====================================================
        # LOCATE CASE
        # =====================================================

        case_directory = (
            get_cases_directory()
            / request.case_id
        )


        evidence_file = (
            case_directory
            / "evidence"
            / safe_file_name
        )


        print(
            f"[FORENXAI] Case directory: "
            f"{case_directory}",
            flush=True
        )


        print(
            f"[FORENXAI] Evidence: "
            f"{evidence_file}",
            flush=True
        )


        if not case_directory.exists():

            raise HTTPException(
                status_code=404,
                detail="Case directory not found."
            )


        if not evidence_file.exists():

            raise HTTPException(
                status_code=404,
                detail="Evidence file not found."
            )


        # =====================================================
        # VALIDATE FILE EXTENSION
        # =====================================================

        if (
            evidence_file
            .suffix
            .lower()
            not in [
                ".pcap",
                ".pcapng"
            ]
        ):

            raise HTTPException(
                status_code=400,
                detail="Unsupported evidence format."
            )


        # =====================================================
        # EVIDENCE HASH / SIZE
        # =====================================================

        print(
            "[FORENXAI] Calculating SHA-256...",
            flush=True
        )


        file_hash = calculate_sha256(
            evidence_file
        )


        file_size = (
            evidence_file
            .stat()
            .st_size
        )


        # =====================================================
        # READ PCAP
        # =====================================================

        print(
            "[FORENXAI] Reading PCAP...",
            flush=True
        )


        # Tier 2 packet rules look at every packet in this same pass, so
        # the capture is read once. A broken rules.json turns them off
        # without stopping the analysis.
        try:
            inspector = PacketInspector()
        except Exception as error:  # noqa: BLE001
            print(
                f"[FORENXAI] Tier 2 packet rules off "
                f"({type(error).__name__}: {error})",
                flush=True
            )
            inspector = None

        packets = extract_packets(
            evidence_file,
            on_packet=(
                inspector.add
                if inspector is not None
                else None
            )
        )


        print(
            f"[FORENXAI] Extracted "
            f"{len(packets)} IP packets.",
            flush=True
        )


        # =====================================================
        # TRAFFIC SUMMARY
        # =====================================================

        print(
            "[FORENXAI] Building "
            "traffic summary...",
            flush=True
        )


        traffic_summary = (
            build_traffic_summary(
                packets
            )
        )


        # =====================================================
        # CUSTOM FORENSIC FLOWS
        # =====================================================

        print(
            "[FORENXAI] Building "
            "network flows...",
            flush=True
        )


        flows = build_flows(
            packets
        )


        print(
            f"[FORENXAI] Extracted "
            f"{len(flows)} flows.",
            flush=True
        )


        # =====================================================
        # CICFLOWMETER EXTRACTION
        # =====================================================

        print(
            "[FORENXAI] Generating "
            "CICFlowMeter features...",
            flush=True
        )


        cicflowmeter_csv = (
            generate_flow_csv(
                evidence_file=evidence_file,
                case_id=request.case_id
            )
        )


        print(
            "[FORENXAI] CICFlowMeter "
            "feature extraction complete.",
            flush=True
        )


        # =====================================================
        # XGBOOST CLASSIFICATION
        # =====================================================

        print(
            "[FORENXAI] Running "
            "XGBoost classification...",
            flush=True
        )


        ml_result = (
            classify_flow_csv(
                cicflowmeter_csv
            )
        )


        ml_summary = (
            ml_result[
                "summary"
            ]
        )


        print(
            f"[FORENXAI] ML flows: "
            f"{ml_summary['total_flows']}",
            flush=True
        )


        print(
            f"[FORENXAI] Benign: "
            f"{ml_summary['benign_flows']}",
            flush=True
        )


        print(
            f"[FORENXAI] Threats: "
            f"{ml_summary['threat_flows']}",
            flush=True
        )


        print(
            "[FORENXAI] ML "
            "classification complete.",
            flush=True
        )


        # =====================================================
        # SHAP EXPLAINABILITY
        # =====================================================

        print(
            "[FORENXAI] Generating "
            "SHAP explanations...",
            flush=True
        )


        shap_result = (
            explain_flow_csv(
                ml_result,
                top_n=10
            )
        )


        print(
            f"[FORENXAI] SHAP explanations: "
            f"{shap_result['total_flows']}",
            flush=True
        )


        print(
            "[FORENXAI] SHAP "
            "explainability complete.",
            flush=True
        )


        # =====================================================
        # RULE-BASED DETECTION
        # =====================================================
        #
        # Runs beside the classifier on the same flows. None means no
        # rule engine is configured yet; the recommendation then says the
        # rule layer was not evaluated, rather than that nothing fired.

        rule_hits = evaluate_rules(
            str(cicflowmeter_csv),
            ml_result.get("findings", [])
        )
        tier1_evaluated = rule_hits is not None

        # Tier 2: the scapy checks gathered while reading the pcap, plus
        # Suricata when it is installed, matched to the same flows.
        tier2_hits, encrypted_flows, tier2_summary = (None, None, {
            "error": "Tier 2 packet rules were not run."
        })
        if inspector is not None:
            tier2_hits, encrypted_flows, tier2_summary = (
                evaluate_packet_rules(
                    evidence_file,
                    str(cicflowmeter_csv),
                    ml_result.get("findings", []),
                    inspector,
                    case_directory
                )
            )

        try:
            rule_config = load_rule_config()
        except Exception:  # noqa: BLE001
            rule_config = {}

        if rule_hits is None and tier2_hits is not None:
            rule_hits = {index: [] for index in tier2_hits}
        if rule_hits is not None and tier2_hits:
            rule_hits = {
                index: sort_hits(
                    hits + tier2_hits.get(index, []),
                    rule_config
                )
                for index, hits in rule_hits.items()
            }


        # =====================================================
        # PHASE 15.3
        # ATTACH RESPONSE RECOMMENDATIONS
        # =====================================================

        print(
            "[FORENXAI] Attaching "
            "response recommendations...",
            flush=True
        )


        ml_findings = (
            ml_result.get(
                "findings",
                []
            )
        )


        if not isinstance(
            ml_findings,
            list
        ):

            raise RuntimeError(
                "ML findings are not "
                "in the expected list format."
            )


        # Generate each distinct recommendation ONCE, before the loop.
        #
        # Every flow that shares a class, a confidence band and the same
        # alternative classes shares an answer, so a capture of two
        # hundred flows is a handful of questions, not two hundred.
        # Doing them here makes the work countable and reportable -- the
        # loop below then costs nothing, instead of the first flow of
        # each class silently blocking for two minutes inside it.
        # SHAP ran above, so each flow's drivers are available here; the
        # rule hits too. Both are attached only for the recommendation
        # stage and removed again below, so analysis.json does not carry
        # a second copy of the SHAP explanations.
        top_features_per_flow = shap_result.get(
            "top_features_per_flow", {}
        )

        for finding in ml_findings:
            if isinstance(finding, dict):
                index = finding.get("flow_index")
                finding["top_features"] = top_features_per_flow.get(
                    str(index)
                )
                finding["rule_findings"] = (
                    None if rule_hits is None
                    else rule_hits.get(index, [])
                )
                finding["payload_encrypted"] = (
                    None if encrypted_flows is None
                    else encrypted_flows.get(index)
                )
                verdict, source = decide(
                    finding,
                    finding["rule_findings"],
                    rule_config or None
                )
                finding["verdict"] = verdict
                finding["verdict_source"] = source

        generated = warm_recommendations(
            ml_findings
        )

        print(
            f"[FORENXAI] {generated} distinct recommendation(s) "
            f"for {len(ml_findings)} flow(s)",
            flush=True
        )


        for finding in ml_findings:

            if not isinstance(
                finding,
                dict
            ):

                raise RuntimeError(
                    "An ML finding is not "
                    "in the expected object format."
                )


            predicted_class = (
                finding.get(
                    "predicted_class"
                )
            )


            if not predicted_class:

                raise RuntimeError(
                    "ML finding is missing "
                    "'predicted_class'."
                )


            # TreeSHAP runs later in the pipeline, so pass whatever
            # drivers the finding already carries. The parameter is
            # optional: the recommendation is grounded in the retrieved
            # documents either way, and SHAP only tells the model which
            # features to mention where a source explains them.
            # The class alone is not the whole prediction. Confidence and
            # the probability distribution decide whether the flow has a
            # live alternative, and an alternative brings its own
            # documents into the retrieval.
            recommendation = (
                get_recommendation(
                    predicted_class,
                    finding.get("top_features"),
                    finding.get("confidence"),
                    finding.get("probabilities"),
                    finding.get("rule_findings"),
                )
            )


            finding[
                "recommendation"
            ] = recommendation

            # Rule hits stay on the finding; SHAP already has its own
            # section in the analysis document.
            finding.pop("top_features", None)


        print(
            f"[FORENXAI] Recommendations "
            f"attached to "
            f"{len(ml_findings)} flows.",
            flush=True
        )


        print(
            "[FORENXAI] Recommendation "
            "mapping complete.",
            flush=True
        )


        # =====================================================
        # CONSTRUCT ANALYSIS JSON
        # =====================================================

        analysis_result = {

            "case_id":
                request.case_id,

            "file_name":
                safe_file_name,

            "sha256":
                file_hash,

            "file_size":
                file_size,


            "traffic_summary":
                traffic_summary,


            "flow_summary": {

                "total_flows":
                    len(flows)

            },


            "flows":
                flows,


            "rule_analysis": {

                "rules_version":
                    rule_config.get("version"),

                "sensitivity":
                    rule_config.get("sensitivity"),

                "tier1_evaluated":
                    tier1_evaluated,

                # Chart data for the Dashboard: flows flagged per
                # class and per rule, for each tier.
                "tier1_chart":
                    summarise_rule_hits(ml_findings, 1),

                "tier2_chart":
                    summarise_rule_hits(ml_findings, 2),

                "tier2":
                    tier2_summary,

                "verdict_sources":
                    dict(Counter(
                        f.get("verdict_source")
                        for f in ml_findings
                        if isinstance(f, dict)
                    )),
            },


            "ml_analysis": {

                "flow_csv":
                    str(
                        cicflowmeter_csv
                    ),

                "summary":
                    ml_result[
                        "summary"
                    ],

                "findings":
                    ml_findings
            },


            "shap_analysis": {

                "total_flows":
                    shap_result[
                        "total_flows"
                    ],

                "top_features_per_flow":
                    shap_result[
                        "top_features_per_flow"
                    ],

                "explanations":
                    shap_result[
                        "explanations"
                    ]
            },


            "packets":
                packets
        }


        # =====================================================
        # WRITE ANALYSIS SAFELY
        # =====================================================

        analysis_file = (
            case_directory
            / "analysis.json"
        )


        temporary_file = (
            case_directory
            / "analysis.tmp"
        )


        print(
            f"[FORENXAI] Writing analysis to: "
            f"{analysis_file}",
            flush=True
        )


        with temporary_file.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                analysis_result,
                file,
                indent=4,
                ensure_ascii=False
            )


        os.replace(
            temporary_file,
            analysis_file
        )


        # =====================================================
        # VERIFY ANALYSIS FILE
        # =====================================================

        if not analysis_file.exists():

            raise RuntimeError(
                "analysis.json was not created."
            )


        json_size = (
            analysis_file
            .stat()
            .st_size
        )


        print(
            f"[FORENXAI] analysis.json size: "
            f"{json_size} bytes",
            flush=True
        )


        if json_size == 0:

            raise RuntimeError(
                "analysis.json was created "
                "but contains 0 bytes."
            )


        print(
            "[FORENXAI] ANALYSIS COMPLETE",
            flush=True
        )


        print(
            "==============================\n",
            flush=True
        )


        # =====================================================
        # RETURN SUMMARY TO FRONTEND
        # =====================================================

        return {

            "status":
                "analysis_complete",

            "case_id":
                request.case_id,

            "file_name":
                safe_file_name,

            "file_size":
                file_size,

            "sha256":
                file_hash,

            "total_packets":
                traffic_summary[
                    "total_packets"
                ],

            "total_flows":
                len(flows),

            "ml_total_flows":
                ml_summary[
                    "total_flows"
                ],

            "benign_flows":
                ml_summary[
                    "benign_flows"
                ],

            "threat_flows":
                ml_summary[
                    "threat_flows"
                ],

            "threat_percentage":
                ml_summary[
                    "threat_percentage"
                ],

            "class_counts":
                ml_summary[
                    "class_counts"
                ],

            "shap_explanations":
                shap_result[
                    "total_flows"
                ],

            "recommendations":
                len(
                    ml_findings
                ),

            "total_bytes":
                traffic_summary[
                    "total_bytes"
                ],

            "protocols":
                traffic_summary[
                    "protocols"
                ],

            "message":
                (
                    "PCAP analysis, ML "
                    "classification, SHAP "
                    "explainability, and "
                    "response recommendations "
                    "completed successfully."
                )
        }


    except HTTPException:

        raise


    except Exception as error:

        print(
            f"[FORENXAI ERROR] "
            f"{type(error).__name__}: "
            f"{error}",
            flush=True
        )


        raise HTTPException(
            status_code=500,
            detail=(
                f"{type(error).__name__}: "
                f"{error}"
            )
        )


# ============================================================
# PHASE 16
# SAVE INVESTIGATOR REVIEW
# ============================================================

@router.post("/{case_id}/review")
def save_review(
    case_id: str,
    request: InvestigatorReviewRequest
):

    # ========================================================
    # VALIDATE CASE ID
    # ========================================================

    if not re.fullmatch(
        r"FX-\d{8}-\d{6}",
        case_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid case ID."
        )


    # ========================================================
    # VALIDATE FLOW INDEX
    # ========================================================

    if request.flow_index < 0:

        raise HTTPException(
            status_code=400,
            detail="Flow index cannot be negative."
        )


    # ========================================================
    # LOCATE CASE
    # ========================================================

    case_directory = (
        get_cases_directory()
        / case_id
    )


    analysis_file = (
        case_directory
        / "analysis.json"
    )


    if not case_directory.exists():

        raise HTTPException(
            status_code=404,
            detail="Case directory not found."
        )


    if not analysis_file.exists():

        raise HTTPException(
            status_code=404,
            detail="analysis.json not found."
        )


    if analysis_file.stat().st_size == 0:

        raise HTTPException(
            status_code=500,
            detail="analysis.json is empty."
        )


    # ========================================================
    # READ ANALYSIS
    # ========================================================

    try:

        with analysis_file.open(
            "r",
            encoding="utf-8"
        ) as file:

            analysis_data = json.load(
                file
            )


    except json.JSONDecodeError as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "analysis.json contains "
                "invalid JSON: "
                f"{error}"
            )
        )


    # ========================================================
    # FIND ML FINDING
    # ========================================================

    findings = (
        analysis_data
        .get(
            "ml_analysis",
            {}
        )
        .get(
            "findings",
            []
        )
    )


    if not isinstance(
        findings,
        list
    ):

        raise HTTPException(
            status_code=500,
            detail=(
                "ML findings are not "
                "in the expected format."
            )
        )


    selected_finding = None


    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue


        if (
            finding.get(
                "flow_index"
            )
            == request.flow_index
        ):

            selected_finding = (
                finding
            )

            break


    if selected_finding is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"Flow "
                f"{request.flow_index} "
                f"was not found in this case."
            )
        )


    # ========================================================
    # GET PREDICTED CLASS
    # ========================================================

    predicted_class = (
        selected_finding.get(
            "predicted_class"
        )
        or selected_finding.get(
            "prediction"
        )
        or selected_finding.get(
            "class"
        )
        or ""
    )


    if not predicted_class:

        raise HTTPException(
            status_code=500,
            detail=(
                "The selected finding does not "
                "contain a predicted class."
            )
        )


    # ========================================================
    # SAVE REVIEW
    # ========================================================

    try:

        review = (
            save_investigator_review(
                case_directory=
                    case_directory,

                case_id=
                    case_id,

                flow_index=
                    request.flow_index,

                predicted_class=
                    predicted_class,

                decision=
                    request.decision,

                notes=
                    request.notes
            )
        )


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


    except FileNotFoundError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )


    except Exception as error:

        print(
            "[FORENXAI REVIEW ERROR] "
            f"{type(error).__name__}: "
            f"{error}",
            flush=True
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Could not save "
                "investigator review: "
                f"{type(error).__name__}: "
                f"{error}"
            )
        )


    print(
        f"[FORENXAI] Investigator "
        f"review saved: "
        f"{case_id} / "
        f"Flow {request.flow_index} / "
        f"{request.decision}",
        flush=True
    )


    return {

        "status":
            "review_saved",

        "review":
            review
    }
# ============================================================
# PHASE 16
# GET INVESTIGATOR REVIEWS
# ============================================================

@router.get("/{case_id}/reviews")
def get_investigator_reviews(
    case_id: str
):

    # ========================================================
    # VALIDATE CASE ID
    # ========================================================

    if not re.fullmatch(
        r"FX-\d{8}-\d{6}",
        case_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid case ID."
        )


    # ========================================================
    # LOCATE CASE
    # ========================================================

    case_directory = (
        get_cases_directory()
        / case_id
    )


    if not case_directory.exists():

        raise HTTPException(
            status_code=404,
            detail="Case directory not found."
        )


    # ========================================================
    # LOAD REVIEWS
    # ========================================================

    try:

        reviews = (
            load_investigator_reviews(
                case_directory
            )
        )


    except FileNotFoundError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )


    except ValueError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Could not load "
                "investigator reviews: "
                f"{error}"
            )
        )


    return {

        "case_id":
            case_id,

        "total_reviews":
            len(reviews),

        "reviews":
            reviews
    }


# ============================================================
# PHASE 17
# GET FORENSIC REPORT DATA
# ============================================================

@router.get("/{case_id}/report")
def get_case_report(
    case_id: str
):

    # ========================================================
    # VALIDATE CASE ID
    # ========================================================

    if not re.fullmatch(
        r"FX-\d{8}-\d{6}",
        case_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid case ID."
        )


    # ========================================================
    # LOCATE BACKEND / CASE
    # ========================================================

    case_directory = (
        get_cases_directory()
        / case_id
    )


    if not case_directory.exists():

        raise HTTPException(
            status_code=404,
            detail="Case directory not found."
        )


    # ========================================================
    # BUILD FORENSIC REPORT
    # ========================================================

    try:

        report = (
            build_case_report(
                case_directory
            )
        )


    except FileNotFoundError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )


    except ValueError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Could not build "
                "forensic report: "
                f"{error}"
            )
        )


    # ========================================================
    # COMPLETE
    # ========================================================

    print(
        f"[FORENXAI] Forensic report "
        f"generated for {case_id}.",
        flush=True
    )


    return report

# ============================================================
# PHASE 18A
# GENERATE LOCAL QWEN XAI NARRATION
# ============================================================

@router.get(
    "/{case_id}/narration/{flow_index}"
)
def get_flow_narration(
    case_id: str,
    flow_index: int
):

    # ========================================================
    # VALIDATE CASE ID
    # ========================================================

    if not re.fullmatch(
        r"FX-\d{8}-\d{6}",
        case_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid case ID."
        )


    if flow_index < 0:

        raise HTTPException(
            status_code=400,
            detail="Flow index cannot be negative."
        )


    # ========================================================
    # LOCATE CASE
    # ========================================================

    case_directory = (
        get_cases_directory()
        / case_id
    )


    analysis_file = (
        case_directory
        / "analysis.json"
    )


    if not case_directory.exists():

        raise HTTPException(
            status_code=404,
            detail="Case directory not found."
        )


    if not analysis_file.exists():

        raise HTTPException(
            status_code=404,
            detail="analysis.json not found."
        )


    # ========================================================
    # READ ANALYSIS
    # ========================================================

    try:

        with analysis_file.open(
            "r",
            encoding="utf-8"
        ) as file:

            analysis_data = json.load(
                file
            )


    except json.JSONDecodeError as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "analysis.json contains invalid JSON: "
                f"{error}"
            )
        )


    # ========================================================
    # GET ML FINDINGS
    # ========================================================

    ml_findings = (
        analysis_data
        .get(
            "ml_analysis",
            {}
        )
        .get(
            "findings",
            []
        )
    )


    # ========================================================
    # GET SHAP EXPLANATIONS
    # ========================================================

    shap_explanations = (
        analysis_data
        .get(
            "shap_analysis",
            {}
        )
        .get(
            "explanations",
            []
        )
    )


    # ========================================================
    # FIND MATCHING ML FINDING
    # ========================================================

    selected_finding = None


    for finding in ml_findings:

        if not isinstance(
            finding,
            dict
        ):
            continue


        if (
            finding.get(
                "flow_index"
            )
            == flow_index
        ):

            selected_finding = finding

            break


    if selected_finding is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"ML finding for flow "
                f"{flow_index} was not found."
            )
        )


    # ========================================================
    # FIND MATCHING SHAP EXPLANATION
    # ========================================================

    selected_shap = None


    for explanation in shap_explanations:

        if not isinstance(
            explanation,
            dict
        ):
            continue


        if (
            explanation.get(
                "flow_index"
            )
            == flow_index
        ):

            selected_shap = explanation

            break


    if selected_shap is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"SHAP explanation for flow "
                f"{flow_index} was not found."
            )
        )


    # ========================================================
    # GENERATE QWEN NARRATION
    # ========================================================

    print(
        f"[FORENXAI] Composing explanation from the retrieved "
        f"documents for {case_id} / Flow {flow_index}...",
        flush=True
    )


    try:

        narration = (
            generate_flow_narration(
                selected_finding,
                selected_shap
            )
        )


    except Exception as error:

        print(
            "[FORENXAI LLM ERROR] "
            f"{type(error).__name__}: "
            f"{error}",
            flush=True
        )


        raise HTTPException(
            status_code=500,
            detail=(
                f"{type(error).__name__}: "
                f"{error}"
            )
        )


    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {

        "case_id":
            case_id,

        "flow_index":
            flow_index,

        "predicted_class":
            selected_finding.get(
                "predicted_class"
            ),

        "narration":
            narration
    }
    
# ============================================================
# GET ANALYSIS
# ============================================================

@router.get("/{case_id}")
def get_analysis(
    case_id: str
):

    # ========================================================
    # VALIDATE CASE ID
    # ========================================================

    if not re.fullmatch(
        r"FX-\d{8}-\d{6}",
        case_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid case ID."
        )


    # ========================================================
    # LOCATE CASE
    # ========================================================

    case_directory = (
        get_cases_directory()
        / case_id
    )


    analysis_file = (
        case_directory
        / "analysis.json"
    )


    # ========================================================
    # VALIDATE CASE
    # ========================================================

    if not case_directory.exists():

        raise HTTPException(
            status_code=404,
            detail="Case directory not found."
        )


    if not analysis_file.exists():

        raise HTTPException(
            status_code=404,
            detail="analysis.json not found."
        )


    if (
        analysis_file
        .stat()
        .st_size
        == 0
    ):

        raise HTTPException(
            status_code=500,
            detail="analysis.json is empty."
        )


    # ========================================================
    # READ ANALYSIS JSON
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

        raise HTTPException(
            status_code=500,
            detail=(
                "analysis.json contains "
                "invalid JSON: "
                f"{error}"
            )
        )


    return analysis_data