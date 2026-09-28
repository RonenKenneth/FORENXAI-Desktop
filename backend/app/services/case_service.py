from pathlib import Path
import json

from app.services.logging_service import logger
from app.utils.runtime_paths import get_cases_directory


def _case_summary(analysis_file: Path) -> dict:
    """The parts of analysis.json the case list shows, in the same shape.

    analysis.json can be tens of MB, and the list needs only a few
    totals, so they are kept in summary.json beside it and rebuilt
    whenever analysis.json is newer (a re-analysis)."""
    cache = analysis_file.with_name("summary.json")
    if cache.exists() and cache.stat().st_mtime >= analysis_file.stat().st_mtime:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    with analysis_file.open("r", encoding="utf-8") as file:
        data = json.load(file)
    ml = data.get("ml_analysis") if isinstance(data.get("ml_analysis"), dict) else {}
    summary = {
        "file_name": data.get("file_name"),
        "traffic_summary": {"total_packets": (data.get("traffic_summary") or {}).get("total_packets")},
        "flow_summary": {"total_flows": (data.get("flow_summary") or {}).get("total_flows")},
        "ml_analysis": {"summary": ml.get("summary", {})},
    }
    try:
        cache.write_text(json.dumps(summary), encoding="utf-8")
    except OSError:
        pass      # read-only case folder: still correct, just not cached
    return summary


def list_cases() -> list[dict]:
    """
    Discover FORENXAI case directories and return
    lightweight metadata for the case-management UI.
    """

    cases_directory = get_cases_directory()

    logger.info(
        "Case discovery started | Cases directory: %s",
        cases_directory,
    )

    discovered_cases = []

    if not cases_directory.exists():

        logger.info(
            "Case discovery completed | Cases found: 0"
        )

        return discovered_cases

    case_directories = sorted(
        [
            path
            for path in cases_directory.iterdir()
            if path.is_dir()
            and path.name.startswith("FX-")
        ],
        key=lambda path: path.name,
        reverse=True,
    )

    for case_directory in case_directories:

        case_id = case_directory.name

        analysis_file = (
            case_directory
            / "analysis.json"
        )

        reviews_file = (
            case_directory
            / "reviews"
            / "investigator_reviews.json"
        )

        evidence_directory = (
            case_directory
            / "evidence"
        )

        case_record = {
            "case_id": case_id,
            "status": "Incomplete",
            "evidence_file": None,
            "total_packets": None,
            "total_flows": None,
            "ml_total_flows": None,
            "benign_flows": None,
            "threat_flows": None,
            "threat_percentage": None,
            "has_reviews": reviews_file.exists(),
            "analysis_exists": analysis_file.exists(),
        }

        # ====================================================
        # DISCOVER EVIDENCE FILE
        # ====================================================

        if evidence_directory.exists():

            evidence_files = [
                file
                for file
                in evidence_directory.iterdir()
                if file.is_file()
            ]

            if evidence_files:

                case_record["evidence_file"] = (
                    evidence_files[0].name
                )

        # ====================================================
        # READ ANALYSIS DATA
        # ====================================================

        if analysis_file.exists():

            try:

                if analysis_file.stat().st_size == 0:

                    logger.warning(
                        "Case discovery found empty analysis file | "
                        "Case ID: %s",
                        case_id,
                    )

                    case_record["status"] = "Invalid"

                    discovered_cases.append(
                        case_record
                    )

                    continue

                analysis_data = _case_summary(analysis_file)

                # --------------------------------------------
                # ACTUAL FORENXAI ANALYSIS STRUCTURE
                # --------------------------------------------

                traffic_summary = (
                    analysis_data.get(
                        "traffic_summary",
                        {},
                    )
                )

                flow_summary = (
                    analysis_data.get(
                        "flow_summary",
                        {},
                    )
                )

                ml_analysis = (
                    analysis_data.get(
                        "ml_analysis",
                        {},
                    )
                )

                ml_summary = (
                    ml_analysis.get(
                        "summary",
                        {},
                    )
                    if isinstance(
                        ml_analysis,
                        dict,
                    )
                    else {}
                )

                # --------------------------------------------
                # CASE STATUS
                # --------------------------------------------

                case_record["status"] = "Analyzed"

                # --------------------------------------------
                # BASIC CASE INFORMATION
                # --------------------------------------------

                case_record["evidence_file"] = (
                    analysis_data.get(
                        "file_name"
                    )
                    or case_record[
                        "evidence_file"
                    ]
                )

                # --------------------------------------------
                # TRAFFIC STATISTICS
                # --------------------------------------------

                case_record["total_packets"] = (
                    traffic_summary.get(
                        "total_packets"
                    )
                )

                case_record["total_flows"] = (
                    flow_summary.get(
                        "total_flows"
                    )
                )

                # --------------------------------------------
                # ML STATISTICS
                # --------------------------------------------

                case_record["ml_total_flows"] = (
                    ml_summary.get(
                        "total_flows"
                    )
                )

                case_record["benign_flows"] = (
                    ml_summary.get(
                        "benign_flows"
                    )
                )

                case_record["threat_flows"] = (
                    ml_summary.get(
                        "threat_flows"
                    )
                )

                case_record["threat_percentage"] = (
                    ml_summary.get(
                        "threat_percentage"
                    )
                )

            except json.JSONDecodeError as error:

                logger.warning(
                    "Case discovery found invalid analysis JSON | "
                    "Case ID: %s | Error: %s",
                    case_id,
                    error,
                )

                case_record["status"] = "Invalid"

            except Exception as error:

                logger.exception(
                    "Case discovery failed for case | "
                    "Case ID: %s | Error: %s: %s",
                    case_id,
                    type(error).__name__,
                    error,
                )

                case_record["status"] = "Error"

        discovered_cases.append(
            case_record
        )

    logger.info(
        "Case discovery completed | Cases found: %s",
        len(discovered_cases),
    )

    return discovered_cases
def get_case_details(
    case_id: str
) -> dict:
    """
    Load an existing FORENXAI case without re-running analysis.

    Returns:
        - case metadata
        - stored analysis.json
        - investigator review information
    """

    cases_directory = (
        get_cases_directory()
    )

    case_directory = (
        cases_directory
        / case_id
    )

    analysis_file = (
        case_directory
        / "analysis.json"
    )

    reviews_file = (
        case_directory
        / "reviews"
        / "investigator_reviews.json"
    )

    logger.info(
        "Existing case load started | Case ID: %s",
        case_id,
    )

    # ========================================================
    # VALIDATE CASE DIRECTORY
    # ========================================================

    if not case_directory.exists():

        logger.warning(
            "Existing case load rejected | "
            "Case ID: %s | Case directory not found.",
            case_id,
        )

        raise FileNotFoundError(
            "Case directory not found."
        )

    # ========================================================
    # VALIDATE ANALYSIS FILE
    # ========================================================

    if not analysis_file.exists():

        logger.warning(
            "Existing case load rejected | "
            "Case ID: %s | analysis.json not found.",
            case_id,
        )

        raise FileNotFoundError(
            "analysis.json not found for this case."
        )

    if analysis_file.stat().st_size == 0:

        logger.error(
            "Existing case load failed | "
            "Case ID: %s | analysis.json is empty.",
            case_id,
        )

        raise ValueError(
            "analysis.json is empty."
        )

    # ========================================================
    # LOAD ANALYSIS
    # ========================================================

    try:

        with analysis_file.open(
            "r",
            encoding="utf-8",
        ) as file:

            analysis_data = (
                json.load(file)
            )

    except json.JSONDecodeError as error:

        logger.error(
            "Existing case load failed | "
            "Case ID: %s | Invalid analysis JSON | %s",
            case_id,
            error,
        )

        raise ValueError(
            "analysis.json contains invalid JSON: "
            f"{error}"
        )

    # ========================================================
    # LOAD REVIEWS
    # ========================================================

    reviews = []

    if reviews_file.exists():

        try:

            if reviews_file.stat().st_size > 0:

                with reviews_file.open(
                    "r",
                    encoding="utf-8",
                ) as file:

                    loaded_reviews = (
                        json.load(file)
                    )

                if isinstance(
                    loaded_reviews,
                    list,
                ):

                    reviews = loaded_reviews

                else:

                    logger.warning(
                        "Existing case review data ignored | "
                        "Case ID: %s | "
                        "Review file is not a JSON list.",
                        case_id,
                    )

        except json.JSONDecodeError as error:

            logger.warning(
                "Existing case review data invalid | "
                "Case ID: %s | Error: %s",
                case_id,
                error,
            )

    # ========================================================
    # COMPLETE
    # ========================================================

    result = {
        "case_id": case_id,
        "status": "Analyzed",
        "evidence_file": (
            analysis_data.get(
                "file_name"
            )
        ),
        "analysis_exists": True,
        "has_reviews": (
            len(reviews) > 0
        ),
        "total_reviews": (
            len(reviews)
        ),
        "analysis": analysis_data,
        "reviews": reviews,
    }

    logger.info(
        "Existing case load completed | "
        "Case ID: %s | Reviews: %s",
        case_id,
        len(reviews),
    )

    return result
def delete_case(
    case_id: str
) -> dict:
    """
    Delete one FORENXAI case directory safely.
    """

    import re
    import shutil

    cases_directory = (
        get_cases_directory()
        .resolve()
    )

    if not re.fullmatch(
        r"FX-\d{8}-\d{6}",
        case_id
    ):

        logger.warning(
            "Case deletion rejected | "
            "Case ID: %s | Invalid case ID.",
            case_id,
        )

        raise ValueError(
            "Invalid case ID."
        )

    case_directory = (
        cases_directory
        / case_id
    ).resolve()

    # ========================================================
    # SAFETY CHECK
    # ========================================================

    if (
        case_directory.parent
        != cases_directory
    ):

        logger.error(
            "Case deletion rejected | "
            "Case ID: %s | Unsafe case path: %s",
            case_id,
            case_directory,
        )

        raise ValueError(
            "Unsafe case path."
        )

    if not case_directory.exists():

        logger.warning(
            "Case deletion rejected | "
            "Case ID: %s | Case directory not found.",
            case_id,
        )

        raise FileNotFoundError(
            "Case directory not found."
        )

    logger.warning(
        "Case deletion started | "
        "Case ID: %s | Directory: %s",
        case_id,
        case_directory,
    )

    shutil.rmtree(
        case_directory
    )

    if case_directory.exists():

        logger.error(
            "Case deletion failed | "
            "Case ID: %s | Directory still exists.",
            case_id,
        )

        raise RuntimeError(
            "Case directory could not be deleted."
        )

    logger.warning(
        "Case deleted successfully | "
        "Case ID: %s",
        case_id,
    )

    return {
        "status": "deleted",
        "case_id": case_id,
    }