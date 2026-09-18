from pathlib import Path
from datetime import datetime, timezone
import json


# ============================================================
# VALID INVESTIGATOR DECISIONS
# ============================================================

VALID_DECISIONS = {
    "Confirmed",
    "Rejected",
    "Inconclusive"
}


# ============================================================
# SAVE INVESTIGATOR REVIEW
# ============================================================

def save_investigator_review(
    case_directory: Path,
    case_id: str,
    flow_index: int,
    predicted_class: str,
    decision: str,
    notes: str
) -> dict:
    """
    Save an investigator review for a specific ML finding.

    Reviews are stored in:

        <case_directory>/reviews/investigator_reviews.json

    If the same flow is reviewed again, the previous review
    for that flow is replaced.
    """

    # ========================================================
    # VALIDATION
    # ========================================================

    if not case_directory.exists():

        raise FileNotFoundError(
            f"Case directory does not exist: "
            f"{case_directory}"
        )


    if not case_id:

        raise ValueError(
            "Case ID is required."
        )


    if flow_index < 0:

        raise ValueError(
            "Flow index cannot be negative."
        )


    if not predicted_class:

        raise ValueError(
            "Predicted class is required."
        )


    if decision not in VALID_DECISIONS:

        raise ValueError(
            "Invalid investigator decision. "
            "Expected one of: "
            "Confirmed, Rejected, Inconclusive."
        )


    notes = notes.strip()


    # ========================================================
    # REVIEW DIRECTORY
    # ========================================================

    reviews_directory = (
        case_directory
        / "reviews"
    )


    reviews_directory.mkdir(
        parents=True,
        exist_ok=True
    )


    reviews_file = (
        reviews_directory
        / "investigator_reviews.json"
    )


    # ========================================================
    # CREATE REVIEW RECORD
    # ========================================================

    review_record = {

        "case_id":
            case_id,

        "flow_index":
            flow_index,

        "predicted_class":
            predicted_class,

        "decision":
            decision,

        "notes":
            notes,

        "review_timestamp":
            (
                datetime.now(
                    timezone.utc
                )
                .isoformat()
            )
    }


    # ========================================================
    # LOAD EXISTING REVIEWS
    # ========================================================

    existing_reviews = []


    if reviews_file.exists():

        if (
            reviews_file
            .stat()
            .st_size
            > 0
        ):

            try:

                with reviews_file.open(
                    "r",
                    encoding="utf-8"
                ) as file:

                    loaded_data = (
                        json.load(
                            file
                        )
                    )

            except json.JSONDecodeError as error:

                raise ValueError(
                    "Existing investigator review "
                    "file contains invalid JSON: "
                    f"{error}"
                )


            if isinstance(
                loaded_data,
                list
            ):

                existing_reviews = (
                    loaded_data
                )

            else:

                raise ValueError(
                    "Existing investigator review "
                    "file does not contain "
                    "a JSON list."
                )


    # ========================================================
    # REMOVE PREVIOUS REVIEW FOR SAME FLOW
    # ========================================================

    existing_reviews = [

        review

        for review
        in existing_reviews

        if (
            review.get(
                "flow_index"
            )
            != flow_index
        )
    ]


    # ========================================================
    # ADD CURRENT REVIEW
    # ========================================================

    existing_reviews.append(
        review_record
    )


    # ========================================================
    # SORT BY FLOW INDEX
    # ========================================================

    existing_reviews.sort(

        key=lambda review:
            review.get(
                "flow_index",
                -1
            )
    )


    # ========================================================
    # SAFE TEMPORARY WRITE
    # ========================================================

    temporary_file = (
        reviews_directory
        / "investigator_reviews.tmp"
    )


    with temporary_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            existing_reviews,
            file,
            indent=4,
            ensure_ascii=False
        )


    # ========================================================
    # REPLACE FINAL REVIEW FILE
    # ========================================================

    temporary_file.replace(
        reviews_file
    )


    return review_record


# ============================================================
# LOAD INVESTIGATOR REVIEWS
# ============================================================

def load_investigator_reviews(
    case_directory: Path
) -> list:
    """
    Load all investigator reviews for a case.

    Returns an empty list when no reviews have been saved yet.
    """

    # ========================================================
    # VALIDATE CASE DIRECTORY
    # ========================================================

    if not case_directory.exists():

        raise FileNotFoundError(
            f"Case directory does not exist: "
            f"{case_directory}"
        )


    # ========================================================
    # LOCATE REVIEW FILE
    # ========================================================

    reviews_file = (
        case_directory
        / "reviews"
        / "investigator_reviews.json"
    )


    # ========================================================
    # NO REVIEWS YET
    # ========================================================

    if not reviews_file.exists():

        return []


    if (
        reviews_file
        .stat()
        .st_size
        == 0
    ):

        return []


    # ========================================================
    # READ REVIEW FILE
    # ========================================================

    try:

        with reviews_file.open(
            "r",
            encoding="utf-8"
        ) as file:

            reviews = (
                json.load(
                    file
                )
            )


    except json.JSONDecodeError as error:

        raise ValueError(
            "Investigator review file "
            "contains invalid JSON: "
            f"{error}"
        )


    # ========================================================
    # VALIDATE FORMAT
    # ========================================================

    if not isinstance(
        reviews,
        list
    ):

        raise ValueError(
            "Investigator review file "
            "does not contain a JSON list."
        )


    # ========================================================
    # SORT REVIEWS
    # ========================================================

    reviews.sort(

        key=lambda review:
            review.get(
                "flow_index",
                -1
            )
    )


    return reviews