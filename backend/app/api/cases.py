from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.case_service import (
    list_cases,
    get_case_details,
    delete_case,
    set_retention,
)
from app.services.logging_service import logger


router = APIRouter(
    prefix="/cases",
    tags=["Cases"],
)


@router.get("")
def get_cases():
    """
    Return all FORENXAI investigation cases.

    Cases are ordered newest-first by case ID.
    """

    try:

        cases = list_cases()

        logger.info(
            "Case list request completed | Cases returned: %s",
            len(cases),
        )

        return {
            "total_cases": len(cases),
            "cases": cases,
        }

    except Exception as error:

        logger.exception(
            "Case list request failed | Error: %s: %s",
            type(error).__name__,
            error,
        )

        raise HTTPException(
            status_code=500,
            detail="Could not retrieve FORENXAI cases.",
        )

@router.get("/{case_id}")
def get_case(
    case_id: str
):
    """
    Load one existing FORENXAI case
    without re-running packet analysis.
    """

    try:

        case = get_case_details(
            case_id
        )

        logger.info(
            "Case detail request completed | Case ID: %s",
            case_id,
        )

        return case

    except FileNotFoundError as error:

        logger.warning(
            "Case detail request rejected | "
            "Case ID: %s | HTTP 404 | %s",
            case_id,
            error,
        )

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )

    except ValueError as error:

        logger.error(
            "Case detail request failed | "
            "Case ID: %s | HTTP 500 | %s",
            case_id,
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

    except Exception as error:

        logger.exception(
            "Case detail request failed | "
            "Case ID: %s | Error: %s: %s",
            case_id,
            type(error).__name__,
            error,
        )

        raise HTTPException(
            status_code=500,
            detail="Could not load FORENXAI case.",
        )
@router.delete("/{case_id}")
def remove_case(
    case_id: str
):
    """
    Delete one FORENXAI case safely.
    """

    try:

        result = delete_case(
            case_id
        )

        logger.warning(
            "Case delete request completed | Case ID: %s",
            case_id,
        )

        return result

    except ValueError as error:

        logger.warning(
            "Case delete request rejected | "
            "Case ID: %s | HTTP 400 | %s",
            case_id,
            error,
        )

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except FileNotFoundError as error:

        logger.warning(
            "Case delete request rejected | "
            "Case ID: %s | HTTP 404 | %s",
            case_id,
            error,
        )

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )

    except Exception as error:

        logger.exception(
            "Case delete request failed | "
            "Case ID: %s | Error: %s: %s",
            case_id,
            type(error).__name__,
            error,
        )

        raise HTTPException(
            status_code=500,
            detail="Could not delete FORENXAI case.",
        )


class RetentionRequest(BaseModel):
    # ISO 8601 date and time; null cancels the scheduled deletion.
    delete_after: Optional[str] = None


@router.put("/{case_id}/retention")
def schedule_case_deletion(
    case_id: str,
    request: RetentionRequest,
):
    """
    Schedule the automatic deletion of one case, or cancel it.
    """

    try:
        return set_retention(case_id, request.delete_after)

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error))
