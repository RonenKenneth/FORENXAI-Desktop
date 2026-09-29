import logging

from logging.handlers import (
    RotatingFileHandler,
)

from app.utils.runtime_paths import (
    get_logs_directory,
)


# ============================================================
# FORENXAI LOGGING CONFIGURATION
# ============================================================

LOGGER_NAME = "FORENXAI"

LOG_FILE_NAME = "forenxai.log"

MAX_LOG_SIZE_BYTES = (
    5
    * 1024
    * 1024
)

BACKUP_LOG_COUNT = 5


# ============================================================
# CREATE LOGGER
# ============================================================

def get_logger() -> logging.Logger:
    """
    Return the centralized FORENXAI logger.

    The logger writes to:
        Development:
            backend/logs/forenxai.log

        Packaged application:
            %LOCALAPPDATA%/FORENXAI/logs/forenxai.log

    Log files rotate automatically when they reach
    approximately 5 MB.
    """

    logger = logging.getLogger(
        LOGGER_NAME
    )


    # --------------------------------------------------------
    # Prevent duplicate handlers
    # --------------------------------------------------------

    if logger.handlers:
        return logger


    logger.setLevel(
        logging.INFO
    )


    logger.propagate = False


    # --------------------------------------------------------
    # Log directory
    # --------------------------------------------------------

    logs_directory = (
        get_logs_directory()
    )


    log_file_path = (
        logs_directory
        / LOG_FILE_NAME
    )


    # --------------------------------------------------------
    # Log format
    # --------------------------------------------------------

    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(name)s | "
        "%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


    # --------------------------------------------------------
    # File handler
    # --------------------------------------------------------

    file_handler = (
        RotatingFileHandler(
            log_file_path,
            maxBytes=MAX_LOG_SIZE_BYTES,
            backupCount=BACKUP_LOG_COUNT,
            encoding="utf-8"
        )
    )


    file_handler.setLevel(
        logging.INFO
    )


    file_handler.setFormatter(
        formatter
    )


    logger.addHandler(
        file_handler
    )


    # --------------------------------------------------------
    # Console handler
    # --------------------------------------------------------

    console_handler = (
        logging.StreamHandler()
    )


    console_handler.setLevel(
        logging.INFO
    )


    console_handler.setFormatter(
        formatter
    )


    logger.addHandler(
        console_handler
    )


    return logger


# ============================================================
# GLOBAL FORENXAI LOGGER
# ============================================================

logger = get_logger()