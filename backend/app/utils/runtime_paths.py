from pathlib import Path
import os
import sys


def get_backend_directory() -> Path:
    """
    Return the persistent FORENXAI backend directory.

    Development:
        ...\Forenxai\backend

    PyInstaller test build:
        ...\Forenxai\backend

    Final packaged deployment:
        directory containing FORENXAI.Backend.exe
        or a directory supplied through FORENXAI_BACKEND_DIR.
    """

    # --------------------------------------------------------
    # Explicit override
    # --------------------------------------------------------

    configured_path = os.environ.get(
        "FORENXAI_BACKEND_DIR"
    )

    if configured_path:
        path = Path(
            configured_path
        ).resolve()

        return path


    # --------------------------------------------------------
    # PyInstaller executable
    # --------------------------------------------------------

    if getattr(
        sys,
        "frozen",
        False
    ):
        executable_directory = (
            Path(sys.executable)
            .resolve()
            .parent
        )

        # During development our executable currently lives in:
        #
        # backend\dist\FORENXAI.Backend.exe
        #
        # while cases are stored in:
        #
        # backend\cases
        #
        if (
            executable_directory.name.lower()
            == "dist"
        ):
            backend_directory = (
                executable_directory.parent
            )

            return backend_directory


        # Final deployment:
        #
        # backend\FORENXAI.Backend.exe
        # backend\cases\
        return executable_directory


    # --------------------------------------------------------
    # Normal Python development
    # --------------------------------------------------------

    return (
        Path(__file__)
        .resolve()
        .parents[2]
    )


def get_cases_directory() -> Path:
    return (
        get_backend_directory()
        / "cases"
    )
    
def get_llm_directory() -> Path:
    return (
        get_backend_directory()
        / "models"
        / "llm"
    )


def get_llm_model_path() -> Path:
    return (
        get_llm_directory()
        / "qwen2.5-3b-q4.gguf"
    )