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


def get_rag_directory() -> Path:
    """
    Return the directory holding the retrieval assets.

    Development:
        ...\\FORENXAI-Desktop\\rag      (sibling of backend\\)

    Packaged deployment:
        backend\\rag, or a directory supplied through FORENXAI_RAG_DIR.

    The recommendation panel reads knowledge/ and config/ from here. It is
    resolved rather than hard-coded because the packaged layout puts the
    assets beside the executable instead of beside the source tree.
    """

    configured_path = os.environ.get(
        "FORENXAI_RAG_DIR"
    )

    if configured_path:
        return Path(
            configured_path
        ).resolve()

    backend_directory = (
        get_backend_directory()
    )

    # Packaged: the assets ship inside the backend directory.
    packaged = (
        backend_directory
        / "rag"
    )

    if packaged.is_dir():
        return packaged

    # Development: rag/ sits beside backend/.
    return (
        backend_directory.parent
        / "rag"
    )


def get_knowledge_directory() -> Path:
    return (
        get_rag_directory()
        / "knowledge"
    )


def get_knowledge_map_path() -> Path:
    return (
        get_rag_directory()
        / "config"
        / "knowledge_map.py"
    )