from pathlib import Path
from typing import Optional
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


def get_toolchain_directory() -> Path:
    """
    Return the directory holding project-local third-party tools.

    Development:
        ...\\FORENXAI-Desktop\\tools    (sibling of backend\\ and rag\\)

    Packaged deployment:
        backend\\tools, or a directory supplied through FORENXAI_TOOLS_DIR.

    This is where a JDK for CICFlowMeter is unpacked. It is deliberately
    NOT the Python virtual environment: .venv is managed by pip and knows
    nothing about JVMs, so a JDK placed inside it would be removed by the
    next environment rebuild and would still need its path wired by hand.
    """

    configured_path = os.environ.get(
        "FORENXAI_TOOLS_DIR"
    )

    if configured_path:
        return Path(configured_path).resolve()

    backend_directory = get_backend_directory()

    packaged = backend_directory / "tools"

    if packaged.is_dir():
        return packaged

    # Development: tools/ sits beside backend/.
    return backend_directory.parent / "tools"


def get_java_home() -> Optional[Path]:
    """
    Return the JVM CICFlowMeter should run on, or None for the system one.

    WHY NOT THE SYSTEM JAVA
    CICFlowMeter's pom.xml sets source and target to 1.8. JDK 24 removed
    support for -source 8, so a current JDK fails the build outright with
    "Source option 8 is no longer supported" before a single packet is
    read. jNetPcap 1.4 dates from 2012 and is likewise happiest on the JVM
    it was built against.

    Rather than downgrading the machine's Java -- which would affect every
    other tool on it -- a JDK is unpacked under tools/ and used only for
    the CICFlowMeter subprocess. Nothing global changes.

    Resolution order, first hit wins:

      1. FORENXAI_JAVA_HOME                  explicit override
      2. tools/jdk* containing bin/java.exe  a JDK unpacked in the project
      3. tools/jdk.path                      a file naming where the JDK is
      4. JAVA_HOME                           whatever the machine uses
      5. None                                fall back to java on PATH

    Step 3 exists because this project tree is inside OneDrive. A JDK is
    roughly 300 MB of small files; unpacking one into tools/ would sync
    every one of them to cloud storage for no benefit. The pointer file
    keeps the location under version control while the bytes stay on the
    local disk, beside CICFlowMeter and Maven in C:\\Tools.
    """

    def _usable(candidate: Path) -> Optional[Path]:
        """A directory is a JDK when bin/java(.exe) sits under it."""
        if not candidate.is_dir():
            return None

        for executable in ("java.exe", "java"):
            if (candidate / "bin" / executable).is_file():
                return candidate

        # Archives usually unpack one level deep:
        # tools/jdk8/jdk8u452-b09/bin/java.exe
        try:
            children = sorted(candidate.iterdir())
        except OSError:
            return None

        for child in children:
            if not child.is_dir():
                continue
            for executable in ("java.exe", "java"):
                if (child / "bin" / executable).is_file():
                    return child

        return None

    configured = os.environ.get("FORENXAI_JAVA_HOME")

    if configured:
        resolved = _usable(Path(configured))
        if resolved:
            return resolved

    toolchain = get_toolchain_directory()

    if toolchain.is_dir():
        # sorted() so that two JDKs sitting side by side always resolve
        # the same way rather than depending on directory order.
        for child in sorted(toolchain.glob("jdk*")):
            if child.is_dir():
                resolved = _usable(child)
                if resolved:
                    return resolved

        pointer = toolchain / "jdk.path"

        if pointer.is_file():
            try:
                for line in pointer.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    resolved = _usable(Path(line))
                    if resolved:
                        return resolved
            except OSError:
                pass

    system = os.environ.get("JAVA_HOME")

    if system:
        resolved = _usable(Path(system))
        if resolved:
            return resolved

    return None