from pathlib import Path
import os
import re
import shutil
import subprocess

from scapy.utils import PcapNgReader
from app.utils.runtime_paths import (
    get_backend_directory,
    get_cases_directory,
    get_java_home,
    get_toolchain_directory,
)

# ============================================================
# CICFLOWMETER CONFIGURATION
# ============================================================

CICFLOWMETER_ROOT = Path(
    r"C:\Tools\CICFlowMeter\CICFlowMeter-master"
)

MAVEN_EXECUTABLE = Path(
    r"C:\Tools\apache-maven-3.9.16-bin"
    r"\apache-maven-3.9.16\bin\mvn.cmd"
)

EDITCAP_EXECUTABLE = Path(
    r"C:\Program Files\Wireshark\editcap.exe"
)


# ============================================================
# NATIVE LIBRARY CONFIGURATION
# ============================================================

JNETPCAP_NATIVE_DIR = Path(
    r"C:\Tools\CICFlowMeter\CICFlowMeter-master"
    r"\jnetpcap\win\jnetpcap-1.4.r1425"
)

INSTALLED_NATIVE_DIR = Path(
    r"C:\Tools\CICFlowMeter\installed"
    r"\CICFlowMeter-4.0\lib\native"
)

NPCAP_NATIVE_DIR = Path(
    r"C:\Windows\System32\Npcap"
)

JNETPCAP_NATIVE_CANDIDATES = [
    JNETPCAP_NATIVE_DIR,
    INSTALLED_NATIVE_DIR,
    NPCAP_NATIVE_DIR,
]

# ============================================================
# PATH HELPERS
# ============================================================

def _backend_directory() -> Path:
    """
    Return the persistent FORENXAI backend directory.

    IMPORTANT:
        Do not derive this path from __file__.

        In a PyInstaller --onefile build, __file__ points inside
        PyInstaller's temporary _MEI extraction directory.

        runtime_paths.py handles both development mode and
        packaged execution correctly.
    """

    return get_backend_directory()


def _case_directory(
    case_id: str
) -> Path:
    """
    Return the persistent directory for one FORENXAI case.
    """

    return (
        get_cases_directory()
        / case_id
    )


# ============================================================
# CONFIGURATION VALIDATION
# ============================================================

def _validate_configuration() -> None:

    if not CICFLOWMETER_ROOT.exists():
        raise RuntimeError(
            "CICFlowMeter directory was not found:\n"
            f"{CICFLOWMETER_ROOT}"
        )

    if not MAVEN_EXECUTABLE.exists():
        raise RuntimeError(
            "Maven executable was not found:\n"
            f"{MAVEN_EXECUTABLE}"
        )

    pom_file = (
        CICFLOWMETER_ROOT
        / "pom.xml"
    )

    if not pom_file.exists():
        raise RuntimeError(
            "CICFlowMeter pom.xml was not found:\n"
            f"{pom_file}"
        )


# ============================================================
# CLEAN DIRECTORY
# ============================================================

def _reset_directory(
    directory: Path
) -> None:
    """
    Remove an old temporary directory and recreate it.

    This prevents a CSV from a previous analysis from being
    mistaken for the output of the current analysis.
    """

    if directory.exists():
        shutil.rmtree(
            directory,
            ignore_errors=True
        )

    directory.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# PCAPNG -> PCAP CONVERSION
# ============================================================

def _convert_pcapng_to_pcap(
    source_file: Path,
    destination_file: Path
) -> Path:
    """
    Convert PCAPNG into classic PCAP using Wireshark editcap.

    IMPORTANT:
    The original evidence file is NOT changed.

    Only a derived processing copy is created for CICFlowMeter.
    """

    if not EDITCAP_EXECUTABLE.exists():
        raise RuntimeError(
            "A PCAPNG file was supplied, but "
            "Wireshark editcap.exe was not found.\n\n"
            "Expected location:\n"
            f"{EDITCAP_EXECUTABLE}\n\n"
            "Install Wireshark or update "
            "EDITCAP_EXECUTABLE in "
            "cicflowmeter_service.py."
        )

    destination_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    command = [
        str(EDITCAP_EXECUTABLE),
        "-F",
        "pcap",
        str(source_file),
        str(destination_file),
    ]

    print(
        "[FORENXAI] PCAPNG detected.",
        flush=True
    )

    print(
        "[FORENXAI] Creating derived "
        "PCAP working copy...",
        flush=True
    )

    print(
        f"[FORENXAI] Original evidence: "
        f"{source_file}",
        flush=True
    )

    print(
        f"[FORENXAI] Working PCAP: "
        f"{destination_file}",
        flush=True
    )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "PCAPNG to PCAP conversion timed out."
        ) from error

    except OSError as error:
        raise RuntimeError(
            "Could not start editcap.exe.\n"
            f"{error}"
        ) from error


    if result.stdout.strip():
        print(
            "[FORENXAI] Editcap output:"
        )

        print(
            result.stdout.strip(),
            flush=True
        )


    if result.stderr.strip():
        print(
            "[FORENXAI] Editcap message:"
        )

        print(
            result.stderr.strip(),
            flush=True
        )


    if result.returncode != 0:
        raise RuntimeError(
            "PCAPNG to PCAP conversion failed.\n\n"
            f"Editcap exit code: "
            f"{result.returncode}\n\n"
            f"STDERR:\n"
            f"{result.stderr}"
        )


    if not destination_file.exists():
        raise RuntimeError(
            "Editcap returned successfully, "
            "but the converted PCAP file "
            "was not created."
        )


    if destination_file.stat().st_size <= 0:
        raise RuntimeError(
            "Editcap created an empty "
            "PCAP working file."
        )


    print(
        "[FORENXAI] PCAPNG conversion "
        "completed successfully.",
        flush=True
    )

    print(
        f"[FORENXAI] Working PCAP size: "
        f"{destination_file.stat().st_size} bytes",
        flush=True
    )


    return destination_file


# ============================================================
# PREPARE CICFLOWMETER INPUT
# ============================================================

# ============================================================
# CAPTURE FORMAT AND LINK LAYER
# ============================================================
#
# The format is read from the file's first bytes, not its name: a pcapng
# saved as ".pcap" is still converted. CICFlowMeter's reader finds IP only
# behind Ethernet (optionally VLAN-tagged) or in raw-IP captures; Linux
# "cooked" (SLL / SLL2), BSD loopback, 802.11 and other link layers give no
# flows at all. Such captures are rewritten into an Ethernet working copy:
# the IP packets and their timestamps are kept, the link header is replaced.

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",      # microsecond
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",      # nanosecond
}
CICFLOWMETER_LINK_TYPES = {1, 12, 14, 101}               # Ethernet, raw IP


def _capture_format(path: Path) -> str:
    with open(path, "rb") as stream:
        magic = stream.read(4)
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    if magic in PCAP_MAGICS:
        return "pcap"
    raise RuntimeError(
        "The evidence file is not a pcap or pcapng capture "
        f"(first bytes {magic.hex()})."
    )


def _link_types(path: Path, probe: int = 2000) -> set[int]:
    """Link types of the capture (every interface seen in the first
    `probe` packets of a pcapng)."""
    from scapy.utils import PcapReader

    with PcapReader(str(path)) as reader:
        for count, _ in enumerate(reader):
            if count >= probe:
                break
        if isinstance(reader, PcapNgReader):
            return {int(interface[0]) for interface in reader.interfaces}
        return {int(reader.linktype)}


def _rewrite_to_ethernet(source: Path, destination: Path) -> int:
    """IP / IPv6 packets of any link layer, re-framed as Ethernet."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapReader, PcapWriter

    written = 0
    with PcapReader(str(source)) as reader, \
            PcapWriter(str(destination), linktype=1, sync=False) as writer:
        for packet in reader:
            layer = IP if IP in packet else IPv6 if IPv6 in packet else None
            if layer is None:
                continue
            framed = Ether() / packet[layer]
            framed.time = packet.time
            writer.write(framed)
            written += 1
    return written


def _prepare_input_file(
    evidence_file: Path,
    input_directory: Path
) -> Path:
    """
    Prepare an evidence file for CICFlowMeter.

    .pcap
        -> copied directly

    .pcapng
        -> converted to a derived classic-PCAP copy

    Original evidence is never modified.
    """

    evidence_file = (
        Path(evidence_file)
        .resolve()
    )

    if not evidence_file.exists():
        raise RuntimeError(
            "Evidence file does not exist:\n"
            f"{evidence_file}"
        )


    extension = (
        evidence_file
        .suffix
        .lower()
    )


    if extension not in {
        ".pcap",
        ".pcapng"
    }:
        raise RuntimeError(
            "Unsupported network capture format: "
            f"{extension}"
        )


    input_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    capture_format = _capture_format(
        evidence_file
    )

    link_types = _link_types(
        evidence_file
    )

    if not link_types <= CICFLOWMETER_LINK_TYPES:
        staged_file = (
            input_directory
            / (evidence_file.stem + "_ethernet.pcap")
        )
        print(
            f"[FORENXAI] Link type(s) {sorted(link_types)} are not "
            "readable by CICFlowMeter; writing an Ethernet "
            "working copy...",
            flush=True
        )
        written = _rewrite_to_ethernet(
            evidence_file,
            staged_file
        )
        print(
            f"[FORENXAI] {written} IP packets re-framed: "
            f"{staged_file}",
            flush=True
        )
        return staged_file

    extension = (
        ".pcapng"
        if capture_format == "pcapng"
        else ".pcap"
    )


    # --------------------------------------------------------
    # Classic PCAP
    # --------------------------------------------------------

    if extension == ".pcap":

        staged_file = (
            input_directory
            / evidence_file.name
        )

        shutil.copy2(
            evidence_file,
            staged_file
        )

        print(
            "[FORENXAI] PCAP staged for "
            "CICFlowMeter:",
            flush=True
        )

        print(
            f"[FORENXAI] {staged_file}",
            flush=True
        )

        return staged_file


    # --------------------------------------------------------
    # PCAPNG
    # --------------------------------------------------------

    working_name = (
        evidence_file.stem
        + "_for_cicflowmeter.pcap"
    )

    staged_file = (
        input_directory
        / working_name
    )


    return _convert_pcapng_to_pcap(
        evidence_file,
        staged_file
    )


# ============================================================
# BUILD NATIVE ENVIRONMENT
# ============================================================

def _java_major(java_home: Path) -> int:
    """Major version of a JDK, or 0 when it cannot be determined.

    Read from the JDK's own `release` file rather than by starting a JVM:
    it is a one-line read instead of a process launch, and it works the
    same on 8 (`JAVA_VERSION="1.8.0_452"`) and on 26 (`"26.0.1"`).
    """
    release = java_home / "release"

    if release.is_file():
        try:
            for line in release.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if not line.startswith("JAVA_VERSION="):
                    continue
                version = line.split("=", 1)[1].strip().strip('"')
                parts = version.split(".")
                if parts[0] == "1" and len(parts) > 1:
                    return int(parts[1])          # 1.8.0_452 -> 8
                return int(parts[0].split("-")[0])
        except (OSError, ValueError, IndexError):
            pass

    try:
        finished = subprocess.run(
            [str(java_home / "bin" / "java"), "-version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        blob = (finished.stderr or "") + (finished.stdout or "")
        found = re.search(r'version "(\d+)(?:\.(\d+))?', blob)
        if found:
            major = int(found.group(1))
            if major == 1 and found.group(2):
                return int(found.group(2))
            return major
    except (OSError, subprocess.SubprocessError, ValueError):
        pass

    return 0


def _build_environment() -> dict[str, str]:

    environment = os.environ.copy()

    # --------------------------------------------------------
    # Java toolchain
    #
    # CICFlowMeter compiles with source/target 1.8. JDK 24 removed
    # -source 8, so a current JDK fails the build before reading a
    # packet. A project-local JDK under tools/ is used when present,
    # and the machine's Java is left alone either way.
    # --------------------------------------------------------

    java_home = get_java_home()

    if java_home is not None:

        major = _java_major(java_home)

        if major >= 24:
            raise RuntimeError(
                "CICFlowMeter needs a JDK that still supports "
                f"-source 8, and the one selected is Java {major}:\n"
                f"{java_home}\n\n"
                "JDK 24 removed -source 8, so Maven will fail with "
                "\"Source option 8 is no longer supported\".\n\n"
                "Unpack a JDK 8 or 11 here and it will be used "
                "automatically, without changing the system Java:\n"
                f"{get_toolchain_directory() / 'jdk8'}\n\n"
                "Or point FORENXAI_JAVA_HOME at one."
            )

        environment["JAVA_HOME"] = str(java_home)

        environment["PATH"] = (
            str(java_home / "bin")
            + os.pathsep
            + environment.get("PATH", "")
        )

        print(
            f"[FORENXAI] Java: {java_home} "
            f"(major {major or 'unknown'})",
            flush=True
        )

    else:
        print(
            "[FORENXAI] Java: system default "
            "(no JDK under tools/, no JAVA_HOME)",
            flush=True
        )

    # --------------------------------------------------------
    # Verify required jNetPcap DLL
    # --------------------------------------------------------

    primary_dll = (
        JNETPCAP_NATIVE_DIR
        / "jnetpcap.dll"
    )

    if not primary_dll.exists():
        raise RuntimeError(
            "Required jNetPcap DLL was not found:\n"
            f"{primary_dll}"
        )

    # --------------------------------------------------------
    # Build native path list
    # --------------------------------------------------------

    native_directories = [
        directory
        for directory
        in JNETPCAP_NATIVE_CANDIDATES
        if directory.exists()
    ]

    if not native_directories:
        raise RuntimeError(
            "No native jNetPcap/Npcap "
            "directories were found."
        )

    native_path_string = os.pathsep.join(
        str(directory)
        for directory
        in native_directories
    )

    # --------------------------------------------------------
    # Windows DLL search path
    # --------------------------------------------------------

    existing_path = environment.get(
        "PATH",
        ""
    )

    environment["PATH"] = (
        native_path_string
        + os.pathsep
        + existing_path
    )

    # --------------------------------------------------------
    # Java native search path
    # --------------------------------------------------------

    environment["MAVEN_OPTS"] = (
        f'-Djava.library.path="{native_path_string}"'
    )

    # --------------------------------------------------------
    # Diagnostics
    # --------------------------------------------------------

    print(
        "[FORENXAI] Native library paths:",
        flush=True
    )

    for directory in native_directories:
        print(
            f"[FORENXAI]   {directory}",
            flush=True
        )

    print(
        "[FORENXAI] jnetpcap.dll:",
        flush=True
    )

    print(
        f"[FORENXAI]   {primary_dll}",
        flush=True
    )

    print(
        "[FORENXAI] jnetpcap.dll exists: "
        f"{primary_dll.exists()}",
        flush=True
    )

    print(
        "[FORENXAI] MAVEN_OPTS:",
        flush=True
    )

    print(
        f"[FORENXAI]   "
        f"{environment['MAVEN_OPTS']}",
        flush=True
    )

    return environment

# ============================================================
# LOCATE CICFLOWMETER CSV
# ============================================================

def _find_generated_csv(
    output_directory: Path,
    staged_capture: Path,
    maven_exit_code: int
) -> Path:
    """
    Locate the CSV generated by CICFlowMeter.

    CICFlowMeter normally uses:

        <input filename>_Flow.csv

    Example:

        test.pcap_Flow.csv

    However, different builds can vary slightly, so we use
    a safe fallback scan of the current output directory.
    """

    expected_csv = (
        output_directory
        / f"{staged_capture.name}_Flow.csv"
    )


    # --------------------------------------------------------
    # Exact expected filename
    # --------------------------------------------------------

    if (
        expected_csv.exists()
        and expected_csv.stat().st_size > 0
    ):
        return expected_csv


    # --------------------------------------------------------
    # Case-insensitive exact filename fallback
    # --------------------------------------------------------

    expected_lower = (
        expected_csv.name.lower()
    )


    for candidate in (
        output_directory.glob("*.csv")
    ):

        if (
            candidate.name.lower()
            == expected_lower
            and candidate.stat().st_size > 0
        ):
            return candidate


    # --------------------------------------------------------
    # CICFlowMeter-style CSV fallback
    # --------------------------------------------------------

    candidates = [
        item
        for item
        in output_directory.glob(
            "*_Flow.csv"
        )
        if (
            item.is_file()
            and item.stat().st_size > 0
        )
    ]


    if len(candidates) == 1:

        candidate = (
            candidates[0]
        )

        print(
            "[FORENXAI] Expected CSV name "
            "was not found exactly, but one "
            "valid CICFlowMeter CSV was detected:",
            flush=True
        )

        print(
            f"[FORENXAI] {candidate}",
            flush=True
        )

        return candidate


    # --------------------------------------------------------
    # Generic CSV fallback
    # --------------------------------------------------------

    all_csv_files = [
        item
        for item
        in output_directory.glob(
            "*.csv"
        )
        if (
            item.is_file()
            and item.stat().st_size > 0
        )
    ]


    if len(all_csv_files) == 1:

        candidate = (
            all_csv_files[0]
        )

        print(
            "[FORENXAI] Using the only "
            "non-empty CSV produced:",
            flush=True
        )

        print(
            f"[FORENXAI] {candidate}",
            flush=True
        )

        return candidate


    # --------------------------------------------------------
    # Nothing useful was generated
    # --------------------------------------------------------

    files_found = []

    if output_directory.exists():

        files_found = [
            f"{item.name} "
            f"({item.stat().st_size} bytes)"
            for item
            in output_directory.iterdir()
            if item.is_file()
        ]


    files_text = (
        "\n".join(files_found)
        if files_found
        else "(no files)"
    )


    raise RuntimeError(
        "CICFlowMeter did not create "
        "the expected CSV.\n\n"
        f"Maven exit code: "
        f"{maven_exit_code}\n\n"
        f"Input used by CICFlowMeter:\n"
        f"{staged_capture}\n\n"
        f"Expected CSV:\n"
        f"{expected_csv}\n\n"
        f"Files created in output folder:\n"
        f"{files_text}"
    )


# ============================================================
# RUN CICFLOWMETER
# ============================================================

def _run_cicflowmeter(
    staged_capture: Path,
    output_directory: Path
) -> tuple[Path, subprocess.CompletedProcess]:

    environment = (
        _build_environment()
    )


    # --------------------------------------------------------
    # Use paths relative to CICFlowMeter root where possible.
    # This matches the command format already proven to work
    # with this CICFlowMeter source build.
    # --------------------------------------------------------

    try:
        input_argument = str(
            staged_capture.relative_to(
                CICFLOWMETER_ROOT
            )
        )

    except ValueError:
        input_argument = str(
            staged_capture
        )


    try:
        output_argument = str(
            output_directory.relative_to(
                CICFLOWMETER_ROOT
            )
        )

    except ValueError:
        output_argument = str(
            output_directory
        )


    # --------------------------------------------------------
    # Maven command
    # --------------------------------------------------------

    command = [
        str(MAVEN_EXECUTABLE),

        "exec:java",

        "-Dexec.mainClass=cic.cs.unb.ca.ifm.Cmd",

        (
            "-Dexec.args="
            f'"{input_argument}" '
            f'"{output_argument}"'
        ),
    ]


    print(
        "[FORENXAI] Running CICFlowMeter...",
        flush=True
    )

    print(
        f"[FORENXAI] CICFlowMeter input: "
        f"{staged_capture}",
        flush=True
    )

    print(
        f"[FORENXAI] CICFlowMeter output: "
        f"{output_directory}",
        flush=True
    )


    try:
        result = subprocess.run(
            command,
            cwd=str(
                CICFLOWMETER_ROOT
            ),
            env=environment,
            capture_output=True,
            text=True,
            timeout=600,
            check=False
        )

    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "CICFlowMeter timed out after "
            "10 minutes."
        ) from error

    except OSError as error:
        raise RuntimeError(
            "Could not start Maven / "
            "CICFlowMeter.\n"
            f"{error}"
        ) from error


    # --------------------------------------------------------
    # Show CICFlowMeter output in Uvicorn terminal
    # --------------------------------------------------------

    if result.stdout:
        print(
            result.stdout,
            flush=True
        )


    if result.stderr:
        print(
            result.stderr,
            flush=True
        )


    print(
        f"[FORENXAI] Maven exit code: "
        f"{result.returncode}",
        flush=True
    )


    # --------------------------------------------------------
    # IMPORTANT
    #
    # The current CICFlowMeter build can throw a jNetPcap
    # cleanup error AFTER successfully writing its CSV.
    #
    # Therefore:
    #
    #     CSV exists + non-empty = usable result
    #
    # even if Maven later returns a non-zero code.
    # --------------------------------------------------------

    generated_csv = (
        _find_generated_csv(
            output_directory,
            staged_capture,
            result.returncode
        )
    )


    if result.returncode != 0:

        print(
            "[FORENXAI] WARNING: Maven returned "
            "a non-zero exit code, but "
            "CICFlowMeter produced a valid CSV.",
            flush=True
        )

        print(
            "[FORENXAI] Continuing with "
            "the generated CSV.",
            flush=True
        )


    return (
        generated_csv,
        result
    )


# ============================================================
# PUBLIC SERVICE FUNCTION
# ============================================================

def _describe_capture(capture: Path) -> str:
    """A one-paragraph account of what is actually in a capture.

    Only called when nothing usable came out of it, so the cost of
    reading the file a second time buys a message the analyst can act
    on.
    """
    try:
        from scapy.all import rdpcap                  # noqa: PLC0415
        packets = rdpcap(str(capture))
    except Exception as error:                        # noqa: BLE001
        return (
            f"The capture could not be re-read for diagnosis "
            f"({type(error).__name__}: {error})."
        )

    total = len(packets)

    if total == 0:
        return "The capture contains no packets at all."

    # Flow key as CICFlowMeter forms it, so the count below is the
    # number of flows it would have considered.
    conversations: dict = {}
    transport = 0

    for packet in packets:
        try:
            layer = packet.payload.payload
            name = layer.__class__.__name__
            if name not in ("TCP", "UDP"):
                continue
            network = packet.payload
            key = tuple(sorted([
                (str(network.src), int(layer.sport)),
                (str(network.dst), int(layer.dport)),
            ])) + (name,)
            conversations[key] = conversations.get(key, 0) + 1
            transport += 1
        except (AttributeError, ValueError, TypeError):
            continue

    usable = sum(
        1 for count in conversations.values() if count > 1
    )

    summary = (
        f"The capture holds {total} packet"
        f"{'' if total == 1 else 's'}, "
        f"{transport} of them TCP or UDP, forming "
        f"{len(conversations)} conversation"
        f"{'' if len(conversations) == 1 else 's'}, "
        f"of which {usable} have more than one packet."
    )

    if total <= 2:
        summary += (
            f" A capture this small cannot produce a flow: "
            f"the first packet of the file is "
            f"{packets[0].summary()}."
        )

    return summary


def _require_flow_rows(
    csv_path: Path,
    staged_capture: Path
) -> None:
    """Fail with the reason when CICFlowMeter wrote a header and no flows.

    CICFlowMeter discards any flow of fewer than two packets, so a
    capture of one packet -- a lone RST, a single beacon, a truncated
    export -- yields the 84-column header and nothing beneath it. That
    file is non-empty, so every size check passes and the failure only
    surfaces later, in the classifier, as "produced no flow rows".
    """
    try:
        with csv_path.open(
            "r", encoding="utf-8", errors="replace"
        ) as handle:
            header = handle.readline()
            for line in handle:
                if line.strip():
                    return                            # at least one flow
    except OSError as error:
        raise ValueError(
            f"The CICFlowMeter CSV could not be read:\n"
            f"{csv_path}\n{error}"
        ) from error

    columns = len(header.split(",")) if header else 0

    raise ValueError(
        "CICFlowMeter produced no flows from this capture.\n\n"
        f"{_describe_capture(staged_capture)}\n\n"
        "CICFlowMeter discards any flow of fewer than two packets, so "
        "a capture needs at least one conversation with a packet in "
        "reply -- a request and its response, or two packets of the "
        "same TCP connection. A single packet, however valid, produces "
        "no row.\n\n"
        f"Capture analysed: {staged_capture}\n"
        f"CSV written:      {csv_path} "
        f"({columns} columns, no data rows)"
    )


def generate_flow_csv(
    evidence_file: Path | str,
    case_id: str
) -> Path:
    """
    Generate CICFlowMeter flow features for a FORENXAI case.

    Supported evidence formats:

        .pcap
        .pcapng

    PCAPNG handling:

        Original .pcapng
              ↓
        derived .pcap copy
              ↓
        CICFlowMeter
              ↓
        flow CSV

    The original evidence is never modified.

    Returns:
        Path to the final CSV stored inside:

            backend/cases/<CASE_ID>/flows/
    """

    _validate_configuration()


    evidence_file = Path(
        evidence_file
    ).resolve()


    if not evidence_file.exists():
        raise RuntimeError(
            "Cannot run CICFlowMeter because "
            "the evidence file was not found:\n"
            f"{evidence_file}"
        )


    print(
        "\n"
        "==============================",
        flush=True
    )

    print(
        "[FORENXAI] CICFLOWMETER STARTED",
        flush=True
    )

    print(
        f"[FORENXAI] Case ID: "
        f"{case_id}",
        flush=True
    )

    print(
        f"[FORENXAI] Original evidence: "
        f"{evidence_file}",
        flush=True
    )


    # ========================================================
    # Case directories
    # ========================================================

    case_directory = (
        _case_directory(
            case_id
        )
    )


    if not case_directory.exists():
        raise RuntimeError(
            "Case directory does not exist:\n"
            f"{case_directory}"
        )


    final_flow_directory = (
        case_directory
        / "flows"
    )


    final_flow_directory.mkdir(
        parents=True,
        exist_ok=True
    )


    # ========================================================
    # CICFlowMeter temporary working directories
    # ========================================================

    staging_root = (
        CICFLOWMETER_ROOT
        / "data"
        / "forenxai"
        / case_id
    )


    input_directory = (
        staging_root
        / "in"
    )


    output_directory = (
        staging_root
        / "out"
    )


    # Start clean so stale CSVs cannot be reused.
    _reset_directory(
        input_directory
    )


    _reset_directory(
        output_directory
    )


    # ========================================================
    # Stage / convert evidence
    # ========================================================

    staged_capture = (
        _prepare_input_file(
            evidence_file,
            input_directory
        )
    )


    # ========================================================
    # CICFlowMeter
    # ========================================================

    generated_csv, result = (
        _run_cicflowmeter(
            staged_capture,
            output_directory
        )
    )


    if not generated_csv.exists():
        raise RuntimeError(
            "Internal error: CICFlowMeter CSV "
            "was located but no longer exists."
        )


    if generated_csv.stat().st_size <= 0:
        raise RuntimeError(
            "CICFlowMeter generated an "
            "empty CSV."
        )


    # ========================================================
    # Copy CSV into FORENXAI case
    # ========================================================
    #
    # Keep the final artifact associated with the ORIGINAL
    # evidence filename, not the temporary converted filename.
    #
    # Examples:
    #
    #   test.pcap
    #       -> test.pcap_Flow.csv
    #
    #   capture.pcapng
    #       -> capture.pcapng_Flow.csv
    #
    # ========================================================

    final_csv = (
        final_flow_directory
        / (
            evidence_file.name
            + "_Flow.csv"
        )
    )


    shutil.copy2(
        generated_csv,
        final_csv
    )


    if not final_csv.exists():
        raise RuntimeError(
            "CICFlowMeter CSV could not be "
            "copied into the case folder."
        )


    if final_csv.stat().st_size <= 0:
        raise RuntimeError(
            "Final CICFlowMeter CSV is empty."
        )


    # ========================================================
    # Finished
    # ========================================================

    print(
        "[FORENXAI] CICFlowMeter CSV created:",
        flush=True
    )

    print(
        f"[FORENXAI] {final_csv}",
        flush=True
    )

    print(
        f"[FORENXAI] CSV size: "
        f"{final_csv.stat().st_size} bytes",
        flush=True
    )


    if (
        evidence_file.suffix.lower()
        == ".pcapng"
    ):
        print(
            "[FORENXAI] NOTE: Original PCAPNG "
            "evidence was preserved unchanged.",
            flush=True
        )

        print(
            "[FORENXAI] CICFlowMeter used a "
            "derived PCAP working copy.",
            flush=True
        )


    print(
        "[FORENXAI] CICFLOWMETER COMPLETE",
        flush=True
    )

    print(
        "==============================\n",
        flush=True
    )


    # --------------------------------------------------------
    # A header-only CSV is not a usable result
    #
    # CICFlowMeter writes the 84-column header before it knows
    # whether any flow will survive, so a file with bytes in it
    # is not proof of a flow. Checking here means the analyst is
    # told what was wrong with the capture, instead of meeting
    # "produced no flow rows" from the classifier two steps
    # later with nothing to act on.
    # --------------------------------------------------------

    _require_flow_rows(
        final_csv,
        staged_capture
    )


    return final_csv