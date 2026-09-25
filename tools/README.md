# tools/

Project-local third-party tools. Nothing here is committed — see the
`.gitignore` entry — and nothing here changes the machine.

## Why a JDK lives here and not in `.venv`

`.venv` is a **Python** virtual environment. pip manages it, it has no concept
of a JVM, and it is rebuilt from `requirements.txt` whenever the environment is
recreated — a JDK placed inside it would be deleted on the next rebuild and
would still need its path wired up by hand. So it goes here instead, beside
`backend/`, `frontend/` and `rag/`.

The effect is the same one you were after: the JDK is temporary, scoped to this
project, and the system Java is left exactly as it is.

## Why CICFlowMeter needs its own JDK

`C:\Tools\CICFlowMeter\CICFlowMeter-master\pom.xml` compiles with:

```xml
<source>1.8</source>
<target>1.8</target>
```

**JDK 24 removed `-source 8`.** On a current JDK, Maven stops with
*"Source option 8 is no longer supported. Use 11 or later"* before a single
packet is read. jNetPcap 1.4 dates from 2012 and is likewise happiest on the
JVM it was built against.

`backend/app/services/cicflowmeter_service.py` refuses to launch Maven on a JDK
of 24 or newer and tells you to unpack one here.

## Installing the JDK

1. Download a **JDK 8 (x64, Windows) ZIP** — not the `.msi` installer, which
   would register itself system-wide and defeat the point:

   https://adoptium.net/temurin/releases/?version=8&os=windows&arch=x64&package=jdk

   Pick the file ending `.zip`. JDK 11 also works if 8 is awkward to obtain.

2. Unpack it into this folder as `jdk8`, so that this path exists:

   ```
   tools\jdk8\bin\java.exe
   ```

   A nested layout also works — the resolver looks one level down, so
   `tools\jdk8\jdk8u452-b09\bin\java.exe` is found too. Unpack it and leave it
   alone.

3. Restart the backend. It will print which JVM it chose:

   ```
   [FORENXAI] Java: ...\tools\jdk8\jdk8u452-b09 (major 8)
   ```

## How it is resolved

`get_java_home()` in `backend/app/utils/runtime_paths.py`, first hit wins:

| Order | Source |
|---|---|
| 1 | `FORENXAI_JAVA_HOME` — explicit override, any path |
| 2 | `tools/jdk*` containing `bin/java.exe` — this folder |
| 3 | `JAVA_HOME` — whatever the machine uses |
| 4 | none — falls back to `java` on `PATH` |

Only the CICFlowMeter subprocess sees it. `JAVA_HOME` and `PATH` are set on the
environment handed to Maven; the parent process and the rest of the machine are
untouched.

## Also required: Npcap

Separate from the JDK, and not optional. `jnetpcap.dll` imports `wpcap.dll`,
which only exists once Npcap is installed. Without it the JVM throws:

```
java.lang.UnsatisfiedLinkError:
com.slytechs.library.NativeLibrary.dlopen(Ljava/lang/String;)J
```

Install from https://npcap.com/#download **as Administrator**, and tick
**"Install Npcap in WinPcap API-compatible Mode"** — jNetPcap 1.4 only knows
the WinPcap API, so without that box `wpcap.dll` still will not resolve.

Check it took:

```
dir C:\Windows\System32\wpcap.dll C:\Windows\System32\Packet.dll
```

Wireshark being installed is not sufficient: it can be installed with the Npcap
component unticked, which is the state this machine was in.

## Suricata (Tier 2 signatures)

Suricata itself is installed system-wide, not here:

    winget install --id OISF.Suricata --exact

(needs Npcap, which Wireshark already installs, and one UAC prompt). The
backend finds `C:\Program Files\Suricata\suricata.exe`, or the path in the
`FORENXAI_SURICATA` environment variable, or `binary` in `rules.json`.

The Emerging Threats Open signatures live here, because Program Files is not
writable without admin rights:

    cd backend
    python update_suricata_rules.py          # writes tools/suricata/et-open.rules

Rerun it to refresh the signatures. Without the file Suricata falls back to
the protocol-event rules in its own suricata.yaml; without Suricata the case
records "Suricata not run" and the scapy checks still run.
