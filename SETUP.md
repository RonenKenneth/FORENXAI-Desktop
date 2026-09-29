# FORENXAI setup

How to install and run FORENXAI on a new Windows machine, from clone to first analysis. Tested on Windows 11 64-bit, branch `merge-main-forenxai-v3`.

FORENXAI has two processes:
- a Python backend (FastAPI on `http://127.0.0.1:8000`) that reads the capture and runs CICFlowMeter, the XGBoost model, TreeSHAP, the rules, Suricata and the local language model;
- a WPF desktop app (.NET 10) that talks to it over HTTP.

## 1. Software to install

| Software | Version tested | Used for | Install |
|---|---|---|---|
| Git | any | cloning | https://git-scm.com |
| Python | **3.11** (3.11.9) | backend | https://www.python.org/downloads/windows/ (tick "Add python.exe to PATH") |
| .NET SDK | **10** | desktop app (`net10.0-windows`) | `winget install Microsoft.DotNet.SDK.10` |
| JDK | **8** (11 also works; 24+ does not) | CICFlowMeter | Temurin 8 ZIP unpacked into `tools\jdk8\` (see `tools\README.md`) |
| Apache Maven | 3.9.16 | runs CICFlowMeter | ZIP unpacked to `C:\Tools\apache-maven-3.9.16-bin\` |
| CICFlowMeter | v4 (`CICFlowMeter-master`) | flow records (the model's 66 features) | https://github.com/ahlashkari/CICFlowMeter, unpacked to `C:\Tools\CICFlowMeter\CICFlowMeter-master\` |
| Wireshark | any 4.x | `editcap` converts PCAPng to PCAP for CICFlowMeter | `winget install WiresharkFoundation.Wireshark` |
| Npcap | any | packet library for CICFlowMeter and Suricata | https://npcap.com, **as Administrator**, tick "WinPcap API-compatible Mode" |
| Suricata | 7.0.10 | Tier 2 signatures | `winget install --id OISF.Suricata --exact` |

The paths above are defaults, not requirements. `runtime_paths.find_tool` looks for each tool in this order: its environment variable (section 7), then the project `tools\` folder (`tools\CICFlowMeter\CICFlowMeter-master`, `tools\apache-maven-*\bin\mvn.cmd`, `tools\wireshark\editcap.exe`, `tools\suricata\suricata.exe`), then the default location above, then `PATH`. No code change is needed when the tools are installed elsewhere.

Check the installation:

```powershell
python --version                 # Python 3.11.x
dotnet --version                 # 10.x
dir C:\Windows\System32\wpcap.dll   # Npcap present
& "C:\Program Files\Wireshark\editcap.exe" -V
& "C:\Program Files\Suricata\suricata.exe" -V
```

## 2. Clone

```powershell
git clone https://github.com/RonenKenneth/FORENXAI-Desktop.git
cd FORENXAI-Desktop
git checkout merge-main-forenxai-v3
```

## 3. Backend: virtual environment and requirements

Create the virtual environment inside `backend\`. It is ignored by Git.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install --upgrade pip
pip install -r requirements.txt
```

- `requirements.txt` pins every package the backend runs on (FastAPI, pandas, NumPy, scapy, XGBoost 3.2.0, scikit-learn 1.9.0, SHAP 0.51.0, llama-cpp-python, pypdf).
- Keep scikit-learn at 1.9.x and XGBoost at 3.2.x. The model bundle's pickles were written by these versions.
- **llama-cpp-python** compiles from source on Windows unless a prebuilt wheel is found. If `pip` fails on it, install the CPU wheel first, then rerun the requirements:

  ```powershell
  pip install llama-cpp-python==0.3.19 --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
  pip install -r requirements.txt
  ```

  The development machine runs 0.3.19.

## 4. Files that are not in Git

| File | Put it at | Notes |
|---|---|---|
| Language model | `backend\models\llm\qwen2.5-3b-q4.gguf` | Qwen2.5-3B-Instruct, Q4_K_M GGUF (about 1.9 GB). Get the team's copy; `python verify_bundle.py --llm` checks its SHA-256 (starts `5ee4f07cdb9beadb`). |
| JDK 8 | `tools\jdk8\` | see `tools\README.md` |
| Suricata rules | `tools\suricata\et-open.rules` | `python update_suricata_rules.py` (in `backend\`, venv active) downloads ET Open and the other free rulesets |

The XGBoost bundle (`backend\models\forenxai\`) is in Git. The backend checks each file against `manifest.json` (SHA-256) before loading it.

## 5. Check the backend

With the venv active, in `backend\`:

```powershell
python verify_bundle.py          # bundle hashes, held-out accuracy, SHAP additivity: ALL CHECKS PASSED
python run_tests.py              # 9 suites: model, Tier 1, Tier 2, packet parsing, cases, RAG, AI summary, recommendations
```

`run_tests.py` needs the language model for its RAG and summary suites and takes a few minutes.

## 6. Run

Two terminals:

```powershell
# Terminal 1: backend (restarts itself if it stops)
cd backend
$env:FORENXAI_DATA_DIR = "$env:LOCALAPPDATA\FORENXAI"   # same case folder as the app; required when run from source
.\.venv\Scripts\python.exe run_backend.py --supervise
# check: http://127.0.0.1:8000/health returns {"status":"healthy"}

# Terminal 2: desktop app
cd frontend\FORENXAI.Desktop
dotnet run -c Release
```

In the app:
1. Open **Evidence** and choose a `.pcap` or `.pcapng` file (100 MB limit).
2. Start the analysis and wait for the progress window to finish.
3. **View Results** opens the Dashboard; the XAI and Reports tabs then show the same case.

Cases are stored in `%LOCALAPPDATA%\FORENXAI\cases\<case id>\` (`evidence\` with a copy of the capture, `flows\`, `suricata\`, `analysis.json`, `packets.json`, reviews). A case is deleted in one of three ways:
- **Delete Case** in the Cases tab removes it immediately.
- **Schedule Deletion** removes it automatically at a chosen date and time. This is stored in `retention.json` and carried out by the backend, or at the next start if the app was closed at that time.
- **The exit dialog** offers to delete the cases created in that session.

## 7. Optional settings (environment variables)

| Variable | Effect |
|---|---|
| `FORENXAI_DATA_DIR` | Folder for cases and logs. The app uses `%LOCALAPPDATA%\FORENXAI` by default, but a backend run from source uses `backend\cases` unless this is set, and the analysis then fails with "Case directory not found". Set it to the same folder for both. |
| `FORENXAI_JAVA_HOME` | Use this JDK for CICFlowMeter instead of `tools\jdk*` or `JAVA_HOME`. |
| `FORENXAI_SURICATA` | Path to `suricata.exe` if it is not in `tools\suricata\` or `C:\Program Files\Suricata\`. |
| `FORENXAI_CICFLOWMETER_DIR` | CICFlowMeter checkout (the folder holding `pom.xml`). |
| `FORENXAI_MAVEN` | Path to `mvn.cmd`. |
| `FORENXAI_EDITCAP` | Path to `editcap.exe`. |
| `FORENXAI_TOOLS_DIR` | Use this folder instead of `tools\` for all of the above and the JDK. |
| `FORENXAI_MODEL_DIR` | XGBoost bundle folder, instead of `backend\models\forenxai` or the copy inside the .exe. |
| `FORENXAI_RAG_DIR` | Retrieval assets folder, instead of `backend\rag` or `..\rag`. |
| `FORENXAI_BACKEND_EXE` | (desktop app) Path to `FORENXAI.Backend.exe` if it is not in `backend\` beside the app. |
| `FORENXAI_PRELOAD_LLM` | Load the language model at startup instead of on first use. |

Rule thresholds, sensitivity and the allowlist are in `backend\app\rules\rules.json`. Each rule has a `basis` saying where its threshold comes from.

## 8. Training pipeline (optional)

The code that trained the model is in `training\`. It is not needed to run the app. It uses its own virtual environment, because it needs PyTorch:

```powershell
cd training
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_pipeline.py --help     # --quick for a short run
```

The datasets (CSE-CIC-IDS2018, TII-SSRC-23, TRUSTLab; about 13 GB) are not in Git. Put them under `training\data\raw\` (`CICIDS2018\<day>.csv`, `TII-SSRC-23\data.csv`, `TRUSTLab\<class>\`), as set in `training\config\settings.py`.

## 9. Common problems

| Symptom | Fix |
|---|---|
| "Case directory not found" when analysing | The backend was started without `FORENXAI_DATA_DIR` (section 6). |
| `Port 8000 is already in use` | Another backend is running: `Get-NetTCPConnection -LocalPort 8000` and stop that process. |
| `UnsatisfiedLinkError ... dlopen` from CICFlowMeter | Npcap missing or installed without WinPcap API-compatible mode. |
| `Source option 8 is no longer supported` | Maven is using JDK 24+. Unpack JDK 8 into `tools\jdk8\`. |
| `editcap.exe was not found` | Install Wireshark, or set `FORENXAI_EDITCAP`. |
| `CICFlowMeter directory was not found` / `Maven executable was not found` | Put them under `tools\` or set `FORENXAI_CICFLOWMETER_DIR` / `FORENXAI_MAVEN` (section 1). |
| Tier 2 says "Suricata not run" | Install Suricata or set `FORENXAI_SURICATA`; run `update_suricata_rules.py`. |
| `Model artifact size or hash mismatch` | A bundle file changed (for example Git line endings). Re-checkout `backend\models\forenxai\`. |
| Build error "the file is locked" | Close the running app (`FORENXAI.Desktop.exe`) before `dotnet build`. |

## 10. Packaging as .exe

The backend becomes one `FORENXAI.Backend.exe` (PyInstaller, `backend\FORENXAI.Backend.spec`). The desktop app starts it from a `backend\` folder beside `FORENXAI.Desktop.exe`.

```powershell
# Backend (venv active, in backend\)
pip install pyinstaller
pyinstaller FORENXAI.Backend.spec --noconfirm     # dist\FORENXAI.Backend.exe

# Desktop app (in frontend\FORENXAI.Desktop\)
dotnet publish -c Release -r win-x64 --self-contained true -o ..\..\publish
```

Inside the .exe: the Python runtime and packages (FastAPI, uvicorn, scapy, XGBoost, SHAP, scikit-learn, pandas, NumPy, llama-cpp, pypdf), the `app` package, `app\rules\` (rules.json, rules_tuning.json) and the XGBoost bundle `models\forenxai\`.

Beside it, because they are large or are separate programs:

```
publish\
  FORENXAI.Desktop.exe
  backend\
    FORENXAI.Backend.exe
    models\llm\qwen2.5-3b-q4.gguf        language model (section 4)
    rag\config\  rag\knowledge\  rag\.rag_index.json  rag\_sources\  rag\_extracted\
    tools\
      jdk8\                              JDK 8 (or jdk.path naming one)
      CICFlowMeter\CICFlowMeter-master\  with jnetpcap\win\jnetpcap-1.4.r1425\
      apache-maven-3.9.16\bin\mvn.cmd
      suricata\et-open.rules             (suricata.exe here, or installed)
```

Every one of these is found relative to the .exe (`backend\app\utils\runtime_paths.py`), or through the variables in section 7. Nothing points at the build machine. Cases and logs go to `%LOCALAPPDATA%\FORENXAI`.

The target machine still needs **Npcap** (WinPcap-compatible mode) and **Wireshark** (for editcap), because they install drivers or system DLLs. Suricata can be installed or placed in `tools\suricata\`.

Two things to know:
- CICFlowMeter runs through Maven, which downloads its dependencies into `%USERPROFILE%\.m2` on the first analysis. That first run needs internet. For an offline machine, run one analysis on a connected machine and copy `.m2\repository`.
- CICFlowMeter writes its temporary files and `target\` build into its own folder, so install the package in a folder the user can write to (for example `%LOCALAPPDATA%\Programs\FORENXAI`), not `C:\Program Files`.