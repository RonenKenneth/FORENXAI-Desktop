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

The paths above are the ones `backend\app\services\cicflowmeter_service.py` expects (`C:\Tools\...`, `C:\Program Files\Wireshark\editcap.exe`). If you install elsewhere, change the constants at the top of that file.

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
python run_tests.py              # 8 suites: model, Tier 1, Tier 2, packet parsing, RAG, AI summary, recommendations
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

Cases are stored in `%LOCALAPPDATA%\FORENXAI\cases\<case id>\` (`evidence\`, `flows\`, `analysis.json`, `packets.json`, reports).

## 7. Optional settings (environment variables)

| Variable | Effect |
|---|---|
| `FORENXAI_DATA_DIR` | Folder for cases and logs. The app uses `%LOCALAPPDATA%\FORENXAI` by default, but a backend run from source uses `backend\cases` unless this is set, and the analysis then fails with "Case directory not found". Set it to the same folder for both. |
| `FORENXAI_JAVA_HOME` | Use this JDK for CICFlowMeter instead of `tools\jdk*` or `JAVA_HOME`. |
| `FORENXAI_SURICATA` | Path to `suricata.exe` if it is not in `C:\Program Files\Suricata\`. |
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
| `editcap.exe was not found` | Install Wireshark to its default folder. |
| Tier 2 says "Suricata not run" | Install Suricata or set `FORENXAI_SURICATA`; run `update_suricata_rules.py`. |
| `Model artifact size or hash mismatch` | A bundle file changed (for example Git line endings). Re-checkout `backend\models\forenxai\`. |
| Build error "the file is locked" | Close the running app (`FORENXAI.Desktop.exe`) before `dotnet build`. |
