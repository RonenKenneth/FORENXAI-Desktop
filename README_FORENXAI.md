# FORENXAI

FORENXAI is a Windows desktop application for post-incident network forensic analysis. It accepts PCAP/PCAPNG evidence, extracts flow-level features with CICFlowMeter, classifies network traffic with an XGBoost model, explains model decisions with TreeSHAP, generates grounded local narration with Qwen 2.5 3B, provides deterministic recommendations, supports investigator review, and produces case reports.

## Branch `merge-main-forenxai-v3`: what was merged and added

This branch combines three lines of work into one application. Merge order,
27 Sep 2026:

1. `main` of RonenKenneth/FORENXAI-Desktop, up to `322bb41`
2. `main` of codexnii0/ForenXAI-v3, up to `f4f28ed` (merge commit `6bdbdbf`)
3. `finetuned-xgboost` (merge commit `1f3e892`), then a traffic-summary fix (`68e5f35`)

### What each source contributed

| Source | Added |
|---|---|
| `main` (Ronen Kenneth) | Production error handling and logging (`backend/app/services/logging_service.py`, logs under the data directory); warning for an empty PCAP / PCAPng; Dashboard traffic-classification donut chart by attack category; Dashboard scrolling and threat-table layout; backend process management in the desktop app |
| ForenXAI-v3 (codexnii0) | Analysis progress pop-up with a live elapsed-time display (in the app, not the terminal); PCAP / PCAPng file metadata; Investigation view (packet list, including ARP; since emptied, see below); PCAPng reader fix; CICFlowMeter fixes (input directory, compile step, error diagnostics) |
| `finetuned-xgboost` | Tuned 66-feature XGBoost bundle with an abstain layer (confidence thresholds + Mahalanobis out-of-distribution limit); Tier 1 flow rules and Tier 2 packet rules with Suricata; hybrid `decide()` verdict; retrieval-grounded recommendations and AI summary (22 cited sources); capture intake for any link layer; Dashboard rule-based detection panel and Rule / Verdict columns; XAI view evidence. Full detail: `README_finetuned-xgboost.md` |

### How conflicts were resolved

| File | Result |
|---|---|
| `backend/app/main.py` | `main`'s logging lifespan plus the RAG warm-up and RAG status in `/health` |
| `backend/app/services/llm_provider.py` | Tunable Qwen threads, context and GPU offload inside `main`'s load logging |
| `backend/app/services/narration_service.py` | `finetuned-xgboost`'s fact-restating AI summary |
| `backend/app/services/model_service.py` | Abstain layer before `main`'s logged model loader |
| `backend/app/services/cicflowmeter_service.py` | v3's CICFlowMeter fixes and `finetuned-xgboost`'s capture checks inside `_generate_flow_csv_impl()`, wrapped by `main`'s logged `generate_flow_csv()` |
| `backend/app/utils/runtime_paths.py` | Both sets of helpers (data and logs; RAG and toolchain) |
| `frontend/.../Views/DashboardView.xaml` (`.cs`) | `main`/v3 layout (donut chart, metadata, scrolling) plus the rule-based detection panel as its own row and Rule / Verdict columns |
| `backend/app/analysis/traffic_analysis.py` | Fix after merge: top-IP lists count IP packets only, because v3 now keeps ARP frames (with MAC addresses) in the packet list |

### Detection: the two rule tiers and their rule sources

| Tier | Reads | Rules | Source of the rules |
|---|---|---|---|
| Machine learning | CICFlowMeter flow records (66 features) | Tuned XGBoost, 16 classes, with abstention | Trained on TRUSTLab |
| **Tier 1** (flow rules) | CICFlowMeter flow records, 60-second windows | PortScan, DoS, DDoS (off), Slowloris, Bruteforce, C2Beaconing, Exfiltration, DNS amplification, TLS failures, oversized packets (off), allowlist | Behavioural definitions used by signature IDSs (Snort, Zeek); thresholds tuned on TII-SSRC-23 and CSE-CIC-IDS2018 (`backend/app/rules/rules.json`, `rules_tuning.json`). Suricata cannot run here: it reads packets, not flow records |
| **Tier 2** (packet evidence, advisory) | The PCAP / PCAPng itself | **Suricata 7.0.10 with the Emerging Threats (ET) Open ruleset** (52,483 signatures), plus Positive Technologies Attack Detection, Nmap scan rules and Suricata's own decoder / stream / HTTP / DNS / TLS / SMTP / app-layer event rules: 52,964 signatures in `tools/suricata/et-open.rules`. Alerts are mapped to the 16 classes by `suricata.class_mapping` in `rules.json`. Alongside Suricata, scapy checks cover what signatures cannot: ARP / IPv6 / DHCP spoofing (MITM), illegal TCP flags, overlapping fragments and TTL changes (Evasion), failed-login replies, API bursts, DNS tunnelling, weak TLS versions, NOP sleds | ET Open (Proofpoint), PT Attack Detection, aleksibovellan/nmap, OISF event rules, all free and listed in the OISF ruleset index |

Verified on this branch: Suricata loads 52,956 of the 52,964 signatures and
maps 30 alerts on LabActivity2 (a port scan) to classes; checksum-offload
alerts are ignored. Only PortScan and DoS (Tier 1, validated on held-out
data, F1 0.98 and 0.96) may decide a verdict; Tier 2 is supporting evidence.

### Setup added by this branch

Besides the steps below, install:

```
winget install --id OISF.Suricata --exact          # Tier 2 signature engine (needs Npcap, installed with Wireshark)
cd backend
.venv\Scripts\pip install -r requirements.txt      # includes scapy, llama-cpp-python, pypdf
.venv\Scripts\python update_suricata_rules.py      # writes tools/suricata/et-open.rules (git-ignored)
python ..\rag\config\rag_index.py                  # after copying the 22 source documents into rag/_sources/
```

Place `qwen2.5-3b-q4.gguf` in `backend/models/llm/`. Without Suricata the
analysis still runs and records "Suricata not run".

### Changes after the merge (UI test round, 27 Sep 2026)

Found while running the merged app end to end and fixed on this branch:

| Area | Change | Files |
|---|---|---|
| Evidence tab | Wording "PCAP / PCAPng" in the heading and the Browse button; "Maximum size: 100 MB" under the heading; larger captures are refused with a message suggesting `editcap -c` to split them. The 100 MB cap is a chosen value, not a measured one (one constant, `MaxEvidenceMegabytes`) | `Views/EvidenceView.xaml(.cs)` |
| Progress pop-up | Shows the backend's current step (reading packets, CICFlowMeter, XGBoost, TreeSHAP, Tier 1 / Tier 2 rules, Qwen recommendations, saving), polled every 2 s from the new `GET /analysis/{case_id}/progress`. The X button now closes the pop-up and unlocks the app while the analysis continues; the Evidence status line keeps the current step. Browse is blocked while an analysis runs | `backend/app/api/analysis.py`, `Services/BackendApiService.cs`, `Views/EvidenceView.xaml.cs` |
| Investigation tab | Contents removed; the page shows "Coming soon." The v3 packet list is no longer shown | `Views/InvestigationView.xaml(.cs)`, `MainWindow.xaml.cs` |
| Dashboard, rule panel | Tier 1, Tier 2 and Hybrid verdict cards have equal widths; the Tier 2 card shows one summary line, and the full Suricata / capture-level evidence moved to a collapsible "Show Tier 2 rule evidence" panel below the cards | `Views/DashboardView.xaml(.cs)` |
| Dashboard, layout | Traffic classification and Selected threat side by side (equal halves); Detected threats and Top SHAP contributors at full width so IP addresses and feature names are not cut off; proportional column widths; SHAP values to 4 decimals; selected row shown in blue (was a white cell) | `Views/DashboardView.xaml(.cs)` |
| Dashboard, Selected threat | Redundant OPEN XAI button removed; the card now shows flow, confidence, verdict, source, destination and explanation. Double-click a row in Detected threats to open it in XAI | `Views/DashboardView.xaml(.cs)` |
| XAI tab | Right panel content kept clear of its scrollbar (the Confidence value was under it); inner scroll areas have a gutter; SHAP table fits without a second scrollbar, values to 4 decimals, text centred in rows | `Views/XaiView.xaml` |
| Dashboard, second round | Top row: Traffic classification (ML attack types; benign counted in the subtitle, not charted) beside Rule-based detected attacks (attack types backed by a Tier 1 / Tier 2 rule, with the tier). Rule panel's third card: Hybrid source as one stacked line (rule / model / uncertain, with counts and meanings). "Rule Hit" column removed; "Supporting Evidence" names the class and the rule tier. Detected threats gain Time, Protocol, Length and Info (per connection, from the packets) and filters (protocol, ML prediction, text). The Selected threat card and SHAP table were replaced by a filterable, scrollable Packets table (all parsed packets). Double-click a threat to open it in XAI | `Views/DashboardView.xaml(.cs)`, `Models/AnalysisModels.cs` |
| Reports, XAI, Evidence, pop-up | Reports label ML results ("ML Prediction", "ML Confidence", "ML Benign", "ML Threats") and add Supporting Evidence; MITRE ATT&CK IDs removed from the XAI recommendation text (unreviewed static map, not used in detection); Evidence wording "Select a network capture…", "PCAP or PCAPng • up to 100 MB", "BROWSE FILE"; the progress pop-up has a working minimize button (minimized: app usable; restored: locked again) | `Views/ReportsView.xaml(.cs)`, `backend/app/services/report_service.py`, `Views/XaiView.xaml.cs`, `Views/EvidenceView.xaml(.cs)` |
| Third round | Reports: summary numbers coloured by meaning (flows blue, benign green, threats red, confirmed orange, rejected teal, inconclusive amber). Dashboard: fixed column widths so both tables scroll horizontally as well as vertically; double-click a packet to open its flow in XAI, highlighted with its SHAP explanation (packets not in an analysed flow, or in a benign flow, say so) | `Views/ReportsView.xaml`, `Views/DashboardView.xaml(.cs)` |
| Fourth round | New logo (`Assets/logo.png` / `logo.ico`, from `logo.jpg`) in the sidebar, the window and taskbar icon, and the progress pop-up. Evidence is acquired asynchronously in one streaming pass (1 MiB buffers, copy and SHA-256 together), then the copy is hashed again and must match [12]; the window no longer freezes on a 100 MB capture. Dashboard filters list only what the capture contains: protocol, attack by ML prediction, attack by supporting evidence (threats); protocol, TCP flag, attack of the packet's flow (packets); search boxes match every word typed. Tier 2 evidence toggle moved inside the Tier 2 card; Hybrid source is a full-width strip under both tiers. Reports: Rejected in red. XAI: no "Generating..." label; SHAP column labelled log-odds. `backend/run_tests.py` runs all maintained suites | `MainWindow.xaml`, `Views/*`, `FORENXAI.Desktop.csproj`, `backend/run_tests.py` |
| Backend stability | The backend process crashed three times inside `xgboost.dll` (Windows error 0xC0000409) minutes after an analysis, with no request running; cause not yet found. `python run_backend.py --supervise` now restarts the server 3 s after a crash, and the app re-checks the backend before each analysis (restarting a packaged backend, or waiting up to 30 s for a supervised one) | `backend/run_backend.py`, `Services/BackendProcessService.cs`, `App.xaml.cs` |

Running from source, start the backend with the app's data folder and the supervisor:

```
cd backend
set FORENXAI_DATA_DIR=%LOCALAPPDATA%\FORENXAI
.venv\Scripts\python.exe run_backend.py --supervise
```

Without `FORENXAI_DATA_DIR` a source-run backend looks for cases in `backend/cases` and the app's analysis fails with "Case directory not found".

### Statistical audit (28 Sep 2026)

Every figure the app computes or quotes was recomputed independently, on the
TRUSTLab held-out test set (280,063 flows) and on a LabActivity2 case.

| Quantity | Method | Result |
|---|---|---|
| Accuracy, macro F1 | Recomputed through the app's own preprocessing [9] | 0.9351 / 0.9305; with the abstain layer 0.9374 / 0.9332 at 1.54% abstention. Identical to the reported figures |
| "ML Confidence" | Highest softmax probability. Calibration: expected calibration error, 15 equal-width bins [3, 7, 8], and the multiclass Brier score [2] | ECE 0.0040, Brier 0.0852; mean confidence 0.939 vs accuracy 0.935. Well calibrated in-distribution; the 0.47–0.87 bands are 1–3 points over-confident. On a capture from another network the confidence carries no such guarantee (LabActivity2: 94% DDoS on a port scan) |
| Tuning gain | McNemar's test on the paired predictions [4]; percentile bootstrap of the macro-F1 difference [5] | 2,936 vs 1,871 discordant flows, exact p = 1.41e-53; 95% CI +0.0033 to +0.0044. Both match the reported values |
| Out-of-distribution rule | Squared Mahalanobis distance to the training mean, limit at the training 99th percentile [6] | Flags 1.04% of held-out flows, as a 99th-percentile limit should |
| Abstention | Per-class confidence thresholds fitted on a validation split, never on test [10] | Error rate 6.26% on kept flows vs 21.6% on abstained flows: the layer removes flows about 3.5 times as likely to be wrong |
| TreeSHAP | Exact TreeSHAP for tree ensembles [1, 11] | Additivity holds for every flow (base value + sum of SHAP = model output for the predicted class, max error 2.4e-06). Values are in log-odds (margin) units, now labelled so in the XAI tab. Top-10 features, values, observed values and base values identical to an independent computation |
| Observed values | Features recomputed from the packets with scapy | Match CICFlowMeter's CSV and the SHAP table for all sampled flows |
| Dashboard and report numbers | Counts and percentages recomputed from `analysis.json` | All match |

References (ACM)

[1] Scott M. Lundberg, Gabriel Erion, Hugh Chen, Alex DeGrave, Jordan M. Prutkin, Bala Nair, Ronit Katz, Jonathan Himmelfarb, Nisha Bansal, and Su-In Lee. 2020. From local explanations to global understanding with explainable AI for trees. *Nature Machine Intelligence* 2, 1 (2020), 56–67. https://doi.org/10.1038/s42256-019-0138-9

[2] Glenn W. Brier. 1950. Verification of forecasts expressed in terms of probability. *Monthly Weather Review* 78, 1 (1950), 1–3. https://doi.org/10.1175/1520-0493(1950)078<0001:VOFEIT>2.0.CO;2

[3] Chuan Guo, Geoff Pleiss, Yu Sun, and Kilian Q. Weinberger. 2017. On calibration of modern neural networks. In *Proceedings of the 34th International Conference on Machine Learning (ICML '17)*, PMLR 70, 1321–1330.

[4] Thomas G. Dietterich. 1998. Approximate statistical tests for comparing supervised classification learning algorithms. *Neural Computation* 10, 7 (1998), 1895–1923. https://doi.org/10.1162/089976698300017197

[5] Bradley Efron and Robert J. Tibshirani. 1993. *An Introduction to the Bootstrap*. Chapman & Hall/CRC, New York, NY. https://doi.org/10.1201/9780429246593

[6] Kimin Lee, Kibok Lee, Honglak Lee, and Jinwoo Shin. 2018. A simple unified framework for detecting out-of-distribution samples and adversarial attacks. In *Advances in Neural Information Processing Systems 31 (NeurIPS '18)*, 7167–7177.

[7] Mahdi Pakdaman Naeini, Gregory F. Cooper, and Milos Hauskrecht. 2015. Obtaining well calibrated probabilities using Bayesian binning. In *Proceedings of the 29th AAAI Conference on Artificial Intelligence (AAAI '15)*, 2901–2907. https://doi.org/10.1609/aaai.v29i1.9602

[8] Matthias Minderer, Josip Djolonga, Rob Romijnders, Frances Hubis, Xiaohua Zhai, Neil Houlsby, Dustin Tran, and Mario Lucic. 2021. Revisiting the calibration of modern neural networks. In *Advances in Neural Information Processing Systems 34 (NeurIPS '21)*, 15682–15694.

[9] Marina Sokolova and Guy Lapalme. 2009. A systematic analysis of performance measures for classification tasks. *Information Processing & Management* 45, 4 (2009), 427–437. https://doi.org/10.1016/j.ipm.2009.03.002

[10] Yonatan Geifman and Ran El-Yaniv. 2017. Selective classification for deep neural networks. In *Advances in Neural Information Processing Systems 30 (NIPS '17)*, 4878–4887.

[11] Tianqi Chen and Carlos Guestrin. 2016. XGBoost: A scalable tree boosting system. In *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD '16)*. ACM, 785–794. https://doi.org/10.1145/2939672.2939785

[12] Karen Kent, Suzanne Chevalier, Tim Grance, and Hung Dang. 2006. *Guide to Integrating Forensic Techniques into Incident Response*. NIST Special Publication 800-86. National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-86

### Backend crash fix: model pinned to the CPU

The `xgboost.dll` crash (Windows error 0xC0000409) that stopped the backend
"out of nowhere" is found and fixed. The bundle was trained on a GPU and saved
with `device="cuda"`; TreeSHAP then ran on CUDA inside `xgboost.dll`, and the
process died later or on exit: 3 of 3 runs crashed with `device="cuda"`, 0 of
3 with `device="cpu"`. `_load_model_bundle_impl()` now sets `device="cpu"`
(the app is CPU-only). The held-out test figures are unchanged (0.9351 /
0.9305; with the abstain layer 0.9374 / 0.9332), SHAP additivity holds (max
error 2.4e-06), and `test_model_preprocessing.py` fails if the model is not on
the CPU. Qwen was checked separately: six narration requests sent at once all
succeeded, served one at a time by `generation_lock`, and the server process
never changed.

### Model input fix: float32 before scaling

The check above first failed: through the app, test accuracy was 0.9304, not
0.9351. Training casts the 66 features to float32 before the scaler
(`clean_features()` in the pipeline's `src/common.py`); the app scaled in
float64, which changed 3,004 of the 280,063 test predictions. The app now
scales from float32 (`prepare_model_input()` in `model_service.py`), and the
reported test figures reproduce exactly.

On LabActivity2 the fix moved most flows' ML class from DoS / Slowloris to
DDoS. Those flows sit on the model's decision boundaries (confidence 39-50%)
because the capture comes from a different network than TRUSTLab; the capture
is a port scan, so neither class is right. The Final Verdict is unchanged:
PortScan, decided by the Tier 1 rule for 2,001 of 2,016 flows.

### Checks on this branch

| Check | Result |
|---|---|
| Backend import (`import app.main`) | OK |
| `backend/run_tests.py` (7 suites: model preprocessing and CPU device, Tier 1 rules, Tier 2 packet rules, RAG index, AI summary, recommendations, all 16 classes) | 7/7 pass |
| `test_classifier.py`, `test_model_service.py`, `test_shap.py`, `test_shap_service.py` | Fail on every branch: unchanged since the first commit, they call removed functions or need a local sample CSV |
| Desktop build (`dotnet build`) | 0 errors, 0 warnings |
| End-to-end in the app, LabActivity2 (1.04 MB, 10,584 packets, 2,016 ML flows) | Pass: 100 MB limit (183 MB capture refused), evidence intake, progress pop-up with live step and X button, Dashboard (rule panel, Tier 2 toggle, donut, Selected threat, tables, row selection), double-click to XAI, XAI, Investigation, Reports |
| Backend supervisor | Pass: server killed on purpose, back and healthy within about 20 s |
| Model, abstain layer, TreeSHAP (independent recomputation from the raw CSV and bundle files) | Pass, 25/25: bundle SHA-256 = manifest; 66 features in one order across `features.pkl`, manifest and OOD stats; 16 classes; class and confidence (max softmax) identical for every flow; Mahalanobis distance and abstain decisions identical; SHAP additivity (base + sum = model margin, max error 3e-06); top-10 contributors, SHAP values, observed values and base values identical; dashboard counts and threat percentage correct |
| Held-out TRUSTLab test (280,063 flows) through the app's own code | Reproduces the reported figures exactly: accuracy 0.9351, macro F1 0.9305; with the abstain layer 0.9374 / 0.9332, abstention 1.54%, error rate 6.26% kept vs 21.6% abstained (`test_model_preprocessing.py` guards the fix below) |

### Next steps

- Measure the real capture-size limit (time and memory on a larger capture such as the 183 MB LabActivity3) and set `MaxEvidenceMegabytes` from it.
- Open a pull request `merge-main-forenxai-v3` → `main`.
- Open items from `finetuned-xgboost` still apply: Tier 2 statistical validation needs labelled packet captures; DNS spoofing detection, Suricata HTTP / DNS logs and custom API signatures are not yet implemented (see `README_finetuned-xgboost.md`, "Tier 2: improvements" and "Known limitations").

## Architecture

```text
PCAP / PCAPNG
      |
      v
CICFlowMeter
      |
      v
XGBoost
      |
      v
Predicted Class
      |
      v
TreeSHAP
      |
      +------------------------+
      |                        |
      v                        v
SHAP Contributors        Deterministic Recommendations
      |
      v
Qwen 2.5 3B GGUF
      |
      v
Grounded Human-Readable Explanation
      |
      v
C# WPF Desktop Interface
```

The main responsibilities are separated as follows:

- **C# WPF frontend**: evidence selection, case navigation, dashboards, XAI display, investigator review, and reports.
- **Python FastAPI backend**: PCAP processing, CICFlowMeter integration, XGBoost inference, SHAP explanations, recommendations, Qwen narration, review storage, and reporting.
- **XGBoost** performs the classification.
- **TreeSHAP** calculates the numerical feature contributions.
- **Qwen** only rewrites existing evidence into readable prose. It does not classify traffic.
- **Recommendations** remain deterministic and are not generated by Qwen.

---

# 1. System Requirements

FORENXAI is currently developed and tested on **64-bit Windows**.

## Required Software

Install the following before setting up the project:

1. **Git**
2. **Python 3.x**
3. **pip**
4. **Python virtual environment support (`venv`)**
5. **.NET SDK 10**
6. **Java JDK 8**
7. **Apache Maven 3.9.x**
8. **Wireshark**
9. **Npcap**
10. **CICFlowMeter v4**
11. **Qwen 2.5 3B GGUF model**
12. **FORENXAI XGBoost model bundle**

The currently tested environment uses:

```text
Windows 10/11 64-bit
Java: 1.8.0_202
Maven: 3.9.16
.NET target: net10.0-windows
Qwen model: qwen2.5-3b-q4.gguf
```

Exact Python package versions should be installed from the repository's `requirements.txt` whenever possible.

---

# 2. Required Project Files

After cloning the repository, the important structure should look similar to this:

```text
Forenxai/
├── frontend/
│   └── FORENXAI.Desktop/
│       ├── Views/
│       ├── Services/
│       ├── Models/
│       └── FORENXAI.Desktop.csproj
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── services/
│   │   ├── analysis/
│   │   ├── models/
│   │   └── utils/
│   │
│   ├── models/
│   │   ├── forenxai/
│   │   │   ├── XGBoost.pkl
│   │   │   ├── scaler.pkl
│   │   │   ├── features.pkl
│   │   │   ├── label_encoder.pkl
│   │   │   ├── manifest.json
│   │   │   └── shap_global.json
│   │   │
│   │   └── llm/
│   │       └── qwen2.5-3b-q4.gguf
│   │
│   ├── cases/
│   ├── requirements.txt
│   ├── run_backend.py
│   └── FORENXAI.Backend.spec
```

## Important

The Qwen model is approximately 1.8 GB and should **not** be committed directly to GitHub.

Place it manually at:

```text
backend\models\llm\qwen2.5-3b-q4.gguf
```

The XGBoost model bundle must remain internally consistent. Do not replace only `XGBoost.pkl` unless the new model uses the same feature order, preprocessing, label encoding, and compatible SHAP setup.

## Model bundle provenance

The bundle in `backend\modelsorenxai\` is the multiclass XGBoost trained on the GPU (NVIDIA GeForce RTX 4050 Laptop GPU, CUDA 12.1) with leakage-safe splits, in which rows with an identical feature vector are kept in the same partition. It was trained on TRUSTLab only (16 classes, 74 features).

| File | SHA-256 (first 16) |
|---|---|
| XGBoost.pkl | 257f40e37094ccf7 |
| scaler.pkl | cb7d1b995316fd6e |
| label_encoder.pkl | 64ed93e1e30701b1 |
| features.pkl | bff07530c1852f17 |
| shap_global.json | 8fe52e3537b62577 |

`manifest.json` carries the full SHA-256 of each file and the backend verifies them at startup. Git is set not to convert line endings in this folder (`.gitattributes`), so the hashes stay valid on every clone.

## Testing the model bundle (branch `gpu-leakage-safe-model`)

A short check that needs no PCAP, CICFlowMeter, Java or language model:

```powershell
git checkout gpu-leakage-safe-model
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python verify_bundle.py
```

Expected: four `PASS` lines and `ALL CHECKS PASSED`, exit code 0. It verifies the bundle hashes, classifies 3,008 held-out flows (`sample_data/heldout_sample.csv`, accuracy about 0.92), and checks that TreeSHAP reconstructs the model output (error about 1e-5).

For the full application, follow the sections below (CICFlowMeter, Java, Wireshark, the language model in `backend/models/llm/`). `python verify_bundle.py --llm` also checks the language model file.

To build and run the desktop window, install the .NET 10 SDK first (the project targets `net10.0-windows`; a machine with only .NET 8 or 9 cannot build it):

```powershell
winget install Microsoft.DotNet.SDK.10
```

Open a new terminal so the updated PATH is used, then start the two parts in separate terminals:

```powershell
# Terminal 1: backend
cd backend
.\.venv\Scripts\python.exe run_backend.py     # http://127.0.0.1:8000, /health returns {"status":"healthy"}

# Terminal 2: desktop window
cd frontend\FORENXAI.Desktop
dotnet run -c Release
```

---

# 3. Clone the Repository

Open PowerShell and run:

```powershell
git clone <YOUR-GITHUB-REPOSITORY-URL>
```

Then enter the project:

```powershell
cd "<PATH-TO-YOUR-CLONED-REPOSITORY>\Forenxai"
```

Example:

```powershell
cd "C:\Users\<USERNAME>\Documents\Forenxai"
```

---

# 4. Backend Setup

## Step 1 - Open the backend folder

```powershell
cd "<PROJECT-ROOT>\backend"
```

## Step 2 - Create a virtual environment

```powershell
python -m venv .venv
```

## Step 3 - Activate the virtual environment

```powershell
.venv\Scripts\activate
```

After activation, PowerShell should show something similar to:

```text
(.venv) PS C:\...\backend>
```

## Step 4 - Upgrade pip

```powershell
python -m pip install --upgrade pip
```

## Step 5 - Install Python dependencies

```powershell
pip install -r requirements.txt
```

If `llama-cpp-python` is not already installed successfully from the requirements file, install the tested CPU wheel with:

```powershell
python -m pip install llama-cpp-python `
    --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
```

Verify it:

```powershell
python -c "import llama_cpp; print('llama-cpp-python OK'); print(llama_cpp.__version__)"
```

You should see:

```text
llama-cpp-python OK
```

---

# 5. Install the Local Qwen Model

Obtain:

```text
qwen2.5-3b-q4.gguf
```

Create the model directory if it does not already exist:

```powershell
New-Item -ItemType Directory -Force ".\models\llm"
```

Place the GGUF file at:

```text
backend\models\llm\qwen2.5-3b-q4.gguf
```

Verify:

```powershell
Test-Path ".\models\llm\qwen2.5-3b-q4.gguf"
```

Expected output:

```text
True
```

---

# 6. Verify the XGBoost Model Bundle

The following files are required:

```text
backend\models\forenxai\XGBoost.pkl
backend\models\forenxai\scaler.pkl
backend\models\forenxai\features.pkl
backend\models\forenxai\label_encoder.pkl
backend\models\forenxai\manifest.json
backend\models\forenxai\shap_global.json
```

Check them:

```powershell
Get-ChildItem ".\models\forenxai"
```

The backend verifies model artifacts before loading them.

If you see an error similar to:

```text
Model artifact size mismatch
```

or:

```text
Model artifact SHA-256 mismatch
```

the file on disk does not match `manifest.json`.

Do not disable the integrity check.

If a model artifact was intentionally replaced, update the corresponding size and SHA-256 in `manifest.json` only after confirming that the replacement model is compatible with the rest of the bundle.

To calculate a SHA-256 hash:

```powershell
(Get-FileHash ".\models\forenxai\XGBoost.pkl" -Algorithm SHA256).Hash
```

To check the file size:

```powershell
(Get-Item ".\models\forenxai\XGBoost.pkl").Length
```

---

# 7. Install Java JDK 8

CICFlowMeter requires Java.

Install a **64-bit JDK 8**.

Verify:

```powershell
java -version
```

and:

```powershell
javac -version
```

The tested setup uses:

```text
Java 1.8.0_202
```

A JDK is required, not only a JRE.

---

# 8. Install Apache Maven

The tested setup uses:

```text
Apache Maven 3.9.16
```

The current FORENXAI CICFlowMeter integration expects Maven at:

```text
C:\Tools\apache-maven-3.9.16-bin\apache-maven-3.9.16\bin\mvn.cmd
```

Create:

```text
C:\Tools\
```

and extract Maven so that this file exists:

```powershell
Test-Path "C:\Tools\apache-maven-3.9.16-bin\apache-maven-3.9.16\bin\mvn.cmd"
```

Expected:

```text
True
```

Verify Maven:

```powershell
& "C:\Tools\apache-maven-3.9.16-bin\apache-maven-3.9.16\bin\mvn.cmd" -version
```

---

# 9. Install Wireshark and Npcap

Install Wireshark with Npcap support.

FORENXAI currently expects `editcap.exe` at:

```text
C:\Program Files\Wireshark\editcap.exe
```

Verify:

```powershell
Test-Path "C:\Program Files\Wireshark\editcap.exe"
```

Expected:

```text
True
```

Npcap should provide its native files under:

```text
C:\Windows\System32\Npcap
```

Verify:

```powershell
Test-Path "C:\Windows\System32\Npcap"
```

---

# 10. Install CICFlowMeter

The current backend integration expects CICFlowMeter at:

```text
C:\Tools\CICFlowMeter\CICFlowMeter-master
```

The directory must contain:

```text
pom.xml
```

Verify:

```powershell
Test-Path "C:\Tools\CICFlowMeter\CICFlowMeter-master\pom.xml"
```

Expected:

```text
True
```

The jNetPcap native library is currently expected at:

```text
C:\Tools\CICFlowMeter\CICFlowMeter-master\jnetpcap\win\jnetpcap-1.4.r1425
```

Verify:

```powershell
Test-Path "C:\Tools\CICFlowMeter\CICFlowMeter-master\jnetpcap\win\jnetpcap-1.4.r1425\jnetpcap.dll"
```

A second native directory used by the tested environment is:

```text
C:\Tools\CICFlowMeter\installed\CICFlowMeter-4.0\lib\native
```

The current backend builds the Java native search path using these locations together with Npcap.

---

# 11. CICFlowMeter Known Behavior

The tested CICFlowMeter/jNetPcap build may print:

```text
java.lang.NullPointerException
at org.jnetpcap.nio.DisposableGC...
```

and Maven may finish with:

```text
BUILD FAILURE
```

after CICFlowMeter has already generated a valid CSV.

FORENXAI intentionally checks whether a valid non-empty CSV was produced.

If the log contains:

```text
WARNING: Maven returned a non-zero exit code, but CICFlowMeter produced a valid CSV.
Continuing with the generated CSV.
```

the pipeline can continue normally.

Do not treat this specific cleanup exception as a FORENXAI analysis failure when the CSV was successfully generated.

---

# 12. Frontend Setup

Open another PowerShell window.

Navigate to:

```powershell
cd "<PROJECT-ROOT>\frontend\FORENXAI.Desktop"
```

Check .NET:

```powershell
dotnet --version
```

The project currently targets:

```text
net10.0-windows
```

Restore dependencies:

```powershell
dotnet restore
```

Build:

```powershell
dotnet build
```

Expected:

```text
Build succeeded.
```

---

# 13. Run FORENXAI

FORENXAI currently runs as two local processes during development:

```text
Python FastAPI backend
+
C# WPF frontend
```

## Terminal 1 - Start the Python backend

Open PowerShell:

```powershell
cd "<PROJECT-ROOT>\backend"
```

Activate the environment:

```powershell
.venv\Scripts\activate
```

Run:

```powershell
python run_backend.py
```

Expected output:

```text
========================================
FORENXAI Backend Starting...
Address: http://127.0.0.1:8000
========================================
```

Leave this terminal open.

---

## Terminal 2 - Test Backend Health

Open another PowerShell:

```powershell
Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/health" `
    -Method GET
```

The backend should report a healthy status.

You can also open:

```text
http://127.0.0.1:8000/docs
```

in a browser to view the FastAPI API documentation.

---

## Terminal 3 - Start the WPF Desktop Application

Open another PowerShell:

```powershell
cd "<PROJECT-ROOT>\frontend\FORENXAI.Desktop"
```

Run:

```powershell
dotnet run
```

The FORENXAI desktop application should open.

---

# 14. Basic Investigation Workflow

After both backend and frontend are running:

1. Open FORENXAI.
2. Go to the evidence section.
3. Select a `.pcap` or `.pcapng` file.
4. Start the analysis.
5. FORENXAI creates a case ID similar to:

```text
FX-20260919-014919
```

6. The backend performs:
   - SHA-256 evidence hashing
   - packet extraction
   - traffic summary generation
   - flow construction
   - CICFlowMeter feature extraction
   - XGBoost classification
   - deterministic recommendations
   - TreeSHAP explanation generation
   - `analysis.json` generation
7. Open the XAI page.
8. Select a detected threat flow.
9. FORENXAI displays:
   - predicted class
   - confidence
   - deterministic SHAP explanation
   - SHAP contributors
   - local Qwen explanation
   - recommended actions
   - investigator review controls
10. Save an investigator review if required.
11. Open the reports section to inspect or export the case report.

---

# 15. Qwen Narration

Qwen narration is generated **on demand** for the selected flow.

FORENXAI does not run Qwen for every flow during the initial PCAP analysis.

This keeps the initial analysis faster.

The flow is:

```text
Initial Analysis
    |
    +--> XGBoost
    +--> SHAP
    +--> analysis.json

Investigator selects a flow
    |
    v
GET /analysis/{case_id}/narration/{flow_index}
    |
    v
Qwen 2.5 3B
    |
    v
Grounded explanation displayed in WPF
```

The first narration request can be slower because the GGUF model must be loaded into memory.

Subsequent requests normally reuse the loaded model.

---

# 16. Investigator Reviews

Investigator reviews are stored under:

```text
backend\cases\<CASE-ID>\reviews\investigator_reviews.json
```

Supported decisions are:

```text
Confirmed
Rejected
Inconclusive
```

---

# 17. Case Files

FORENXAI stores development case output under:

```text
backend\cases\
```

Each case receives its own directory.

Example:

```text
backend\cases\FX-20260919-014919\
```

Generated artifacts may include:

```text
evidence\
flows\
reviews\
analysis.json
```

Reports are also generated from the case data.

---

# 18. Common Troubleshooting

## Port 8000 is already in use

Error:

```text
[WinError 10048]
```

Check:

```powershell
netstat -ano | findstr :8000
```

Stop the stale process:

```powershell
Stop-Process -Id <PID> -Force
```

Then restart:

```powershell
python run_backend.py
```

---

## Model artifact size or hash mismatch

Example:

```text
Model artifact size mismatch
```

This means the current file does not match `manifest.json`.

Do not bypass the check.

Confirm the model was intentionally changed, calculate its correct size/hash, verify bundle compatibility, and then update the manifest.

---

## Qwen model not found

Check:

```powershell
Test-Path ".\models\llm\qwen2.5-3b-q4.gguf"
```

The file must be located at:

```text
backend\models\llm\qwen2.5-3b-q4.gguf
```

---

## `llama_cpp` cannot be imported

Activate the backend virtual environment:

```powershell
.venv\Scripts\activate
```

Then install the tested CPU wheel:

```powershell
python -m pip install llama-cpp-python `
    --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
```

---

## CICFlowMeter cannot start

Check:

```powershell
java -version
javac -version
```

Then verify:

```powershell
Test-Path "C:\Tools\apache-maven-3.9.16-bin\apache-maven-3.9.16\bin\mvn.cmd"
Test-Path "C:\Tools\CICFlowMeter\CICFlowMeter-master\pom.xml"
Test-Path "C:\Tools\CICFlowMeter\CICFlowMeter-master\jnetpcap\win\jnetpcap-1.4.r1425\jnetpcap.dll"
```

---

## WPF build says the EXE is locked

Close FORENXAI or run:

```powershell
Get-Process FORENXAI.Desktop -ErrorAction SilentlyContinue |
    Stop-Process -Force
```

Then rebuild:

```powershell
dotnet build
```

---

# 19. GitHub / `.gitignore` Recommendations

Do not commit runtime data, temporary build output, the Python virtual environment, or the large GGUF model.

Recommended `.gitignore` entries:

```gitignore
# Python
backend/.venv/
__pycache__/
*.pyc

# Runtime cases
backend/cases/

# PyInstaller
backend/build/
backend/dist/

# Large local LLM
backend/models/llm/*.gguf

# .NET
frontend/FORENXAI.Desktop/bin/
frontend/FORENXAI.Desktop/obj/

# IDE
.vscode/
.vs/
```

The Qwen model should be distributed separately and copied into:

```text
backend\models\llm\
```

after cloning.

---

# 20. Development Status

The normal development workflow is currently functional:

```text
PCAP/PCAPNG
→ CICFlowMeter
→ XGBoost
→ SHAP
→ Recommendations
→ Qwen narration
→ Investigator Review
→ Reports
→ WPF UI
```

Standalone packaging is still being finalized.

At present, CICFlowMeter, Java, Maven, Wireshark/editcap, Npcap, and the local GGUF model are external runtime dependencies.

Do not assume the repository is fully portable to another Windows computer until the standalone deployment phase has been completed and tested.

---

# 21. Quick Start Summary

After completing the one-time setup:

## Start Backend

```powershell
cd "<PROJECT-ROOT>\backend"
.venv\Scripts\activate
python run_backend.py
```

## Start Frontend

In another terminal:

```powershell
cd "<PROJECT-ROOT>\frontend\FORENXAI.Desktop"
dotnet run
```

## Verify Backend

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Then use the FORENXAI desktop interface to select and analyze a PCAP/PCAPNG file.

---

# 22. Security and Forensic Integrity Notes

- Original evidence should not be manually modified after acquisition.
- FORENXAI calculates SHA-256 hashes for evidence.
- Model artifacts are verified against `manifest.json`.
- Do not disable model integrity verification.
- Qwen does not determine the attack class.
- XGBoost provides the classification.
- TreeSHAP provides the numerical explanation.
- Qwen only converts supplied model evidence into readable text.
- Investigator review remains a human decision.
- AI output should be treated as an analytical finding, not automatically as ground truth.

---

# FORENXAI

**Explainable AI-Driven Network Forensics**

Current stack:

```text
C# WPF
FastAPI
Python
CICFlowMeter
XGBoost
TreeSHAP
Qwen 2.5 3B GGUF
```
