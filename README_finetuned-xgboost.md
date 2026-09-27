# Branch `finetuned-xgboost`: what changed and why

This branch replaces the classifier with the tuned XGBoost model and adds a
hybrid detection layer (Tier 1 flow rules, Tier 2 packet rules and Suricata),
a retrieval-grounded recommendation stage and the matching interface.

All paths are relative to the repository root (`FORENXAI-Desktop/`).

---

## Guided update: setup, layout, status and merging

### A. How the parts connect

```
PCAP / PCAPng (Evidence tab)
  -> capture intake: SHA-256, format from file header, non-Ethernet link layers re-framed
       cicflowmeter_service.py
  -> three readers of the same file
       CICFlowMeter v4 ......... flow records (CSV, 66 model features)   cicflowmeter_service.py
       scapy, one pass ......... traffic summary + Tier 2 packet checks  pcap_service.py + packet_rule_service.py
       Suricata 7.0.10 ......... signature alerts (eve.json)             packet_rule_service.run_suricata
  -> detection, side by side
       XGBoost + abstain layer . class, confidence, OOD                 model_service.py
       Tier 1 flow rules ....... hits on the flow records               rule_service.py (rules.json)
       Tier 2 rules ............ packet + Suricata hits, matched to flows packet_rule_service.attach
  -> TreeSHAP explanation ....................................... shap_service.py
  -> decide(): verdict + source (agree/rule/model/conflict/abstain)  rule_service.decide
  -> RAG recommendations + AI summary (Qwen, cited sources) ....... recommendation_service.py, narration_service.py, rag/
  -> analysis.json (backend/cases/<id>/) -> WPF UI: Dashboard (rule charts), XAI view, Reports
```

`backend/app/api/analysis.py` (`start_analysis`) runs this chain for each case.

### B. Dependencies and how to get them

The base prerequisites (Git, Python 3.11, .NET 10 SDK, JDK 8 + Maven for
CICFlowMeter, Wireshark with Npcap, CICFlowMeter v4) are in
`README_FORENXAI.md`. This branch adds or requires:

| Dependency | Needed for | How to get it |
|---|---|---|
| Python packages | Backend, including `scapy` (Tier 2), `xgboost`, `shap`, `llama_cpp_python`, `pypdf` | `cd backend` then `python -m venv .venv` and `.venv\Scripts\pip install -r requirements.txt` |
| Wireshark (`editcap.exe`) + Npcap | PCAPng to PCAP conversion for CICFlowMeter; Npcap is also required by Suricata | `winget install WiresharkFoundation.Wireshark` (Npcap installs with it) |
| Suricata 7.0.10 | Tier 2 signatures (optional: without it, cases record "Suricata not run") | `winget install --id OISF.Suricata --exact` (one UAC prompt); found at `C:\Program Files\Suricata`, or set `FORENXAI_SURICATA` |
| Suricata rulesets | 52,964 free signatures | `cd backend` then `.venv\Scripts\python update_suricata_rules.py` (writes `tools/suricata/et-open.rules`; git-ignored; rerun to refresh) |
| Qwen 2.5 3B GGUF | Recommendations and AI summary | Place `qwen2.5-3b-q4.gguf` in `backend/models/llm/` (git-ignored; see `backend/models/llm/README.md`) |
| RAG source archive | Cited passages | Copy the 22 source documents into `rag/_sources/` (git-ignored; see `rag/README.md`), then `python rag/config/rag_index.py` to rebuild the index |
| .NET 10 SDK | Desktop UI | `winget install Microsoft.DotNet.SDK.10` |

Check the install:

```
cd backend
.venv\Scripts\python verify_bundle.py
.venv\Scripts\python test_rules.py
.venv\Scripts\python test_packet_rules.py
.venv\Scripts\python test_rag_pipeline.py
.venv\Scripts\python test_recommendations.py --fast
cd ..\frontend\FORENXAI.Desktop
dotnet build
```

Run: `cd backend` then `.venv\Scripts\python run_backend.py` (port 8000), and
in a second terminal `cd frontend\FORENXAI.Desktop` then `dotnet run`.

### C. Where the added files are

| Area | Files added by this branch |
|---|---|
| Model bundle | `backend/models/forenxai/` (tuned model, `decision_thresholds.json`, `ood_stats.json`, `model_facts.json`, `CHANGES.md`) |
| Rules | `backend/app/rules/rules.json`, `rules_tuning.json`; `backend/app/services/rule_service.py` (Tier 1, `decide()`), `packet_rule_service.py` (Tier 2, Suricata) |
| Rule tooling | `backend/tune_rules.py`, `validate_rules.py`, `update_suricata_rules.py` |
| Tests | `backend/test_rules.py`, `test_packet_rules.py`, `test_rag_pipeline.py`, `test_narration_rag.py`, `test_recommendations*.py` |
| RAG | `rag/config/*.py`, `rag/knowledge/**`, `rag/_sources/manifest.json` + `SHA256SUMS.txt`, `rag/SOURCES_ACM.md` |
| UI | `frontend/FORENXAI.Desktop/Views/DashboardView.xaml(.cs)`, `XaiView.xaml(.cs)`, `Models/AnalysisModels.cs` |
| Docs | this file, `tools/README.md`, `rag/README.md`, `rag/RAG_PIPELINE.md` |
| Git-ignored (per machine) | `backend/.venv/`, `backend/cases/`, `backend/models/llm/*.gguf`, `rag/_sources/*` (except manifest and checksums), `tools/*` (Suricata rules, JDK) |

### D. Status

| Part | Status |
|---|---|
| Tuned 66-feature model, abstain layer | Done, tested |
| Tier 1 flow rules | Done; tuned and validated (PortScan F1 0.98, DoS 0.96 decide verdicts; DDoS and oversized-packet rules disabled) |
| Tier 2 packet rules + Suricata | Done, functionally tested; not statistically evaluated (advisory only) |
| Hybrid `decide()` | Done, tested |
| Capture intake for any PCAP/PCAPng link layer | Done, tested (10 variants) |
| RAG recommendations, AI summary | Done, tested; corpus audited to 22 sources |
| Dashboard rule panel, XAI view | Done, builds; see the merge notes below |
| Open | Tier 2 scoring and tuning on labelled pcaps; LabActivity3 timing; DNS spoofing; Suricata HTTP/DNS logs; custom API signatures |

### E. Merging into `main`

Checked on 26 Sep 2026: `main` has one commit this branch lacks,
`a6a85a9` "Improve dashboard scrolling and threat table visibility" (it also
adds `BackendProcessService.cs`, a data directory in `runtime_paths.py`, and
`llama_cpp` packaging). A trial merge (`git merge-tree`) gives three
conflicts; everything else, including `model_service.py`, merges cleanly.

Steps (on a clean working tree, Git Bash or PowerShell):

```
git checkout finetuned-xgboost
git pull
git fetch origin
git merge origin/main          # stops with the three conflicts below
```

Resolve:

1. `backend/app/utils/runtime_paths.py`: keep this branch's side
   (`get_rag_directory`, `get_knowledge_directory`, `get_knowledge_map_path`,
   `get_toolchain_directory`, `get_java_home`). Main's side of that block is
   only a blank line.
2. `frontend/FORENXAI.Desktop/Views/DashboardView.xaml` and
   `DashboardView.xaml.cs`: both branches rewrote the Dashboard. Take main's
   version as the base (it has the new scrolling and threat-table layout), then
   re-add from this branch:
   - the "RULE-BASED DETECTION" panel (Tier 1 bars, Tier 2 bars, verdict-source
     bar; the `RuleBarTemplate` resource) as a row above the threat table;
   - the Rule and Verdict columns of the threat table;
   - in the code-behind: `tier1Bars` / `tier2Bars` / `verdictLegend`,
     `LoadRulePanel()`, `ClearRulePanel()`, `FillBars()`, `TopRuleHit()`,
     the `BarRow` class, `RuleDisplay` / `VerdictDisplay` on `ThreatRow`, and
     the `LoadThreats()` change that also lists flows only the rules flagged.
   Drop this branch's outer `ScrollViewer` if main's layout already scrolls.
3. Build and test, then finish the merge:

```
cd frontend/FORENXAI.Desktop && dotnet build && cd ../..
cd backend && .venv/Scripts/python test_rules.py && .venv/Scripts/python test_packet_rules.py && cd ..
git add -A
git commit                     # merge commit
git push
```

Then open a pull request `finetuned-xgboost` -> `main` on GitHub; with the
conflicts resolved on the branch, it merges without further conflicts.

### F. Updated artifacts: location, purpose and connections

Artifacts are the files the system or the thesis is built from, as opposed to
source code. `BUNDLE` below means
`C:\Users\HOME PC\Downloads\MULTI_CLASS_FORENXAI\forenxai_pipeline_full\forenxai_binary\new_deploy_gpu\`
(the frozen training bundle, outside this repository).

**Runtime artifacts (read by the application)**

| Artifact | Location | Purpose | Connected to |
|---|---|---|---|
| `XGBoost.pkl`, `scaler.pkl`, `label_encoder.pkl`, `features.pkl` | `backend/models/forenxai/` | Tuned classifier, its scaler, class names and the 66-feature order | Loaded by `model_service.py`; copied from `BUNDLE`; hashes in `manifest.json` |
| `manifest.json` | `backend/models/forenxai/` | Feature count (66), feature order, file hashes, library versions | Checked by `model_service.verify_model_bundle()` before loading |
| `decision_thresholds.json`, `ood_stats.json` | `backend/models/forenxai/` | Per-class confidence thresholds and the Mahalanobis OOD limit (554.10) | `model_service.abstain_decisions()`; its `abstained` flag feeds `rule_service.decide()` |
| `shap_global.json`, `model_facts.json` | `backend/models/forenxai/` | Global SHAP summary; measured per-class figures | `shap_service.py`; quoted by `recommendation_service.py` |
| `rules.json` | `backend/app/rules/` | Every Tier 1 and Tier 2 threshold, the Suricata class mapping, allowlist, priority order and `decide()` trust table | Read by `rule_service.load_config()` and `packet_rule_service.py`; written by `tune_rules.py --write`; packaged by `FORENXAI.Backend.spec` |
| `rules_tuning.json` | `backend/app/rules/` | Tier 1 tuning report (candidates, chosen values, held-out results) | Produced by `tune_rules.py`; its test results are copied into `rules.json` |
| `et-open.rules` (git-ignored) | `tools/suricata/` | 52,964 merged Suricata signatures | Produced by `update_suricata_rules.py`; loaded by `packet_rule_service.run_suricata()` |
| `qwen2.5-3b-q4.gguf` (git-ignored) | `backend/models/llm/` | Local language model | `llm_provider.py`, used by the recommendation and narration services |
| Knowledge files | `rag/knowledge/` | Playbooks, attack profiles, glossary, caveats | Mapped per class by `rag/config/knowledge_map.py` |
| Source archive (git-ignored except `manifest.json`, `SHA256SUMS.txt`) | `rag/_sources/` | The 22 cited documents | Indexed by `rag/config/source_index.py`; references in `rag/SOURCES_ACM.md` |
| `.rag_index.json` (generated, git-ignored) | `rag/` | Prebuilt retrieval index | Built by `rag/config/rag_index.py`; opened by `recommendation_service.retrieve()` |
| `analysis.json` (per case, git-ignored) | `backend/cases/<case id>/` | One case's full result: flows, prediction, SHAP, Tier 1/2 hits, verdicts, `rule_analysis`, recommendations | Written by `analysis.py`; read by the Dashboard, XAI view and Reports |

**Thesis artifacts (tables, figures, documents)**

| Artifact | Location | Purpose | Produced by |
|---|---|---|---|
| Table 4 `T04_frozen_deployment_bundle_revised.csv` | `BUNDLE\tables\` | Deployment bundle: files, sizes, hashes, contents (19 rows) | Measured from this repository |
| Table 28 `T28_shap_top6_features_per_class_tuned.csv` | `BUNDLE\tables\` | Six leading SHAP features per class (renamed headers) | `BUNDLE\finetune\19_tuning_report.py` |
| Tables T17a/b, T24/T24a, T27a, T28b, T30 | `BUNDLE\tables\` | Tuning, decision layer, per-class and SHAP comparison tables | `19_tuning_report.py` |
| Figure 14 `fig14_system_architecture.png` | `BUNDLE\figures\` | System architecture (black and white) | `forenxai_binary\scripts\fig14_architecture.py` |
| Conceptual framework `fig_conceptual_framework_ipo.png` | `BUNDLE\figures\` | Input–Process–Output figure (user view, Tier 1 and Tier 2) | `forenxai_binary\scripts\fig_conceptual_framework.py` |
| `SHA256SUMS.txt`, `SHA256SUMS.txt.sha256` | `BUNDLE\` | Checksums of the frozen bundle; refreshed after the table and figure edits | Verify with `sha256sum -c SHA256SUMS.txt` |
| Thesis paragraphs `FORENXAI_thesis_additions.md` | `C:\Users\HOME PC\OneDrive\Desktop\Thesis\Final\` | New paragraphs per chapter, with placement and reason | Written for the thesis update |
| RAG references `SOURCES_ACM.md` | `rag/` | ACM references of the 22 retrieval sources and the list of removed ones | Retrieval audit of 26 Sep 2026 |
| Hybrid-detection handover page | https://claude.ai/artifact/3TFCNHCBAMkv5jfg2hNKQm | The design specification that Tier 1, Tier 2 and `decide()` implement | Team handover document |

How they connect: the tuning scripts (`tune_rules.py`, `19_tuning_report.py`)
produce the reports and tables; the chosen values go into the runtime
artifacts (`rules.json`, the model bundle); the application reads those to
produce each case's `analysis.json`; and the thesis tables and figures
describe the same runtime artifacts with their hashes, so Table 4 can be
checked against the files the app actually loads.

After merging, check one packaging point: `packet_rule_service.DEFAULT_RULES_FILE`
looks for `tools/suricata/et-open.rules` relative to the repository. Main now
keeps runtime data in `runtime_paths.get_data_directory()` for the packaged
app, so a packaged build should resolve the rules file through
`runtime_paths` as well (or set `suricata.rules_file` in `rules.json`).

---

## 1. Tuned model bundle

**Purpose:** deploy the tuned 66-feature XGBoost in place of the old
74-feature model, and let the application mark flows the model should not be
trusted on.

| Path | Change |
|---|---|
| `backend/models/forenxai/XGBoost.pkl`, `scaler.pkl`, `features.pkl`, `shap_global.json`, `manifest.json` | Tuned classifier (132 trees, 66 features, 16 classes) with its scaler, feature order, global SHAP summary and hashes |
| `backend/models/forenxai/decision_thresholds.json`, `ood_stats.json` | Per-class confidence thresholds and the out-of-distribution limit (squared Mahalanobis distance) |
| `backend/models/forenxai/model_facts.json`, `backend/app/services/model_facts.py` | The model's measured figures, read at runtime instead of being written into prompts |
| `backend/models/forenxai/CHANGES.md` | Handover note on the bundle |
| `backend/app/services/model_service.py` | Feature count checked against the manifest (no longer fixed at 74); each flow gets `abstained`, `abstain_reason` and `ood_distance` |
| `backend/verify_bundle.py`, `backend/inspect_bundle.py` | Check the bundle's hashes and contents |

### The 66 model features

The model reads these 66 CICFlowMeter features, in this order: the order is
fixed by `features.pkl` and `manifest.json` (`feature_order`) and must match
the scaler. `model_service.py` checks the count against the manifest and the
names against the feature contract before predicting.

| # | Feature | # | Feature | # | Feature |
|---|---|---|---|---|---|
| 1 | ACK Flag Count | 23 | ECE Flag Count | 45 | Fwd Packet Length Std |
| 2 | Average Packet Size | 24 | FIN Flag Count | 46 | Fwd Packet/Bulk Avg |
| 3 | Bwd Bulk Rate Avg | 25 | FWD Init Win Bytes | 47 | Fwd Segment Size Avg |
| 4 | Bwd Bytes/Bulk Avg | 26 | Flow Bytes/s | 48 | Fwd URG Flags |
| 5 | Bwd Header Length | 27 | Flow Duration | 49 | PSH Flag Count |
| 6 | Bwd IAT Max | 28 | Flow IAT Max | 50 | Packet Length Max |
| 7 | Bwd IAT Mean | 29 | Flow IAT Mean | 51 | Packet Length Mean |
| 8 | Bwd IAT Min | 30 | Flow IAT Min | 52 | Packet Length Min |
| 9 | Bwd IAT Std | 31 | Flow IAT Std | 53 | Packet Length Std |
| 10 | Bwd IAT Total | 32 | Flow Packets/s | 54 | Packet Length Variance |
| 11 | Bwd Init Win Bytes | 33 | Fwd Bulk Rate Avg | 55 | Protocol |
| 12 | Bwd PSH Flags | 34 | Fwd Bytes/Bulk Avg | 56 | RST Flag Count |
| 13 | Bwd Packet Length Max | 35 | Fwd Header Length | 57 | SYN Flag Count |
| 14 | Bwd Packet Length Mean | 36 | Fwd IAT Max | 58 | Subflow Bwd Bytes |
| 15 | Bwd Packet Length Min | 37 | Fwd IAT Mean | 59 | Subflow Bwd Packets |
| 16 | Bwd Packet Length Std | 38 | Fwd IAT Min | 60 | Subflow Fwd Bytes |
| 17 | Bwd Packet/Bulk Avg | 39 | Fwd IAT Std | 61 | Subflow Fwd Packets |
| 18 | Bwd Segment Size Avg | 40 | Fwd IAT Total | 62 | Total Bwd packets |
| 19 | Bwd URG Flags | 41 | Fwd PSH Flags | 63 | Total Fwd Packet |
| 20 | CWR Flag Count | 42 | Fwd Packet Length Max | 64 | Total Length of Bwd Packet |
| 21 | Down/Up Ratio | 43 | Fwd Packet Length Mean | 65 | Total Length of Fwd Packet |
| 22 | Dst Port | 44 | Fwd Packet Length Min | 66 | URG Flag Count |

By group:

| Group | Count | Features |
|---|---|---|
| Flow totals and duration | 8 | Flow Duration, Total Fwd Packet, Total Bwd packets, Total Length of Fwd Packet, Total Length of Bwd Packet, Flow Bytes/s, Flow Packets/s, Down/Up Ratio |
| Packet sizes | 16 | Fwd and Bwd Packet Length Max / Min / Mean / Std; Packet Length Max / Min / Mean / Std / Variance; Average Packet Size; Fwd and Bwd Segment Size Avg |
| Inter-arrival times (IAT) | 14 | Flow IAT Max / Min / Mean / Std; Fwd and Bwd IAT Total / Max / Min / Mean / Std |
| TCP flags | 12 | FIN, SYN, RST, PSH, ACK, URG, CWR, ECE Flag Counts; Fwd and Bwd PSH Flags; Fwd and Bwd URG Flags |
| Headers and windows | 4 | Fwd and Bwd Header Length; FWD and Bwd Init Win Bytes |
| Bulk transfer | 6 | Fwd and Bwd Bytes/Bulk Avg, Packet/Bulk Avg, Bulk Rate Avg |
| Subflows | 4 | Subflow Fwd / Bwd Packets and Bytes |
| Service | 2 | Dst Port, Protocol |

**Removed in the 74 -> 66 rebuild:** Active Mean, Active Std, Active Max,
Active Min, Idle Mean, Idle Std, Idle Max and Idle Min. TRUSTLab exports these
eight without populating them: four are zero in all 1,400,000 rows, Active
Max equals Idle Max in every row, Active Mean is exactly half of Active Max,
and Active Max equals Flow Duration / 1e6. CICFlowMeter fills them properly
from a real capture, so keeping them would feed the model values it never
trained on (`EXCLUDED_DEGENERATE_COLUMNS` in `model_service.py`). Identifier
columns (Flow ID, Src/Dst IP, Src Port, Timestamp, Label) are never model
inputs.

### Abstain layer: out-of-distribution (OOD) statistics

A flow is **abstained** when the model should not be trusted on it: it lies
too far from the training data, or its confidence is below its class's
threshold. Stored in `backend/models/forenxai/ood_stats.json` and
`decision_thresholds.json`; applied by `abstain_decisions()` in
`backend/app/services/model_service.py`.

**Distance measure:** squared Mahalanobis distance of the flow's 66 scaled
features `x` from the training mean `μ`, using the inverse covariance `Σ⁻¹`:

    D²(x) = (x − μ)ᵀ Σ⁻¹ (x − μ)

| Statistic | Value | Meaning |
|---|---|---|
| Method | `mahalanobis_squared` | Distance that accounts for how features vary together |
| Fitted on | `mc_train_random.parquet`, 85% training split, after the bundle's scaler | The test split was never used |
| Mean vector `μ` | 66 values | The average training flow (scaled units) |
| Inverse covariance `Σ⁻¹` | 66 × 66 matrix | Feature co-variation, inverted |
| Shrinkage | 1e-6 | Added to `Σ` before inversion for numerical stability |
| Threshold | **554.10** | 99th percentile of training distances |
| Training median | 12.22 | Typical distance of a training flow |

A flow with `D² > 554.10` gets `abstained = true`,
`abstain_reason = "out_of_distribution"` and `ood_distance = D²`.

**Verification** (from `ood_stats.json`):

| Data | Flows flagged OOD |
|---|---|
| TRUSTLab training | about 1% (by construction: p99) |
| TRUSTLab held-out test | 1.04% |
| CSE-CIC-IDS2018 | 65.29% |

Traffic from another network is mostly recognised as unfamiliar, which is
what the layer is for.

**Confidence thresholds** (`decision_thresholds.json`, fitted on a 15%
validation split of the training data): a flow whose top probability is
below its class's threshold gets `abstain_reason = "low_confidence"`.

| Class | Threshold | Class | Threshold |
|---|---|---|---|
| API | 0.575 | Evasion | 0.525 |
| Benign | 0.200 | Exfiltration | 0.200 |
| Bruteforce | 0.350 | Exploitation | 0.475 |
| BufferOverflow | 0.475 | MITM | 0.550 |
| C2Beaconing | 0.200 | PortScan | 0.700 |
| DDoS | 0.200 | Slowloris | 0.200 |
| DNS | 0.200 | TLSSSL | 0.425 |
| DoS | 0.200 | WebBased | 0.200 |

**Effect on the TRUSTLab test split** (measured once, thresholds never
tuned on it):

| | Without abstain layer | With abstain layer |
|---|---|---|
| Accuracy | 0.9351 | 0.9374 |
| Macro F1 | 0.9305 | 0.9332 |
| Flows abstained | 0% | 1.54% (1.04% OOD, 0.50% low confidence) |
| Error rate on kept flows | | 6.26% |
| Error rate on abstained flows | | 21.60% |

In the application, `decide()` gives an abstained flow the rule's class when a
rule fired (source `rule`), and otherwise the verdict **Uncertain** (source
`abstain`) for analyst review.

## 2. Tier 1 rules: flow records

**Purpose:** behaviour rules that run beside the model on the CICFlowMeter
CSV. Every threshold lives in one file.

| Path | Change |
|---|---|
| `backend/app/services/rule_service.py` | Ten rules over 60-second windows: PortScan, DDoS (off), DoS, Slowloris, Bruteforce, C2Beaconing, Exfiltration, DNS amplification, failed TLS handshakes and oversized packets (off). Also the allowlist, the priority order and `decide()`, which gives each flow its hybrid verdict |
| `backend/app/rules/rules.json` | All thresholds and sensitivity levels, the Tier 2 settings, the Suricata class mapping and the table of classes the rules decide |
| `backend/app/rules/rules_tuning.json`, `backend/tune_rules.py`, `backend/validate_rules.py` | Tuning without leakage: flows in even-numbered minutes choose the thresholds and flows in odd-numbered minutes test them, on TII-SSRC-23 and CSE-CIC-IDS2018 |
| `backend/test_rules.py` | Tier 1 tests, including the tuned thresholds |

### Basis of the Tier 1 rules (PortScan and DoS)

**Definitions.** The rules follow the behavioral definitions of scanning and
flooding used by signature-based intrusion detection systems: a port scan is
one source touching many ports of a host with almost no data each, and a DoS
flood is one source opening a very large number of connections to one
service. Counting distinct ports per source, or connections per service,
inside a time window is the approach of Snort's port-scan detector and Zeek's
scan-detection policy. The 60-second window and the starting values (20 ports,
100 flows) come from the hybrid-detection design document
(https://claude.ai/artifact/3TFCNHCBAMkv5jfg2hNKQm).

| Rule | Fires when | Grouped by |
|---|---|---|
| T1-PORTSCAN-01 | ≥ 50 distinct destination ports from one source to one host within 60 s, median ≤ 3 forward packets per flow | source, destination host, window |
| T1-DOS-01 | ≥ 800 flows from one source to the same destination and port within 60 s (DNS, DHCP, NTP, NetBIOS ports excluded) | source, destination host, port, window |

**How it runs.** `rule_service.py` reads the CICFlowMeter CSV, places each flow
in the 60-second window it started in, groups the flows as above, counts
distinct ports (PortScan) or flows (DoS), and marks every flow of a group that
reaches the threshold with a hit whose evidence states the count and the
threshold. `decide()` then uses the hit: PortScan and DoS are rule-trusted
classes, so their hits set the verdict.

**Tuning.** `tune_rules.py` chose the thresholds on TII-SSRC-23 and
CSE-CIC-IDS2018, the labelled datasets that keep real IP addresses and
timestamps. Flows in even-numbered minutes chose; flows in odd-numbered
minutes tested. The selection rule was the best F1 on the rule's class with
benign false alarms of at most 1%. Candidates: PortScan 10, 15, 20, 30, 50
ports (50 chosen); DoS 50, 100, 200, 400, 800 flows (800 chosen). The
sensitivity setting scales both (high ×0.7: 35 ports / 560 flows; low ×1.5:
75 ports / 1,200 flows).

**Held-out results** (`rules_tuning.json`):

| Rule | Recall | Precision | F1 | Benign false alarms |
|---|---|---|---|---|
| PortScan | 0.9997 | 0.9636 | 0.9813 | 0.02% |
| DoS | 0.9939 | 0.9268 | 0.9592 | 0.00% |

**Port scan vs DoS.** The rules measure different things, so a normal port
scan cannot meet the DoS condition: a scan spreads a few flows over many
ports, while a flood puts many flows on one port. The PortScan/DoS confusion
comes from the classifier, which judges one flow at a time; Tier 1 judges the
pattern across flows. On LabActivity2 (a port scan, 2,016 flows) the classifier
labelled 1,704 scan flows DoS and 248 Slowloris; the PortScan rule flagged
2,000 flows and the DoS rule none, so the verdict for those 2,000 flows is
PortScan (source `rule`). If both rules fired on one flow, the priority order
in `rules.json` would put DoS first; that requires the same source to also
send ≥ 800 flows to a single port within a minute.

**Limits.** Slow or distributed scans (under 50 ports per minute per source)
and low-rate floods (under 800 flows per minute) are not detected; attacks
split across two windows can fall below the threshold in each; thresholds are
network-dependent, hence adjustable in `rules.json`; the rules could not be
validated on TRUSTLab, whose addresses and timestamps are anonymised.

**Sources.** M. Roesch, "Snort: Lightweight intrusion detection for networks,"
LISA 1999; V. Paxson, "Bro: A system for detecting network intruders in
real-time," *Computer Networks* 31 (1999); H. Asad, S. Adhikari and I. Gashi,
"A perspective–retrospective analysis of diversity in signature-based
open-source network intrusion detection systems," *Int. J. Inf. Secur.* 23
(2024), doi:10.1007/s10207-023-00794-9; A. Khraisat et al., "Survey of
intrusion detection systems," *Cybersecurity* 2 (2019),
doi:10.1186/s42400-019-0038-7. Zeek's scan-detection defaults should be
checked against the current Zeek documentation before citing.

## 3. Tier 2 rules: packets and Suricata

**Purpose:** detect what flow records cannot show: ARP spoofing, header
tricks and attacks carried in unencrypted payloads.

| Path | Change |
|---|---|
| `backend/app/services/packet_rule_service.py` | scapy checks for MITM, Evasion, WebBased (patterns and 4xx sweeps), API, Bruteforce (failed logins), DNS tunnelling, old TLS versions and BufferOverflow. Patterns split across TCP segments are still found. Also runs Suricata, maps its alerts to classes, attaches packet hits to flow rows and marks flows with encrypted payloads |
| `backend/app/services/pcap_service.py` | Tier 2 sees each packet during the pcap read the application already does, so the capture is read once |
| `backend/update_suricata_rules.py`, `tools/README.md` | Download the ET Open ruleset (52,473 signatures) to `tools/suricata/`, which git ignores; setup notes |
| `backend/test_packet_rules.py` | Tier 2 tests, including link types (Ethernet, VLAN, SLL, raw IP, loopback, IPv6) as pcap and pcapng |

## 4. Pipeline and capture handling

**Purpose:** combine the model, SHAP, both rule tiers and the verdict, and
accept any pcap or pcapng.

| Path | Change |
|---|---|
| `backend/app/api/analysis.py` | Runs Tier 1, Tier 2 and `decide()`. Adds `verdict`, `verdict_source` and `payload_encrypted` to each flow, and a `rule_analysis` block (chart data, Suricata status) to `analysis.json` |
| `backend/app/services/cicflowmeter_service.py` | Detects the capture format from the file's first bytes rather than its extension. Re-frames Linux cooked (SLL) and loopback captures as Ethernet, which CICFlowMeter cannot otherwise read |
| `backend/app/utils/runtime_paths.py`, `backend/app/main.py`, `backend/FORENXAI.Backend.spec` | Path handling; `app/rules` is included in the packaged application |

## 5. Recommendations and AI-generated summary (RAG)

**Purpose:** recommendations drawn from cited documents and grounded in the
prediction, SHAP and the rule evidence. The language model restates facts and
adds none of its own.

| Path | Change |
|---|---|
| `backend/app/services/recommendation_service.py` | Retrieval and generation for all 15 attack classes. Each action is checked against its sources and cited in ACM style |
| `backend/app/services/narration_service.py`, `backend/app/services/llm_provider.py` | AI-generated summary that restates the flow's facts only; one Qwen generation at a time |
| `rag/config/*.py`, `rag/knowledge/**`, `rag/_sources/*`, `rag/README.md`, `rag/RAG_PIPELINE.md` | Knowledge corpus (11 playbooks, 15 attack profiles, glossary, caveats), the source index and the build scripts |
| `backend/test_rag_pipeline.py`, `backend/test_narration_rag.py`, `backend/test_recommendations*.py`, `backend/bench_recommendations.py` | Tests and a benchmark |

## 6. Desktop interface

**Purpose:** show the rule results next to the predictions.

| Path | Change |
|---|---|
| `frontend/FORENXAI.Desktop/Views/DashboardView.xaml(.cs)` | New "Rule-based detection" panel with two bar charts (flows flagged per class for Tier 1 and for Tier 2), the Suricata and encryption status, and a bar showing who decided each verdict. The threat table gains Rule and Verdict columns and also lists flows that only the rules flagged |
| `frontend/FORENXAI.Desktop/Views/XaiView.xaml(.cs)` | The basis of each recommendation (model, SHAP, rules), a verdict badge, the tier of each rule hit, abstain and encrypted-payload notes, scrollable bulleted panels and the "AI-GENERATED SUMMARY" section |
| `frontend/FORENXAI.Desktop/Models/AnalysisModels.cs` | Fields for rule hits, verdicts and the rule analysis |
| `frontend/FORENXAI.Desktop/Services/BackendApiService.cs` | Small API adjustments |

## 7. Setup and sample data

`README_FORENXAI.md`, `backend/requirements.txt`, `tools/jdk.path`,
`.gitignore`, `.gitattributes`, `backend/models/llm/README.md` and
`backend/sample_data/*` cover setup, dependencies, the project-local JDK used
by CICFlowMeter, and sample data for the tests.

---

## Setting up this branch

```
git checkout finetuned-xgboost
winget install --id OISF.Suricata --exact     # optional: enables the Suricata part of Tier 2
cd backend
python update_suricata_rules.py               # writes tools/suricata/et-open.rules
python test_rules.py
python test_packet_rules.py
```

Without Suricata the analysis still runs; each case records "Suricata not run"
and the scapy checks cover Tier 2.

## Known limitations

- The DDoS and oversized-packet rules ship disabled. On held-out data DDoS
  flagged 6.7% of benign flows, and the oversized-packet rule caught none of
  16,000 BufferOverflow flows.
- Tier 2 has not been scored on labelled attack captures.
- Rules override the model only for PortScan and DoS, the two rules measured
  as precise on held-out data.
- Slowloris, C2Beaconing, Exfiltration, DNS and TLS thresholds are starting
  values: no labelled data was available to tune them.
- Cases analysed before this branch show "Not in this case" in the rule panel.

### Tier 2 validation: out of scope

The packet-level (Tier 2) rules and the Suricata layer are implemented and
functionally tested, but not statistically validated. Validation needs
labelled packet captures for the same fifteen attack families the model was
trained on. TRUSTLab publishes flow records only; its authors were asked for
the original captures without a reply; and no public dataset covers all
fifteen families (API attacks have none). Combining public datasets would
cover about ten classes but mix networks and labelling methods, so it was not
used to report figures. Safeguard: Tier 2 is advisory by design and cannot
change a verdict; only PortScan and DoS (Tier 1, measured on held-out data)
may. The validation procedure is the one already used for Tier 1 (split by
capture, tune for best F1 with benign false alarms of at most 1%, test once);
it needs only the captures.

### Detection limitations per attack class

| Class | Detected by | Limitation | Public labelled PCAPs |
|---|---|---|---|
| PortScan | Tier 1 (validated, decides); Suricata | Misses slow scans (under 50 ports per minute per source) and scans spread over several sources | Yes (CIC-IDS2017, CSE-CIC-IDS2018, CICIoT2023) |
| DoS | Tier 1 (validated, decides); Suricata | Misses low-rate floods (under 800 flows per minute to one port); name-service ports excluded | Yes |
| DDoS | Model; Suricata | Tier 1 rule disabled (6.7% benign false alarms); many sources each below the per-source threshold go unflagged | Yes |
| Slowloris | Tier 1 (untuned); Suricata | Threshold untuned; only the listed web ports are checked | Yes (CIC-IDS2017) |
| Bruteforce | Tier 1 (weak, F1 0.28); Tier 2 | Failed-login replies are readable only in plain protocols (FTP, SMTP, POP3, Telnet, HTTP); SSH and HTTPS attempts rely on counting | Yes |
| C2Beaconing | Tier 1 (untuned); Suricata | Beacons with random jitter break the regularity test; encrypted C2 shows only timing; signatures need known malware (abuse.ch feeds unreachable from the development network) | Yes (bot traffic) |
| Exfiltration | Tier 1 (untuned); Suricata | Only single flows over 10 MB with little return traffic; slow or split exfiltration missed; DNS-based exfiltration only through the DNS-name check | Partial (CIC-Bell-DNS-EXF-2021) |
| DNS | Tier 1 amplification (untuned); Tier 2 tunnelling | Encrypted DNS (DoH, DoT) not visible; DNS spoofing detection not yet implemented | Partial (CICIoT2023, CIC-Bell-DNS-EXF-2021) |
| TLSSSL | Tier 1 (untuned); Tier 2 | Only failed handshakes and outdated protocol versions; certificate problems and TLS-library exploits beyond the signatures not checked | Partial (Heartbleed in CIC-IDS2017) |
| MITM | Tier 2 only | Only ARP, IPv6 neighbour and DHCP spoofing; Suricata does not parse ARP; DNS spoofing not yet implemented | Yes (CICIoT2023) |
| Evasion | Tier 2; Suricata | Covers illegal flags, overlapping fragments and TTL changes; application-layer obfuscation beyond the decoders is missed | Partial (scan variants; synthetic via ID2T) |
| WebBased | Tier 2; Suricata | Plain HTTP only; heavily obfuscated or novel payloads may evade the pattern families and signatures | Yes (CIC-IDS2017, CICIoT2023) |
| API | Tier 2 only (counting) | No custom API signatures yet; most APIs use HTTPS, so content is usually not inspectable | None found |
| Exploitation | Suricata only | Known exploits only; new vulnerabilities are detected only if the model flags them | Yes (UNSW-NB15) |
| BufferOverflow | Tier 2; Suricata | Tier 1 oversized-packet rule off (0 of 16,000); NOP-sled and filler checks miss polymorphic shellcode | Yes (UNSW-NB15) |
| Benign | Allowlist | Allowlist empty by default; "no rule fired" does not prove traffic is benign | — |

General: signatures detect known attacks only; payload checks apply to
unencrypted traffic only; thresholds depend on the network (hence adjustable
in `rules.json`); Tier 1 could not be validated on TRUSTLab because its
addresses and timestamps are anonymised; analysis covers only the traffic in
the uploaded capture.

Dataset coverage sources: Villafranca et al. 2026 (TRUSTLab; notes several
families are "underrepresented in many contemporary datasets"); Neto et al.
2023 (CICIoT2023, *Sensors* 23(13):5941); CIC-IDS2017 and CIC-Bell-DNS-EXF-2021
(UNB dataset pages). UNSW-NB15 and Heartbleed coverage should be confirmed on
their dataset pages before citing.

## Tier 2: improvements

Status of the twelve improvements. Code is in
`backend/app/services/packet_rule_service.py`, settings in
`backend/app/rules/rules.json`, tests in `backend/test_packet_rules.py`.

### Done

| # | Improvement | What was done |
|---|---|---|
| 3 | Suricata HOME_NET per capture | `suricata.home_net: "auto"` passes the private ranges plus the 256 busiest hosts that received connections; `external_net: "any"` keeps attacks between two internal hosts in scope. On LabActivity2, Suricata went from 0 to 23 class-mapped alerts (ET SCAN, all mapped to PortScan, which is correct for that scan) |
| 4 | More Suricata output | TLS log events are read: a session that negotiated SSL 2/3 or TLS 1.0 fires T2-TLS-02, the server's choice, which the ClientHello check alone cannot see. HTTP and DNS logs are not used yet |
| 5 | Alert-to-class mapping | `suricata.sid_classes` maps a signature ID to a class (or `null` to ignore it) before the prefix rules apply; unmapped signatures are listed in the Dashboard |
| 6 | Stream handling | HTTP requests are rebuilt by TCP sequence number, so out-of-order segments and retransmissions no longer hide or duplicate a match. The request and payload-tail buffers evict the least recently used entry instead of being cleared during floods |
| 7 | WebBased decoding | In addition to URL decoding, HTML entities, `%uXXXX` and backslash-u escapes, and printable base64 tokens are decoded before matching |
| 8 | STARTTLS | A flow that sends STARTTLS, AUTH TLS or AUTH SSL is marked encrypted, and content rules stop inspecting it |
| 9 | MITM coverage | IPv6 neighbour advertisements (several MACs for one address) and more than one DHCP server answering now fire T2-MITM-01. MITM hits mark the contested host's flows only for `attach_window_seconds` (300 s) after the spoof |
| 10 | Flow matching | Non-first IP fragments take the first fragment's ports. The time offset is chosen among the quarter-hour estimate, one step either side and zero, by how many hit times fall inside a flow with their own 5-tuple. Suricata's input and output paths are resolved to absolute paths (a relative evidence path made Suricata fail) |
| 12 | Interface | The Dashboard lists capture-level hits with their evidence, and the Suricata signatures that mapped to no class. The whole Dashboard now scrolls |

### Suricata rulesets

`backend/update_suricata_rules.py` merges the free rulesets from the OISF
ruleset index into `tools/suricata/et-open.rules`: ET Open (52,483
signatures), Positive Technologies ptrules/open and ptresearch/attackdetection
(exploits, malware), aleksibovellan/nmap (scan types, mapped to PortScan or
Evasion), abuse.ch SSLBL JA3 and certificate rules (C2 over TLS), and
Suricata's own decoder, stream, http, dns, tls, smtp and app-layer event
rules. Unreachable sources are skipped and reported. On 26 Sep 2026
ptrules/open and the abuse.ch feeds timed out from the development network;
52,956 rules loaded. `suricata.class_mapping` maps the new signature prefixes
(`ATTACK [PTsecurity]` to Exploitation, `MALWARE [PTsecurity]` and `SSLBL` to
C2Beaconing, `POSSBL` scans to PortScan or Evasion). API and MITM have no
free Suricata ruleset (Suricata does not parse ARP); both stay covered by the
scapy checks T2-API-01 and T2-MITM-01.

### Still open (these need data or a long run)

1. **Score Tier 2 on labelled captures.** No Tier 2 rule has a measured
   precision, recall or benign false-alarm rate. TRUSTLab ships flow CSVs
   only. Candidate data: the CIC-IDS2017 pcaps (Tuesday FTP/SSH brute force,
   Wednesday slow DoS, Thursday web attacks, Friday port scans) with their
   labelled flow CSVs, or lab captures with one attack per class. This is
   needed before any Tier 2 class can be added to `decision.trust`.
2. **Tune the thresholds.** All Tier 2 values are the design's starting
   points. Reuse the Tier 1 method in `backend/tune_rules.py` (choose on even
   minutes, test on odd minutes, benign false alarms of at most 1%) once
   item 1 provides data.
11. **Speed on large captures.** Neither the scapy checks nor Suricata have
    been timed on LabActivity3 (183 MB, about 435,000 flows).

Also not covered yet: DNS spoofing (MITM), and Suricata's HTTP and DNS logs.
