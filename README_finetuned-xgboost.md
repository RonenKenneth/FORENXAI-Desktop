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
