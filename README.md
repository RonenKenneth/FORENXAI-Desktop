# FORENXAI

FORENXAI is a Windows desktop application for post-incident network forensic analysis. It accepts PCAP/PCAPNG evidence, extracts flow-level features with CICFlowMeter, classifies network traffic with an XGBoost model, explains model decisions with TreeSHAP, generates grounded local narration with Qwen 2.5 3B, provides deterministic recommendations, supports investigator review, and produces case reports.

**Setting up a new machine: follow [`SETUP.md`](SETUP.md).** This file records what changed on the branch and why.

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

### Merge of `main` 38810d7 (Phase 22–25: Cases, Investigation, polish), 28 Sep 2026

`main` added Case Management, the Investigation workspace, UI polish and two Dashboard cards. It did not change the model bundle, `model_service.py` or `shap_service.py`, so the branch keeps the tuned 66-feature XGBoost and its TreeSHAP (`main` still carries the older 74-feature bundle, unchanged since the branches split).

**Taken from `main`:**
- **Case Management:**
  - Backend: `api/cases.py` and `services/case_service.py` add `GET /cases`, `GET /cases/{id}` and `DELETE /cases/{id}`.
  - Desktop app: a new Cases page lists, opens and deletes cases. Deletion asks for confirmation, and the case that is open can't be deleted.
  - Delete accepts only `FX-YYYYMMDD-HHMMSS` folders directly inside the cases folder.
- **Investigation workspace:** `InvestigationView` gets search, review and priority filters, Next Unreviewed, review progress, and Review Selected, which opens XAI on the exact flow. It replaces our "Coming soon." page, and `MainWindow` keeps `main`'s `Investigation_Click`, which needs an open case.
- **Dashboard:** two new cards, Total Packets and Forensic Flows (packet conversations), plus thousands separators.
- **Visual styles:** `main`'s button and text-box styles on the XAI and Evidence pages.

**Kept from this branch:**
- **Dashboard layout:** `main` restyled the old Selected Threat card and SHAP table, which this branch had replaced.
- **Evidence Start button:** its inline style keeps the dark disabled look used across the app. `main`'s `SuccessButtonStyle` still exists but isn't applied to this button.
- **XAI bullet template:** kept alongside `main`'s styles.

**Changed after the merge:**
- **Investigation follows the verdict.**
  - New columns: **Verdict (evidence)**, worded as the Dashboard's Supporting Evidence, **ML Prediction** and **ML Confidence**.
  - Priority rules:

    | Priority | Rule |
    |---|---|
    | High | A rule backs the verdict (`rule` / `agree`), or ML confidence ≥ 90% |
    | Medium | ML confidence ≥ 70% |
    | Low | Otherwise |
    | **Uncertain** | The model abstained and no rule fired |

  - Unreviewed flows are sorted High, Uncertain, Medium, Low.
  - LabActivity2: 2,007 High, 6 Uncertain, 2 Medium, 0 Low. These match an independent count.
- **Case list speed:** it read each case's full `analysis.json` (about 70 MB) on every refresh, taking 22 s for 35 cases. The totals are now cached in `summary.json` beside it and rebuilt when the analysis is newer, so a refresh takes 0.05 s after the first. Open now uses the same cached analysis call as the Dashboard, so a case is downloaded once, not twice. Covered by `test_cases.py`.

**Checked:**
- `dotnet build`: 0 errors, 0 warnings.
- `run_tests.py`: 9/9 suites pass.
- In the app:
  - The Cases page lists 40 cases; opening `FX-20260928-071432` loads the Dashboard (10,584 packets, 6,996 forensic flows, 2,016 ML flows).
  - Investigation lists 2,015 threat flows with the verdict column and correct priority counts.
  - Review Selected opens flow 249 in XAI with its SHAP table.

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

### Packets, encryption and loading (28 Sep 2026)

**Packets read like Wireshark.** `pcap_service.describe()` gives every packet its
highest recognised protocol and a one-line summary of its contents: ARP ("Who has
192.168.50.1? Tell 192.168.50.102"), DNS queries and responses, DHCP, ICMP and
ICMPv6 message types, TLS records (Client Hello, Application Data...), SSH
banners, HTTP request lines, TCP ports, flags, sequence numbers and payload
length, well-known UDP services (NBNS, SSDP, MDNS...) and IP protocols (IGMP,
GRE, ESP/AH...). ICMP is now its own transport instead of "OTHER". Tested on
LabActivity2 (10,584 packets: TCP, ICMP, ARP, DNS, ICMPv6, IGMP, NBNS) and on
LabActivity3 (2.55 million packets, including TLS Client Hellos, DNS, SSDP,
WS-Discovery).

**Encryption is judged on evidence.** Ethernet pads short frames to 60 bytes and
scapy files the pad under TCP, so bare SYN/RST probes looked like 6-byte
payloads, and any flow on port 443, 993, 22... was called encrypted. LabActivity2
showed "15 encrypted flows, 99% inspectable"; none of the 15 carried a TLS
record or SSH banner. Padding is now stripped (`_l4_payload`), and a flow is
encrypted only when a TLS record, SSH banner, STARTTLS, or payload on an
encrypted port is seen. LabActivity2: 0 encrypted flows, 100% inspectable,
matching an independent scan of the packets.

**Loading.** Packets moved out of `analysis.json` into `packets.json`, served a
page at a time (`GET /analysis/{case_id}/packets`, filtered on the server by
protocol, TCP flag, ML attack and text). Each flow carries its connection's
totals (bytes, packets, flags, first time) for the Length and Info columns.
`GET /analysis/{case_id}` streams the stored file instead of re-encoding it
(about 20 s before, 0.16 s now); responses are gzip-compressed (43 MB to 1 MB
on the wire, 0.58 s); the app decompresses and parses the stream directly and
fetches each case once for the Dashboard and XAI tabs; narration and report
requests reuse one cached parse of the file.

**Verified.** An independent recomputation from the capture and the flow CSV
matches every value shown (15 checks): packet and byte counts, protocol counts,
flow counts, per-flow Length and Info, the four cards, Traffic classification,
both tier charts, the hybrid source line, the rule-based attacks pie, encryption
and inspectable share. The values read from the running app's Dashboard and
Reports tabs are the same, and the packet filters return the expected counts
("who has": 510; "SYN 192.168.50.104": 1,003). Model, abstain layer and
TreeSHAP: 25/25. `test_packet_parsing.py` covers protocol/info, padding,
encryption and the packet store.

### Filters, packet columns and reproducibility (28 Sep 2026)

**Packets table: every field of the capture, no ML column.** Frame (captured and
wire length, interface, comment), Ethernet (source/destination MAC, EtherType,
VLAN), IP (version, TTL/hop limit, ID, flags, fragment offset, DSCP, ECN, header
and total length), TCP (flags, sequence, acknowledgement, window, header length,
options), UDP length, ICMP type/code, payload length, relative time and the
Wireshark-style protocol and info. Columns a capture has no value for (VLAN,
comments...) are hidden.

**Filters, scoped to the capture.** Every option lists only what the capture
contains.
- Detected threats: protocol, ML prediction, ML confidence band, supporting
  evidence, evidence source (Tier 1 flow rule, Tier 2 packet rule, model only,
  uncertain), source IP, destination IP, port (either side), search.
- Packets (filtered on the server, 1,000 per page): protocol, TCP flag, source
  and destination (IP or MAC), IP version, interface, port (either side), length
  range, search across every field.
- Search boxes match every word typed; "Clear filters" resets each table.
- Checked in the running app against independent counts: ML = PortScan 4,
  model only 8, destination .104 + port 22 1, confidence below 50% 4; packets
  DNS 26, source .104 + RST 997, port 53 27, length 100–200 6. All equal.

**CICFlowMeter's ARP pseudo-flow.** CICFlowMeter folds non-IP frames into one
flow whose "addresses" are ARP header bytes (LabActivity2: 520 ARP frames as
`8.6.0.1 -> 8.0.6.4`, protocol 0, ports 0). The backend flags it
(`pseudo_flow`) when neither address occurs in the capture; the Dashboard shows
it as "Non-IP frames (ARP)". ICMP and IGMP flows also have protocol 0 and ports 0
but real addresses, so they are shown as they are.

**Reproducible results.** Suricata ran multi-threaded, so threshold rules
(e.g. "ET SCAN Potential SSH Scan", 5 in 120 s) fired on a different probe from
run to run, and Tier 2 flagged different flows for the same capture. Suricata
now runs with `--runmode single`. Two analyses of LabActivity2 are identical in
ML predictions and confidence, Tier 1 and Tier 2 hits, supporting evidence,
encryption and pseudo-flow flags, the rule summary, and the packet data.

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

### Measured values vs fixed text

An audit checked each value shown in the app. Each value either comes from the capture or is fixed text.

**Measured from the capture:**
- counts and connection totals;
- Tier 1 measurements;
- Tier 2 and Suricata hits (the severity comes from each alert);
- ML class, confidence and SHAP.

**Fixed values from `rules.json`:** thresholds, time window and rule severity. These are labelled as configuration.

Three fixed values had been shown as measurements. They are now either measured or labelled.

- **Flow coverage (Tier 1 and ML input).**
  - CICFlowMeter writes a flow only when it has more than one packet (`FlowGenerator.java`: `if (flow.packetCount() > 1)`). The training data was built the same way, so the model never saw single-packet flows. CICFlowMeter is left unchanged.
  - Instead, `packet_store.capture_coverage()` compares the capture's conversations with the flow records and stores the result in `analysis.json` (`capture_coverage`). The Tier 1 card shows it.
  - On LabActivity2 the flow records hold 2,013 of 6,996 TCP/UDP conversations. The other 4,983 are single-packet, mostly unanswered SYN probes, for example 192.168.50.102 → .1 on 2,000 ports.
  - Tier 2 (Suricata and the packet rules) and the Packets table read these probes; the ML and Tier 1 do not.
- **Flow counts.**
  - The Evidence tab now bases its low-flow warnings on the flows analysed (CICFlowMeter), not on packet conversations. It shows both counts, each labelled.
  - The PDF's "Custom Flows" row is now "Packet conversations (both directions)".
- **Class text.**
  - The recommendation summary is one knowledge-base text per class and is not measured from the capture. The XAI tab now labels it as the class profile.
  - The Reports tab now shows the recommended action for the ML class.
  - The per-class F1 in the XAI tab and the AI summary is now labelled as the TRUSTLab test-set figure from training.

### Charts, rules vs ML, packets to XAI (28 Sep 2026)

| Area | Change | Files |
|---|---|---|
| Dashboard charts | The Hybrid source strip is removed. Both charts now show the uncertain part themselves. Traffic classification draws flows the model abstained on as a grey "Uncertain" slice. Rule-based detected attacks adds "Uncertain" for flows with no rule where the model abstained. Every non-empty slice is drawn at least 4° wide so small groups stay visible; the legends keep the exact counts | `Views/DashboardView.xaml(.cs)` |
| Rules vs ML | One line under both charts: Agree, Differ (with the most frequent pair, e.g. "ML DDoS vs rule PortScan, 2,001"), Model only, Uncertain | `Views/DashboardView.xaml(.cs)` |
| Packets to XAI | Double-click opens XAI whenever the packet has a flow. TCP and UDP match by connection. ICMP and IGMP match CICFlowMeter's protocol-0 flow for the same two hosts. ARP frames open the ARP pseudo-flow. Any other packet shows a warning that says why, e.g. a single-packet probe is not in the flow records | `Views/DashboardView.xaml.cs` |
| ICMP Info | ICMP errors are shown as in Wireshark, with the code name (RFC 792) and the packet they quote, e.g. "Destination unreachable (Protocol unreachable) for TCP 192.168.50.102:50764 > 192.168.50.100:256". In LabActivity2, host .100 answered each of 1,000 TCP probes from .102 this way | `backend/app/services/pcap_service.py`, `test_packet_parsing.py` |
| Packet columns | "Captured" is renamed "Bytes in file": the bytes saved for a packet. It differs from Length (bytes on the wire) only when the capture truncated packets (snaplen), so the column is shown only then | `packet_store.py`, `DashboardView` |
| Buttons | A dark button template in `App.xaml` for every view: disabled buttons are dimmed instead of white (Previous on page 1, Browse during an analysis) | `App.xaml`, `Views/EvidenceView.xaml` |

Checked in the app on a fresh LabActivity2 analysis:
- **Charts and summary line:** DDoS 2,009 and Uncertain 7; PortScan 2,001 and Uncertain 7; Rules vs ML reads agree 0, differ 2,001, model only 8, uncertain 7.
- **Double-click:** an ICMP packet opens flow 2012, a DNS query opens flow 2013, an ARP frame opens the ARP pseudo-flow 2010, and a single-packet SYN probe shows the warning.
### Rule basis, packet filters, setup and training code (28 Sep 2026)

| Area | Change | Files |
|---|---|---|
| Tier 1 rules | Every rule in `rules.json` has a `basis`, shown under its evidence in the XAI tab. There are three kinds of basis: (1) tuned and tested on labelled public data (PortScan, DoS, Bruteforce, DDoS), with the held-out figures; (2) matched to an open-source reference: the ET Open signatures run by Suricata (for example sid 2001219 "Potential SSH Scan", 5 SYNs in 120 s; sid 2016016 DNS amplification, 5 in 60 s) and US-CERT TA14-017A (DNS amplification factor 28–54); (3) heuristic, supporting evidence only (Slowloris, C2, Exfiltration, TLS). No threshold comes from the investigator's capture, and only PortScan and DoS decide a verdict | `backend/app/rules/rules.json`, `rule_service.py` |
| Tier 2 rules | Each scapy check has a basis: RFC 9293 (illegal TCP flags), Ptacek & Newsham 1998 and Handley et al. 2001 (fragment overlap, TTL changes), arpwatch conditions (MITM), ET sid 2002383 (5 failed FTP logins). Suricata hits cite their signature ID. The weak-TLS check now also flags **TLS 1.1**, which RFC 8996 deprecates (was TLS 1.0 and older) | `rules.json`, `packet_rule_service.py`, `test_packet_rules.py` |
| Flow coverage | `capture_coverage` in `analysis.json`, shown in the Tier 1 card. It records how many of the capture's conversations are in the CICFlowMeter records. On LabActivity2 that is 2,013 of 6,996; the other 4,982 are single-packet conversations, which CICFlowMeter never exports | `packet_store.py`, `analysis.py`, `DashboardView` |
| Labels | Evidence tab and PDF separate flows analysed (CICFlowMeter) from packet conversations. The XAI tab labels the recommendation summary as the class profile. Reports show the recommended action for the ML class. The per-class F1 is labelled as the TRUSTLab test-set figure from training | `EvidenceView`, `PdfReportService`, `XaiView`, `ReportsView`, `narration_service.py` |
| Packets filters | The Interface and IP version dropdowns stay enabled when the capture has one value (they looked broken when disabled); tooltips give the counts. Refilling the dropdowns and Clear filters no longer start one reload per box; a slower, older response can no longer replace a newer page. Disabled buttons (for example Previous on page 1) are dimmed instead of white | `DashboardView.xaml(.cs)` |
| Setup | New `SETUP.md`: software, venv, requirements, files outside Git, checks, run commands, environment variables, common problems. `requirements.txt` accepts llama-cpp-python 0.3.19 or later 0.3.x, so the prebuilt CPU wheel works | `SETUP.md`, `backend/requirements.txt` |
| Training code | The training pipeline's source, configuration, knowledge base, result tables and bundle documentation (3.8 MB) are copied from `forenxai_pipeline_full/forenxai_binary` into `training/`. Datasets, models and backups stay outside Git | `training/` |

Checked in this round:
- Coverage matches an independent count: 6,996 / 2,013 / 4,983.
- All 2,012 rule hits on LabActivity2 carry a basis.
- Packet filters in the app match counts computed from `packets.json`: eth0 10,584; eth0 + DNS 26; IPv6 11; port 22 13.
- Next and Previous page through 1,000 rows at a time.
- After fast edits (port 53, then empty, then 22), the table shows port 22.

Table 17 of the manuscript (the four TreeSHAP equations) was checked against the code:
- **Eq. 1, the Shapley value:** correct.
- **Eq. 2, additivity in margin space:** holds on the app's model. The maximum error is 3e-06 (`verify_model.py`).
- **Eq. 3, the class-conditional mean |SHAP| over R_k:** matches `per_class_own` in `training/scripts/15_explain_shap.py`. The pairwise matrix (Table 16, "All 120 class pairs") uses R = all sampled rows (`per_class`), and the text should say so.
- **Eq. 4, O(TL2^M) to O(TLD^2):** as in Lundberg et al., 2020.

Two statements in Table 16 describe training only:
- The app computes SHAP on the CPU (see "Backend crash fix").
- The app lists the top 10 contributors per flow, not 6.

### Packaging, Tier 1 list, SHAP sum, uncertain flows (28 Sep 2026)

| Change | What it does | Where |
|---|---|---|
| No hard-coded tool paths | CICFlowMeter, Maven, editcap and Suricata are found by `find_tool`. Order: environment variable, then the `tools\` folder beside the backend (or its .exe), then the standard install location, then `PATH`. The jNetPcap and Npcap folders follow from the CICFlowMeter folder and `%SystemRoot%`. `model_facts.json` and the ET Open rules resolve through `runtime_paths` too. Nothing points at the build machine | `backend/app/utils/runtime_paths.py`, `cicflowmeter_service.py`, `packet_rule_service.py`, `model_facts.py` |
| .exe build | The spec also collects scapy's layers and pypdf, which are loaded at runtime and invisible to PyInstaller. The model bundle is read from beside the .exe or, failing that, from the copy packed inside it. SETUP.md section 10 has the build commands and the folder layout | `backend/FORENXAI.Backend.spec`, `SETUP.md` |
| Tier 1 rules list | The Tier 1 card has a "Show Tier 1 rules" dropdown like Tier 2's. Each rule shows its role (decides / evidence / off), the flows it flagged, its description, thresholds and basis. The list comes from `rules.json` through `rule_catalog()` (`tier1_rules` in analysis.json) | `rule_service.py`, `DashboardView` |
| SHAP table adds up | Below the top 10, one row "Other N features (sum)". Under the table: base value + top 10 + other N = the class's log-odds score, and the note that softmax over the 16 scores gives the confidence. SHAP values add up to the score, not to the percentage. Checked on all 2,016 explained flows (error 0) | `shap_service.py` (`rest_count`, `rest_shap_sum`, `margin`), `XaiView` |
| Uncertain flows reviewable | XAI and Investigation list every abstained flow, including one the model called Benign. The fresh LabActivity2 case lists 2,015 threats + 1 uncertain = 2,016 to review | `XaiView`, `InvestigationView` |
| Tier 1 card | Shows only the flagged count, the detected attacks and the dropdown. The flow-record coverage note moved to the end of the dropdown | `DashboardView` |
| Exit warning and session cases | Closing the app always asks first. If cases were created in this session, the dialog lists them and explains that each holds a copy of the evidence, flows, analysis and reviews (personal data such as IP addresses). Yes deletes them and exits, No keeps them and exits, Cancel returns. Cases that fail to delete are listed before exit. Deletion removes the case folders; it is not a secure wipe. Reports exported elsewhere and the original evidence file are not touched | `MainWindow.xaml.cs`, `App.SessionCaseIds`, `EvidenceView` |
| Cases page | Buttons 34 px high ("Refresh", "Delete Case", "Open Case"). Cells centred with the header padding, selection drawn on the cells, numbers with separators, "—" for a case without totals | `CasesView.xaml` |

### Checks on this branch

| Check | Result |
|---|---|
| Backend import (`import app.main`) | OK |
| `backend/run_tests.py` (9 suites: model preprocessing and CPU device, Tier 1 rules, Tier 2 packet rules, packet parsing and store, case list, RAG index, AI summary, recommendations, all 16 classes) | 9/9 pass |
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

The bundle in `backend\models\forenxai\` is the tuned multiclass XGBoost. It was trained on the GPU (NVIDIA GeForce RTX 4050 Laptop GPU, CUDA 12.1) with leakage-safe splits: rows with an identical feature vector are kept in the same partition. It was trained on TRUSTLab only (16 classes, 66 features) and runs on the CPU in the app. The code that built it is in `training/`.

| File | SHA-256 (first 16) |
|---|---|
| XGBoost.pkl | 247fb8446ca6144a |
| scaler.pkl | 7b356febe0212f2d |
| label_encoder.pkl | 64ed93e1e30701b1 |
| features.pkl | 64a7c523e12144dc |
| shap_global.json | 704dfcec9581d067 |

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
