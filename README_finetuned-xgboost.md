# Branch `finetuned-xgboost`: what changed and why

This branch replaces the classifier with the tuned XGBoost model and adds a
hybrid detection layer (Tier 1 flow rules, Tier 2 packet rules and Suricata),
a retrieval-grounded recommendation stage and the matching interface.

Compared with `main`: 25 commits, about 95 files. All paths are relative to the
repository root (`FORENXAI-Desktop/`).

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
