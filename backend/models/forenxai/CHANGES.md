# gpu-leakage-safe-model — what is here, what changed, and where it lives

Handover note for Ronnen Kenneth. Written 23 September 2026.

This folder is the deployed model the desktop app loads. Everything below is
either in this folder or at an absolute path given in full, so nothing has to
be hunted for.

---

## 1. What this folder is

`C:\Users\HOME PC\OneDrive\Desktop\Thesis\Final\final-project\FORENXAI-Desktop\backend\models\forenxai\`

| File | What it is | SHA-256 (first 16) |
|---|---|---|
| `XGBoost.pkl` | the 16-class classifier, 25.6 MB, trained on TRUSTLab | `25ca234168549112` |
| `scaler.pkl` | StandardScaler, fitted on training rows only | `7b356febe0212f2d` |
| `features.pkl` | the 66 feature names **in order** | `64a7c523e12144dc` |
| `label_encoder.pkl` | the sixteen class names | `64ed93e1e30701b1` |
| `shap_global.json` | both attribution profiles (`per_class`, `per_class_own`) | `89f65b8890027710` |
| `manifest.json` | all five hashes, the frozen feature order, library versions | `58c50b76390f0216` |
| `model_facts.json` | measured per-class F1, confusion matrix, 120 pair similarities |  |

**The feature order matters.** A model fed the right 66 columns in the wrong
order fails silently rather than loudly, which is why the order is frozen in
both `features.pkl` and `manifest.json`.

**Read the scope note in `manifest.json` before quoting any number:**

> "Validated on TRUSTLab only. Performance on other capture environments is
> not established — see the binary experiment, scripts 05–07."

That sentence is the study's conclusion in one line. The model is accurate on
the network it was built for and does not transfer; the binary experiment
exists to bound that claim, not to be deployed.

**These five files were not modified.** They are byte-identical to the
copies in the pipeline bundle, verified by hash on 23 September. Everything
below changed around the model, not the model itself.

---

## 2. The three locations, and which is authoritative

| Location | Holds | Authoritative for |
|---|---|---|
| `C:\Users\HOME PC\OneDrive\Desktop\Thesis\Final\final-project\FORENXAI-Desktop\` | the running app: backend, frontend, `rag/` | **the retrieval corpus and the code** |
| `C:\Users\HOME PC\Downloads\MULTI_CLASS_FORENXAI\forenxai_pipeline_full\forenxai_binary\new_deploy_gpu\` | the reproducible evidence bundle | **the results, tables and figures** |
| `…\FORENXAI-Desktop\backend\models\forenxai\` (this folder) | the deployed model | **nothing on its own — it is a copy** |

If the app and the bundle ever disagree about a knowledge file or a retrieval
module, **the app wins** and the bundle should be re-synced from it. That is
the direction the drift below was repaired in.

---

## 3. What changed, 22–23 September 2026

### 3.1 The bundle was shipping placeholder guidance — fixed

`new_deploy_gpu\knowledge\` still carried the **PLACEHOLDER** playbooks:
prose written to exercise the citation path, not sourced from any standard.
The app had long since replaced them with playbooks compiled from the source
archive by `rag\config\build_playbooks.py`. **29 of 31 files differed.** The
bundle README claimed the corpus was byte-identical to the project copy; it
was not. All 31 files are now the compiled versions.

Why it mattered: a recommendation grounded in placeholder prose is grounded in
nothing, and it reads with the confidence of a citation.

### 3.2 The bundle could not run its own retrieval — fixed

`new_deploy_gpu\config\` held only `knowledge_map.py`. The two modules that
actually read the archive were absent, so the retrieval step could not be run
or audited from the bundle at all. Now present:

```
new_deploy_gpu\config\knowledge_map.py      class -> documents (the lookup)
new_deploy_gpu\config\source_index.py       reads the archive, builds the index
new_deploy_gpu\config\extract_sources.py    extracts every source to text
new_deploy_gpu\config\build_playbooks.py    compiles the playbooks
```

### 3.3 Nine cited papers were not in the archive — added

The peer-reviewed comparators the thesis argues against were cited in the
write-up but absent from the retrieval archive. Copied in from
`C:\Users\HOME PC\Downloads\MULTI_CLASS_FORENXAI\forenxai_pipeline_full\forenxai_binary\references\`,
manifested with full citations, and indexed:

| Paper | Sections indexed |
|---|---|
| Catillo (transferability) | 34 |
| Mchina (ACAFS) | 23 |
| Gombar (triage) | 21 |
| Villafranca (TRUSTLab, the dataset's own paper) | 20 |
| Sharafaldin (CICIDS) | 11 |
| Coşar (CSE-CIC-IDS2018) | 10 |
| Herzalla (TII-SSRC-23) | 9 |
| Badiger (stacking) | 8 |
| Bilal (federated) | 8 |

Journal headings needed their own extractor: the original one only matched
`1.2 Numbered Headings`, so IEEE's `I. INTRODUCTION` and Nature's bare
`Methodology` yielded one section per paper. `source_index.py` now also matches
roman-numeral and named sections. **Titles are kept in their printed casing** —
re-casing an all-caps heading breaks the body-text anchor and silently empties
the section.

### 3.4 Every source is now extracted to text

`rag\config\extract_sources.py` (new) extracts **every entry in the manifest**
to `rag\_extracted\`, one Markdown file per source, each carrying its citation,
its source filename with size and hash, and an HTML-comment page marker per
page so a quotation can be checked against the original.

```
python config\extract_sources.py           # only what is missing or stale
python config\extract_sources.py --force   # everything again
python config\source_index.py              # rebuild and report the index
```

`source_index.py` reads that folder as the reader of last resort, so a cited
document is **readable or absent — there is no third state.** The previous code
excused four documents as "covered elsewhere", which is the same failure the
archive exists to prevent: a citation the retrieval step cannot support. Those
four (the SP 800-53 release-delta log and the three OWASP risk pages) are now
indexed and quotable.

Two defects the extraction caught:

- The manifest pointed `OWASP.Top10.2025` at the rendered **navigation menu** —
  2 KB of link text. The archive also holds the Markdown edition of the whole
  Top 10. Extraction now takes that: **468,438 characters instead of 1,995.**
- HTML extracts opened with the site menu, so a quotation began *"Skip to
  content A02 Security Misconfiguration A03 …"*. Extraction now starts at the
  article's own `<h1>`.

### 3.5 The recommendation panel only ever cited two sources — fixed

`backend\app\services\recommendation_service.py` never called the literature
archive. Retrieval was controls + two fixed baseline sections + two searched
sections, so a recommendation came back with **2 references** no matter how
large the archive grew.

The service now also calls `literature_for()` and returns a `literature`
field, cited in `sources`. Then a second problem showed up: Villafranca (the
TRUSTLab paper) took **both** literature slots for almost every class, because
it describes this exact taxonomy. `literature_for()` now returns **one passage
per paper**.

| | Before | After |
|---|---|---|
| Citations per recommendation | 2 | **4–7** |
| Comparators ever surfaced | 3 of 9 | **6 of 9** |

**The comparators never enter `standards`, and never reach the verifier's
evidence set.** A paper's experimental setup is not authority for a containment
instruction. They are context beside a prediction, and they are cited.

Badiger, Herzalla and Mchina still never surface: their vocabulary is
CSE-CIC-IDS2018 and TII-specific and does not clear the two-rare-term bar on
TRUSTLab class names. That is correct behaviour, not a gap.

**The frontend needed no change.** `System.Text.Json` ignores the new field and
`RecommendationData.Sources` already renders the citation list, so the extra
references appear in the XAI tab as they are. A dedicated "Published context"
panel would need XAML work in
`frontend\FORENXAI.Desktop\Views\XaiView.xaml`.

### 3.6 Three byte-identical duplicate PDFs removed

Same bytes as a cited copy, and not cited under their own identifier, so
nothing was lost:

| Removed | Identical to |
|---|---|
| `MITS_05.01_02.pdf` | `Arslan.mits.pdf` |
| `Federal_Government_…_Playbooks_508C.pdf` | `CISA.playbooks.pdf` |
| `nistspecialpublication800-86.pdf` | `NIST.SP.800-86.pdf` |

7.1 MB per location, 14.1 MB across both.

### 3.7 The PCAP path was broken - diagnosed, fixed and verified end to end

Running an analysis threw:

```
java.lang.UnsatisfiedLinkError:
com.slytechs.library.NativeLibrary.dlopen(Ljava/lang/String;)J
```

Two separate causes, both found:

**Npcap is not installed.** `jnetpcap.dll` imports `wpcap.dll`, and that file
exists nowhere on this machine - no `C:\Windows\System32\wpcap.dll`, no
`Packet.dll`, no `C:\Windows\System32\Npcap\`, no `C:\Program Files\Npcap\`.
Wireshark is installed but *without* its packet driver, which is what happens
when "Install Npcap" is unticked during Wireshark setup. The DLL loads, fails
to resolve its import, and `dlopen` returns null. It is not an architecture
mismatch: `jnetpcap.dll` and the JVM are both 64-bit, checked from the PE
headers.

Fix: install from https://npcap.com/#download **as Administrator**, ticking
**"Install Npcap in WinPcap API-compatible Mode"** - jNetPcap 1.4 only knows
the WinPcap API. Verify with
`dir C:\Windows\System32\wpcap.dll C:\Windows\System32\Packet.dll`.

**The system JDK is too new.** `JAVA_HOME` is JDK 26, and CICFlowMeter's
`pom.xml` compiles with `<source>1.8</source>`. **JDK 24 removed `-source 8`**,
so Maven would stop with *"Source option 8 is no longer supported"* even once
Npcap is in.

Rather than downgrading the machine's Java, the service now uses a
**project-local JDK**:

```
FORENXAI-Desktop\tools\jdk8\bin\java.exe     <- unpack a JDK 8 or 11 here
FORENXAI-Desktop\tools\README.md             <- how, and why not .venv
```

`get_java_home()` in `backend\app\utils\runtime_paths.py` resolves it -
`FORENXAI_JAVA_HOME`, then `tools/jdk*`, then the system `JAVA_HOME`, then
`java` on `PATH` - and both unpack layouts work, flat and one level deep.
`JAVA_HOME` and `PATH` are set only on the environment handed to the Maven
subprocess, so the machine's Java is untouched.

`_build_environment()` now **refuses to launch Maven on a JDK of 24 or newer**
and names the exact folder to unpack into, instead of letting it fail three
minutes later inside a Maven log.

On `.venv`: a JDK cannot live there. It is a Python virtual environment, pip
owns it, and it is rebuilt from `requirements.txt` - a JDK inside it would be
deleted on the next rebuild. `tools/` is git-ignored except its README and the
pointer file.

### 3.8 Both dependencies installed, and the whole path proven

Installed 23 September 2026 and verified working:

| | |
|---|---|
| **Npcap 1.89** | WinPcap API-compatible mode ON - `wpcap.dll` and `Packet.dll` are in `C:\Windows\System32\` as well as `System32\Npcap\`. Both are required; the compatibility copy is what jNetPcap 1.4 resolves against. |
| **Temurin OpenJDK 1.8.0_504-b01 (x64)** | at `C:\Tools\jdk8u504-b01`, beside CICFlowMeter and Maven. `javac 1.8.0_504`, 192 MB, 444 files. |

**The JDK is not inside the project tree**, and that is deliberate:
`FORENXAI-Desktop` sits under OneDrive, so unpacking 444 files there would sync
the whole JDK to cloud storage for no benefit. `tools\jdk.path` records the
location instead - a 20-line text file that IS committed, while the bytes stay
on the local disk. `get_java_home()` reads it as resolution step 3.

Two Kerberos binaries (`bin\klist.exe`, `jre\bin\klist.exe`) could not be copied
out of Downloads because of a permission denial. They are irrelevant to
CICFlowMeter; `java`, `javac`, `jar`, `rt.jar` and `tools.jar` are all present
and the toolchain compiles and runs.

**Verified, in order:**

1. `jnetpcap.dll` loads. A JNI test against `jnetpcap.jar` under the JDK 8
   toolchain returned `libpcap version: Npcap version 1.89, based on libpcap
   version 1.10.7` and enumerated 8 interfaces. The original
   `UnsatisfiedLinkError` is gone.
2. **CICFlowMeter ran end to end.** A 48-packet synthetic capture
   (`backend\sample_data\synthetic_test.pcap`, written with scapy because the
   repository had no capture to test with) produced
   `synthetic_test.pcap_Flow.csv`: **4 flows, 84 columns**, correct header
   starting `Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp,
   Flow Duration`.

**Expect Maven to exit 1 anyway.** CICFlowMeter throws inside jNetPcap at
shutdown after the CSV is already written. `_run_cicflowmeter()` has always
handled this - it checks for a valid CSV before trusting the exit code, and
logs *"Maven returned a non-zero exit code, but CICFlowMeter produced a valid
CSV"*. That warning in the log is normal and is not a failure.

`sample_data\synthetic_test.pcap` is kept as a fixture: it is the only capture
in the repository, and it makes the PCAP path testable without hunting for real
traffic.

### 3.9 "CICFlowMeter produced no flow rows" now says why

The first real capture run through the UI failed with:

```
{"detail":"ValueError: CICFlowMeter produced no flow rows."}
```

Nothing was broken. `tcp_reset.pcap` is **100 bytes and holds exactly one
packet** - a single TCP RST, 192.168.31.181:3262 -> 192.168.31.214:80.
CICFlowMeter discards any flow of fewer than two packets, so it wrote the
84-column header and no rows. The file was non-empty, so every size check
passed, and the failure only surfaced two steps later in `model_service.py`
against an empty dataframe, with a message that gave the analyst nothing to act
on.

`generate_flow_csv()` now ends with `_require_flow_rows()`, which reads the CSV
for a data row and, when there is none, re-reads the capture and reports what
was actually in it:

```
CICFlowMeter produced no flows from this capture.

The capture holds 1 packet, 1 of them TCP or UDP, forming 1 conversation,
of which 0 have more than one packet. A capture this small cannot produce a
flow: the first packet of the file is
Ether / IP / TCP 192.168.31.181:3262 > 192.168.31.214:http R / Padding.

CICFlowMeter discards any flow of fewer than two packets, so a capture needs
at least one conversation with a packet in reply -- a request and its
response, or two packets of the same TCP connection. A single packet, however
valid, produces no row.

Capture analysed: ...\evidence\tcp_reset.pcap
CSV written:      ...\flows\tcp_reset.pcap_Flow.csv (84 columns, no data rows)
```

The capture is re-read only on failure, so the diagnosis costs nothing on a
normal run. Regression checked: the 48-packet fixture still passes through
`generate_flow_csv()` and returns 4 flows.

**What to do when this appears:** use a capture with real conversations in it.
A packet count is not enough on its own - the packets have to belong to
conversations that have at least a reply.

### 3.10 The 84-to-66 feature contract, made explicit

CICFlowMeter emits 84 columns; the model consumes 66. Checked against the
live CICFlowMeter output: **all 66 are present and the names match exactly,
nothing missing, no translation needed.** The 18 unused columns are three
different kinds of thing, now named in `model_service.py` rather than left to
be worked out by subtraction:

| Group | Count | Columns |
|---|---|---|
| Identity | 6 | `Flow ID, Src IP, Src Port, Dst IP, Timestamp, Label` - shown to the analyst, never features. `Dst Port` and `Protocol` ARE features and are in the 66: they describe the service, not the host. |
| Excluded by contract | 8 | `Active*`, `Idle*` - dropped in the 74 -> 66 rebuild |
| Untrained | 4 | `Fwd Packets/s, Bwd Packets/s, Fwd Act Data Pkts, Fwd Seg Size Min` - real features outside the three-dataset intersection |

The selection itself was already correct: `dataframe[expected_features]` takes
the 66 by name in frozen order and drops the rest. What was missing was a
guard. `assert_feature_contract()` now refuses a `features.pkl` that lists any
`Active*`/`Idle*` column, because that failure is silent - those columns exist
in CICFlowMeter output full of plausible numbers, while the deployed model has
only ever seen zeros in them. Nothing would raise; the predictions would just
be wrong. Every run now logs what it dropped and why.

### 3.11 Two prediction warnings removed, and the forest walked once

```
UserWarning: Falling back to prediction using DMatrix due to mismatched
devices. XGBoost is running on: cuda:0, while the input data is on: cpu.
UserWarning: X has feature names, but StandardScaler was fitted without
feature names
```

The first is misleading. Its suggested fix - move the booster to the CPU - was
measured at **4.26 s against 0.74 s on 200,000 rows**, six times slower for
identical output. The right fix is to build the `DMatrix` explicitly, which is
what the fallback was doing anyway, and the warning then has nothing to warn
about.

Doing that exposed a larger waste. The code called `model.predict()` for the
class and `model.predict_proba()` for the confidence. For a `multi:softprob`
booster those are the same computation - `predict()` is `predict_proba()`
followed by `argmax` - so all 400 trees were being walked twice:

| rows | before | after | |
|---|---|---|---|
| 500 | 78.6 ms | 32.0 ms | 2.5x |
| 5,000 | 75.4 ms | 38.7 ms | 1.9x |
| 50,000 | 584.7 ms | 308.1 ms | 1.9x |

Now one `booster.predict(DMatrix(...))` gives the probability matrix, and the
class is its `argmax`. **Verified byte-identical to the old path: classes
equal, maximum probability difference 0.000e+00.**

The scaler warning had the same shape - a cosmetic mismatch, not a contract
one. The scaler was fitted on an unnamed array, so it is now handed
`feature_frame.to_numpy()`. Column *order* is what it relies on, and that is
fixed and asserted a few lines above; the names were never carrying the
contract.

Both warnings are gone from the prediction path. `test_recommendations.py`
still passes 11/11.

### 3.12 The recommendation cache never hit - 92% of generations removed

The panel was generating once per FLOW, not once per class. The cache key
was:

```python
(predicted_class, tuple(top-5 SHAP features), round(confidence, 1), alternatives)
```

The SHAP five-tuple and the exact confidence differ for almost every flow, so
almost every flow produced a distinct key. Measured on 200 flows across five
classes: **200 distinct keys, 200 generations.** At 136 s each that is over
seven hours for one capture.

The five-tuple was not earning its place. Generating for the same class with
two entirely disjoint SHAP feature sets returns **byte-identical actions** -
measured, not assumed. The actions are grounded in the retrieved documents and
filtered by the verifier, and neither depends on which features ranked highest
for one flow. SHAP still reaches the prompt; it is simply not what makes one
answer differ from another.

The key is now what genuinely changes the retrieval - class, confidence BAND,
and the alternative classes that band brings with it:

| | distinct keys for 200 flows | generations |
|---|---|---|
| before | 200 | 200  (~7.5 h) |
| after | **15** | **15**  (~34 min) |

Confidence is quantised to three bands (below 0.60, 0.60-0.85, above 0.85)
*before* anything reads it, so the prompt and the key cannot disagree - a
cached answer written for one confidence is never served to a flow the prompt
would have told a different one. The flow's own exact confidence is still
displayed beside the recommendation, from the finding, not from here.

Measured after the change: first flow of a class 73.0 s, second flow of the
same class and band **0.000 s**.

### 3.13 Where the remaining time goes, and the one lever left

Generation is the whole cost: retrieval is ~100 ms, a generation is 136 s.
Measured on this machine:

| | |
|---|---|
| prompt | 3,192 tokens of a 4,096 context |
| prefill rate | ~76 tokens/second |
| prefill cost | **~42 s before the first output token** |
| shared prefix between two classes' prompts | 295 chars, **2%** |

`llama-cpp-python` here is a **CPU-only wheel** - it ships `ggml-cpu.dll`, no
`ggml-cuda.dll`, and `llama_supports_gpu_offload()` returns False. `n_gpu_layers`
is therefore ignored silently. Installing a CUDA wheel is the single largest
remaining speedup and it is a deployment decision, not a code one:

```
pip install --force-reinstall --no-cache-dir ^
  --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu124 ^
  llama-cpp-python
```

Then set `N_GPU_LAYERS = -1` in `llm_provider.py`. The file checks
`llama_supports_gpu_offload()` at load and prints which mode it is in, so a
wheel that silently lacks CUDA cannot be mistaken for a working one.

Thread count was measured rather than assumed: 4 and 8 threads were within a
percent of each other (76.4 and 77.2 tok/s prefill) and **12 was distinctly
worse (54.4 tok/s)** through oversubscription on a 12-logical-core machine.
The default now follows physical cores and caps at 8.

The second lever, if the CUDA wheel is not an option, is the prompt itself.
Prefill is linear in tokens, so halving 3,192 tokens saves ~21 s per
generation. Two approaches, in order of return:

1. **Move every constant instruction to the front.** Only 2% of two prompts
   is shared today, so llama.cpp's KV prefix cache is almost useless. Ordering
   the prompt constant-first, variable-last would let every call after the
   first skip prefill on the shared portion.
2. **Trim the document budgets.** Six local passages (6,952 chars) plus six
   standards (5,199 chars) are 87% of the prompt. Both are already truncated
   by per-document budgets; those budgets were never tuned against output
   quality.

Neither is done here: both change what the model is shown, so both need the
verifier re-measured across all sixteen classes rather than assumed safe.

### 3.14 Recommendations are generated per class, not per flow

`analysis.py` looped over every finding and called `get_recommendation()` for
each. Even with the cache key fixed (3.12), the first flow of each class paid
the full generation cost *inside* the loop, so the analysis appeared to hang
with nothing able to say how long was left.

Two new functions in `recommendation_service.py`:

- `plan_recommendations(findings)` groups flows by the answer they share
  (class, confidence band, alternative classes), largest group first.
- `warm_recommendations(findings)` generates each distinct answer once,
  before the loop, reporting progress.

`analysis.py` calls `warm_recommendations()` before the flow loop; the loop
is then pure cache hits.

Measured on a realistic 200-flow capture (140 Benign, 28 DoS, 18 PortScan,
9 DDoS, 5 Slowloris): **14 groups, of which 11 need the model.** Benign is
free -- it already returns fixed policy text before `_generate()` is reached
(`if not has_playbook: return`), and it accounts for 140 of the 200 flows.

The log now states the work up front:

```
[FORENXAI] Recommendation 1/11: DoS (13 flows)
[FORENXAI] 11 distinct recommendation(s) for 200 flow(s)
```

### 3.15 The CUDA wheel does not work on this machine

Attempted, failed, reverted. Recorded so it is not attempted again blindly.

`llama-cpp-python` was installed from abetlen's cu124 index. The newest CUDA
build published there is **0.3.4** (they stopped shipping prebuilt CUDA wheels
in early 2025), so it is also a downgrade. It would not load:

```
Failed to load shared library '...\llama_cpp\lib\llama.dll':
Could not find module (or one of its dependencies).
```

The wheel needs the CUDA 12.4 runtime DLLs. This machine has driver 596.49 and
an RTX 4050 but **no CUDA toolkit**, so the dependency is absent.

Rolling back was not clean either:

- PyPI has **no binary wheel for 0.3.35**, so the version previously installed
  here had been built from source on this machine. `pip install
  llama-cpp-python==0.3.35` tries to rebuild and fails without a compiler.
- numpy was briefly pinned to 1.26.4, the version in the model's training
  manifest. That is the *training* version, not the runtime one:
  `shap 0.51.0 requires numpy>=2`.

**Current state: `llama-cpp-python 0.3.19` (prebuilt CPU wheel from abetlen's
cpu index), `numpy 2.4.6`.** Verified: numpy, pandas, sklearn, xgboost,
joblib, shap, scapy and llama_cpp all import; `test_recommendations.py` passes
15/15 with generation.

To get CUDA, build from source -- the same way 0.3.35 originally was:

```
CUDA Toolkit 12.4 + Visual Studio Build Tools (C++ workload)
set CMAKE_ARGS=-DGGML_CUDA=on
pip install --force-reinstall --no-cache-dir llama-cpp-python
```

Then check `llama_cpp.llama_supports_gpu_offload()` is True and set
`N_GPU_LAYERS = -1` in `llm_provider.py`. Qwen 3B Q4 is ~1.8 GB against 6 GB
of VRAM, so every layer fits.

Note: `test_model_service.py`, `test_classifier.py` and `test_shap_service.py`
fail on stale fixtures - the first two point at a hardcoded
`C:\Tools\CICFlowMeter\...\data\out\testtest.pcap_Flow.csv` that does not
exist, and the third imports `explain_flow_dataframe`, which no longer exists
in `shap_service.py`. Both predate these changes and neither touches the
prediction path.

---

## 4. How to check it still works

```
cd C:\Users\HOME PC\OneDrive\Desktop\Thesis\Final\final-project\FORENXAI-Desktop\backend

.venv\Scripts\python test_recommendations.py --fast          # retrieval, ~20 s
.venv\Scripts\python test_recommendations.py                 # + the model, ~2 min
.venv\Scripts\python test_recommendations_all_classes.py --fast
.venv\Scripts\python test_recommendations_all_classes.py --repeat 2
```

Results on 23 September:

- `test_recommendations.py` — **15 of 15 passed, three consecutive runs**, with
  identical counts each time. That repetition is the point: the module claims
  determinism (temperature 0, top_k 1) and this is what demonstrates it.
- `test_recommendations_all_classes.py` — **all 16 classes passed with the
  model in the loop**: every class returned verified actions, 0 missing
  documents, 0 missing controls, 4–7 citations each. Six classes had one or
  two actions rejected by the verifier as untraceable, which is the check
  doing its job rather than a fault.
- `dotnet build` in `frontend\FORENXAI.Desktop\` — 0 warnings, 0 errors.
- The backend boots and registers all 8 routes.

`test_recommendations_all_classes.py` is new. The existing test generates for
one class, which is the right trade for a test that runs in a minute; this one
asks whether the panel holds for all sixteen. A class whose playbook is thin,
whose controls are unmapped, or against whose retrieved text the verifier
rejects everything, is invisible until every class is tried.

**Benign is the documented exception.** It returns three fixed lines about
what a benign classification does and does not mean — written by the app, not
generated and not quoted from a standard — so `standards_grounded` is `False`
and the reference list is empty. Measured: 3 actions, 3 cited, 0 references,
`verified` true. An empty reference list there is the honest answer, not a
missing one, and the test tolerates it explicitly rather than by accident.

**One thing the tests cannot cover:** `/analysis/start` requires a `.pcap` in
`cases\<case_id>\evidence\` and runs CICFlowMeter. `backend\sample_data\` only
holds `heldout_sample.csv`, so the full HTTP round-trip was never exercised.
Drop a capture in and the tab can be tested end to end from the UI.

---

## 5. Integrity

The bundle carries a hash for every file it holds:

```
cd C:\Users\HOME PC\Downloads\MULTI_CLASS_FORENXAI\forenxai_pipeline_full\forenxai_binary\new_deploy_gpu
sha256sum -c SHA256SUMS.txt          # every entry should report OK
sha256sum -c SHA256SUMS.txt.sha256   # the list's own hash
```

Because a file cannot hold its own hash, `SHA256SUMS.txt.sha256` holds the
list's hash from outside. **Quote that one line in the paper — it pins every
other file at once.** Read it from the file rather than from any document,
including this one: it is regenerated whenever the bundle changes, and it
changed several times on 22–23 September.

---

## 6. Known gaps — read before the defence

**Three cited sources have no file.** They are in
`rag\_sources\manifest.json` but the PDFs were never archived, so a citation
to them resolves to nothing:

- `Lundberg.shap`
- `Lundberg.treeshap`
- `SommerPaxson.closedworld`

The first two are the SHAP and TreeSHAP originals — they sit behind the whole
explainability chapter, and the deck cites Lundberg. Obtain the three PDFs,
drop them in `rag\_sources\`, and run the two extraction commands from §3.4.
Nothing else needs changing. `source_index.unreadable()` names them on every
build rather than letting the failure go unnoticed.

**Thirteen standards are indexed but never surface.** The seven NIST RMF
FAQs, CSWP.29, FIPS.200, IR.8312, the Privacy Framework, RFC3128 and RFC9424
are in the search pool and never win a slot, because `SEARCHED_SECTIONS = 2`
in `recommendation_service.py` lets at most two of 814 sections through per
class. Raising it widens the panel and the model's prompt; it was left at 2
deliberately, and it is a tuning decision rather than a defect.

**Four documents are reachable only by name.** The three OWASP risk pages and
the SP 800-53 change log are indexed and quotable through
`source_index.passages_of()`, but nothing maps them to a class. Mapping
"A01 Broken Access Control → WebBased" is a domain judgement — and
`knowledge_map.py`'s own header warns that its MITRE mappings "are wrong until
a human has checked them". Decide the risk-to-class pairs and they can be
wired deterministically, the same way the NIST controls already are.

**The MITRE mappings still need review.** That warning in
`rag\config\knowledge_map.py` has not been discharged. It is the oldest open
item in the retrieval layer.
