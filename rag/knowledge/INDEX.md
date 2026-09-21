# Knowledge corpus

Documents the recommendation stage reads. Retrieval is **vectorless**: the
classifier names one of sixteen classes, `config/knowledge_map.py` maps that
name to specific sections, and those sections are read verbatim. No
embeddings, no vector store, no chunking.

Nothing here is bundled — these are third-party publications. Download them
yourself into the folders below. Every file is optional; the pipeline reports
what is missing rather than inventing content.

---

## Layout

```
knowledge/
  incident_response/    what to DO about a detection
  detection/            what the attack IS, and how it is normally detected
  interpretability/     how to read a SHAP attribution honestly
  features/             what each of the 74 flow features means
  datasets/             the dataset paper and its published figures
  INDEX.md              this file
```

---

## 1. `incident_response/` — the recommendations panel

This is the corpus the "what should I do" panel quotes. Without it the
recommendation stage has nothing to cite and will say so.

| Document | Why | Where |
|---|---|---|
| **NIST SP 800-61r3**, *Incident Response Recommendations and Considerations* | The containment / eradication / recovery structure recommendations follow | csrc.nist.gov/pubs/sp/800/61/r3/final |
| **NIST SP 800-53r5**, *Security and Privacy Controls* | Control identifiers to cite (SI-4 monitoring, SC-5 DoS protection, AC-7 login attempts) | csrc.nist.gov/pubs/sp/800/53/r5/upd1/final |
| **NIST CSF 2.0** | Function-level framing (Detect / Respond / Recover) for the executive summary | nist.gov/cyberframework |
| **Your own organisation's runbook** | Anything site-specific — escalation contacts, change windows, approved blocking | — |

NIST publications are US Government works in the public domain, so storing
and quoting them locally is unproblematic. Your own runbook is usually the
most valuable file here: generic advice is what the model already knows;
your escalation path is not.

## 2. `detection/` — attack context

| Document | Why | Where |
|---|---|---|
| **MITRE ATT&CK Enterprise** (JSON or the technique pages you need) | Technique IDs per class. Gives an investigator a shared vocabulary and a link out | attack.mitre.org · github.com/mitre-attack/attack-stix-data |
| **NIST SP 800-94**, *Guide to Intrusion Detection and Prevention Systems* | Explains what flow-level detection can and cannot see — directly relevant to this model's limits | csrc.nist.gov/pubs/sp/800/94/final |
| **CISA advisories** relevant to your environment | Current, specific, actionable | cisa.gov/news-events/cybersecurity-advisories |

ATT&CK is free to use with attribution: *"© 2026 The MITRE Corporation. This
work is reproduced and distributed with the permission of The MITRE
Corporation."*

## 3. `interpretability/` — the SHAP panel

| Document | Why | Where |
|---|---|---|
| **Lundberg & Lee (2017)**, *A Unified Approach to Interpreting Model Predictions*, NeurIPS | The definition of a Shapley value. Cite for what SHAP is | papers.nips.cc — NeurIPS 2017 |
| **Lundberg et al. (2020)**, *From local explanations to global understanding with explainable AI for trees*, Nature Machine Intelligence 2(1) | TreeSHAP — the exact algorithm this pipeline uses | nature.com/articles/s42256-019-0138-9 |
| **`shap` documentation** | Practical reading of force and waterfall plots | shap.readthedocs.io |
| **`caveats.md`** — write this one yourself | The honest limits. A template is below | — |

Papers are usually copyrighted. Keep them locally for your own reference;
do not redistribute them with the project.

### `interpretability/caveats.md` — write this, it matters

The recommendation stage should quote limits, not just capabilities.
Minimum content:

- SHAP shows **association, not causation**. "Flow Duration drove this
  prediction" does not mean long duration causes the attack.
- Attribution is **relative to a baseline** — the average prediction across
  the background data, not an absolute zero.
- **Correlated features share credit arbitrarily.** Flow features are heavily
  correlated, so a feature with low attribution may still be informative.
- Values are computed on **scaled** inputs; the raw number is shown only for
  human reading.
- A confident explanation of a **wrong** prediction is still wrong. SHAP
  explains the model, not the world.

## 4. `features/` — feature definitions

| Document | Why |
|---|---|
| **CICFlowMeter feature list** (`github.com/ahlashkari/CICFlowMeter`) | Turns `Bwd Bulk Rate Avg` into a sentence an investigator understands |
| **`glossary.md`** — write this yourself | One line per feature, in plain English |

This is what lets the SHAP panel say *"backward bulk transfer rate — how fast
the server sent data in sustained bursts"* rather than echoing a column name.
Only the ~25 features that appear in `results/shap/global_random.json` need
entries; start there.

## 5. `datasets/` — provenance

| Document | Why |
|---|---|
| **Villafranca, Tasic & Cano (2026)**, *Frontiers in Computer Science* 8:1803271 | The TRUSTLab paper. Baseline figures and class definitions |
| **`scope.md`** — write this yourself | The claim boundary, copied from `deploy/manifest.json` |

---

## How retrieval uses these

`config/knowledge_map.py` holds one entry per class:

```python
"PortScan": {
    "attack": "detection/attack_portscan.md",
    "response": "incident_response/nist_800_61r3_detection_analysis.md",
    "mitre": ["T1046"],
    "controls": ["SI-4", "SC-7"],
}
```

A missing file is reported, never guessed at. That is the point of the
vectorless design: retrieval either finds the right section or says it
could not, where a similarity search would confidently return the nearest
wrong chunk.

## Preparing a PDF for retrieval

The stage reads Markdown or plain text, not PDF. Convert once:

```bash
python - <<'EOF'
import pypdf
r = pypdf.PdfReader("knowledge/incident_response/NIST.SP.800-61r3.pdf")
text = "\n\n".join(p.extract_text() or "" for p in r.pages)
open("knowledge/incident_response/nist_800_61r3.md", "w", encoding="utf-8").write(text)
EOF
```

Then split by section so the map can point at a specific one. A whole
800-page publication in the prompt is expensive and dilutes the answer;
the containment section alone is what a recommendation needs.

## Minimum viable corpus

If you only have time for three files:

1. `incident_response/nist_800_61r3_containment.md` — the actions
2. `interpretability/caveats.md` — the honesty (write it yourself, 20 lines)
3. `features/glossary.md` — plain-English feature names (25 lines)

That is enough for all three UI panels to produce grounded output.
