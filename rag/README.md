# Retrieval (RAG) assets

Read at runtime by the backend's recommendation panel
(`backend/app/services/recommendation_service.py`), and by the pipeline's
report scripts (14 and 15).

| Path | Contents |
|---|---|
| `knowledge/` | 31 files: incident-response playbooks, attack profiles, the SHAP caveats note, the 66-feature glossary, the dataset scope note and INDEX.md |
| `config/knowledge_map.py` | Class-to-document lookup for the 16 classes, the ambiguous-pair rules and the low-confidence class list. It finds `knowledge/` at `../knowledge` |
| `_sources/manifest.json` | Registers every cited source document |
| `_sources/SHA256SUMS.txt` | SHA-256 of the 88 files in the source archive |

## How the recommendation panel uses them

Retrieval is a dictionary lookup, not a similarity search. The classifier has
already named exactly one of sixteen classes, so `knowledge_map.context_for()`
returns that class's attack profile and response playbook directly, plus the
three documents loaded for every class. An unknown class raises rather than
falling back to a similar one: a recommendation attached to the wrong playbook
is worse than no recommendation.

Qwen then writes the response actions **from the retrieved passages only**,
decoding greedily (temperature 0, `top_k` 1), and every action it produces is
checked back against the retrieved vocabulary before it is returned. Actions
that fail that check are dropped and reported in `rejected_ungrounded`. If the
model is unavailable, or too little of its output survives the check, the panel
falls back to quoting action sentences straight out of the playbook. Both paths
are traceable; neither invents.

The same case therefore produces the same recommendation on every run, which is
a requirement for forensic work rather than a preference.

Each response carries `citations`, `mitre`, `controls`, `missing_documents`,
`truncated_documents`, `low_confidence_f1` and `ambiguous_with` alongside the
actions, so a report can state where each recommendation came from.

## Checks

The source archive itself (26 PDFs, HTML pages and text caches, about 98.7 MiB)
is not in Git. It holds third-party publications. Copy the archive to
`rag/_sources/`, then check it:

```
cd rag/_sources
sha256sum -c SHA256SUMS.txt          # expect: 88 OK
```

Check that the class map finds its corpus:

```
python rag/config/knowledge_map.py   # expect: 33/33 knowledge files present
```

Check that every class can produce a grounded recommendation:

```
cd backend
.venv/Scripts/python -m app.services.recommendation_service
                                     # expect: 16/16 classes have every document present
```

## A caveat worth keeping in view

The shipped playbooks under `knowledge/incident_response/` carry a
**PLACEHOLDER** banner. They were written to exercise the retrieval and
citation path, not sourced from a standard. Replace them with the relevant
sections of NIST SP 800-61r3 and your own runbook before this is used on real
traffic, keeping the heading structure intact — retrieval and the extraction
fallback both depend on it. The MITRE technique identifiers in
`config/knowledge_map.py` are a starting point and need the same review.
