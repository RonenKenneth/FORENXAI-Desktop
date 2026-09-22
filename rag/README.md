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

## Where the playbooks come from

`knowledge/incident_response/*.md` are **generated**, not written. They are
compiled from the publications in `_sources/` by
`rag/config/build_playbooks.py`, and every line carries the identifier and
page it came from:

```
- Begin recovery procedures during or after incident response processes.
  (NIST SP 800-61r3, RC.RP-01 R1, p. 42)
```

Regenerate rather than edit them:

```
python rag/config/build_playbooks.py --check   # what would change
python rag/config/build_playbooks.py           # write
```

A hand edit cannot be traced back to a source, which is the failure these
files exist to avoid. The retrieval layer reads the trailing marker on each
line, so a quoted line is credited to NIST rather than to the file that
collected it.

## What this still does not give you

Section 4.1 of each playbook is specific to the incident type -- it is that
class's NIST SP 800-53 controls. Sections 4.2 to 4.5 are NIST's incident
response lifecycle and read the same in every playbook, because that is what
the publication says: the shape of a response does not change between a
brute-force and a denial-of-service incident, only the controls and the
evidence do.

The consequence is worth stating plainly. The guidance is now real and
checkable, but it is less specific than the placeholder prose it replaced,
because that prose was invented to sound specific. **Your organisation's own
runbook still belongs here.** Add it as a further source in
`build_playbooks.py` rather than by editing the generated files.

The MITRE technique identifiers in `config/knowledge_map.py` remain a
starting point and still need a domain review.
