# RAG recommendation pipeline

How the Recommendations panel turns an XGBoost class into cited response
actions, and what was changed to make it fast. XGBoost, feature extraction,
SHAP and the evidence pipeline are untouched.

## Architecture

```
                         XGBoost -> predicted class
                                      |
                            knowledge_map.py (routing)
                                      |
                 .rag_index.json  (prepared once, reused)
          +-------------+-------------+-----------------+
          |             |             |                 |
       profile      playbook     fixed sources     runtime retrieval
     (detection)   (sourced     NIST 800-53 ctrls   postings search over
                    lines)      + SP800-61r3 3.2    814 archive sections
                                + SP800-86 3.1      -> top 0-2 passages
          +-------------+-------------+-----------------+
                                      |
                   build_generation_context()  ~1,600 tokens
                   every source numbered S1..Sn
                                      |
                      Qwen2.5-3B, greedy, JSON grammar
                   {"actions":[{"text":..., "source_id":"S7"}]}
                                      |
                         verify_actions()  (no LLM)
                  one id? supplied? unique? cited text supports it?
                     +----------------+----------------+
                     |                                 |
             verified actions                    dropped actions
        (topped up with verbatim                 + reason each
         playbook quotes if < 3)
                     |
     recommendation object -> UI fields (unchanged) + report fields
```

## Files

| File | Role |
|---|---|
| `rag/knowledge/` | source of truth: profiles, playbooks, notes (unchanged) |
| `rag/config/knowledge_map.py` | class -> documents, controls, MITRE, ambiguous pairs (unchanged) |
| `rag/_sources/manifest.json`, `SHA256SUMS.txt` | source registration and integrity (unchanged) |
| `rag/config/source_index.py` | parses the archive; used only when the index is built |
| `rag/config/rag_index.py` | **new**: builds, versions and searches the prepared index |
| `rag/.rag_index.json` | derived, untracked; rebuilt automatically when stale |
| `backend/app/services/recommendation_service.py` | retrieval, context, generation, verification |
| `backend/test_rag_pipeline.py` | **new** test suite |
| `backend/bench_recommendations.py` | **new** stage-by-stage benchmark |

## Index build

`build_rag_index()` reads the 31 knowledge files and the source index once and
stores, per class: the profile, the playbook split into one source per sourced
line, the controls and the two baseline sections resolved by exact identifier,
the class's query terms, literature passages and citations. It also stores the
814-section search pool with postings (term -> sections containing it) for every
term a class query can contain, and the result of checking `_sources/` against
`SHA256SUMS.txt`.

```
python rag/config/rag_index.py            # build if stale, print a report
python rag/config/rag_index.py --force    # rebuild
```

## Startup

`app/main.py` calls `start_rag_warmup()` in the FastAPI lifespan. It returns at
once; a background thread then

1. computes `knowledge_version()` (hash of knowledge/, knowledge_map.py,
   manifest.json, SHA256SUMS.txt, the extraction stamp and the archive file
   list; a few ms),
2. opens `.rag_index.json` if its recorded version matches, otherwise rebuilds
   it (about 0.7 s) and writes it,
3. loads Qwen, so the first recommendation does not pay for it. Set
   `FORENXAI_PRELOAD_LLM=0` to skip this.

The server accepts requests immediately. A request that needs the index before
the thread is done waits on the same lock, so the index is never built twice.
`GET /health` reports the RAG state, load time, version and integrity status.

## Runtime retrieval

`retrieve_supporting_passages(class, query_context=None, top_k=2)`:

- query terms: the class name, its summary and MITRE ids from knowledge_map.py,
  built deterministically; no model call before retrieval;
- scoring is identical to `source_index.search()`: a term matches a section
  when it occurs in the lower-cased text, weight log(N/df), terms in more than
  40% of sections ignored, fewer than two matched terms is not a match, ties
  broken on document and section id. Only sections in the postings of a query
  term are scored. The test suite checks the same passages come back as before
  for all 16 classes;
- the two baseline sections are excluded (they are always supplied);
- at most two passages; fewer when fewer qualify.

Cache: `(knowledge_version, class, terms, top_k) -> passages`. Entries of any
other version are dropped on the next write. The full recommendation cache
(class, confidence band, alternatives) is unchanged.

## Qwen context

`build_generation_context(class, retrieved)` returns the prompt and the
`S1..Sn -> source` map. It contains only: the class and summary, one note line
on alternatives and ambiguity, the NIST SP 800-53 controls, the two baseline
sections, the 0-2 retrieved passages, each sourced playbook line (section 4.1 is
skipped because it repeats the controls), and the detection profile. Each piece
is clipped to a fixed budget (`rag_index.py`). SHAP features, the glossary, the
caveats and scope notes are no longer sent.

Generation is greedy (temperature 0, top_k 1) and constrained by a JSON-schema
grammar in which `source_id` is an enum of the supplied ids and the list holds 3
to 5 actions.

## Verification

`verify_actions(actions, sources)` keeps an action only if it is an object with
text, has exactly one `source_id`, that id was supplied, it resolves to one
source, and the cited source itself accounts for the wording (`verify()`: a
shared four-word run, or 70% of the significant words). A correct-looking
action citing the wrong line is dropped. Every drop has a reason.

If fewer than three actions survive, the remainder is filled with playbook lines
quoted verbatim under their own source id, in the order containment, evidence
handling, recovery, detection. Nothing unsourced is ever added. Benign keeps its
three fixed policy actions.

## Recommendation object

All fields the WPF interface reads are unchanged in name and type (`actions`,
`actions_cited`, `references`, `action_evidence`, `sources`, `verified`, ...),
so the interface needs no change. New fields for the verification view and the
reports:

| Field | Content |
|---|---|
| `retrieved_sources` | every standard supplied: source_id, doc, label, kind, score |
| `generated_actions` | number of actions Qwen produced |
| `verified_actions` | action_id, text, source_id, label, doc_id of each displayed action |
| `dropped_actions` | text, source_id and reason of each rejected action |
| `verification_summary` | generated / verified / dropped counts and reasons |
| `verification` | parse status, supplied source map, top-up count |
| `knowledge_version` | index version the answer was built from |

`references` lists only documents that displayed actions cite. The in-app
report (`report_service.build_case_report`) embeds this same object per flow.

## Stale index handling

The index is used only when its recorded version equals `knowledge_version()`.
Editing any knowledge file, the map, the manifest or SHA256SUMS, re-extracting a
source or adding or removing an archive file changes the version, and the next
load rebuilds. A schema change in `rag_index.py` (`SCHEMA`) also forces a
rebuild. Delete `rag/.rag_index.json` at any time; it is recreated.

## Benchmark

```
python backend/bench_recommendations.py --classes DoS WebBased PortScan --out after.json
python backend/bench_recommendations.py --compare before.json after.json
python backend/bench_recommendations.py --no-llm      # everything except Qwen
```

It times each stage by wrapping the service's own functions, measures startup in
fresh processes, and measures Qwen prompt processing separately from decoding on
the exact prompt the service built.

## Tests

```
python backend/test_rag_pipeline.py          # 130 checks, no language model
python backend/test_rag_pipeline.py --live   # plus one real generation
```
