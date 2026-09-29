# new_deploy_gpu

Bundle from the leakage-safe GPU retrain (started 2026-09-20 23:42, finished 2026-09-21).
The earlier GPU run is kept unchanged in deploy_gpu/. The CPU bundle is deploy/.

Differences from deploy_gpu/: splits keep exact duplicate feature vectors on one side
(LEAKAGE_SAFE_SPLITS = True in settings_snapshot.py). Every number here is from the new run.

Contents: XGBoost.pkl, scaler.pkl, features.pkl, label_encoder.pkl, manifest.json,
shap_global.json, shap/, mc_random_eval/, external_eval/, external_validation_gpu.csv,
mc_summary_random_gpu.csv, session_artifact_analysis_gpu.json, phase2_random/,
reverse_transfer_mc/ (including per_trustlab_class.csv, the pooled-class scores), tables/, binary_internal/, thesis_tables_revised.md, external_shift_diagnostic.json and clip_diagnostic.csv (the diagnostics behind the external-validation discussion), RUN_INDEX.md.
The retrieval (RAG) assets are inside this folder: knowledge/ (31 files), _sources/ (97 files), config/knowledge_map.py, config/source_index.py, config/build_playbooks.py, and the language model qwen2.5-3b-q4.gguf. From inside config/, knowledge_map.py finds knowledge/ at ../knowledge.

Rebuilt 2026-09-21 at 66 features. TRUSTLab exports eight Active/Idle columns without
populating them, so the shared feature contract went from 74 to 66 and all twenty models
were retrained. The 74-feature bundle is archived in new_deploy_gpu_74feat/.

Earlier the same day: two evaluation defects were corrected and stages 06, 07 and 16 rerun.
No model was retrained, so every hashed file is byte-identical and SHA256SUMS.txt still verifies.
The models were then put through the revised tests again and every result file came back
byte-identical, so the copies here are current and reproducible.
See RUN_INDEX.md, "Revision run" and "Confirmation run", for what changed and what it did to the results. In short:
prevalence adjustment in the binary external validation now covers precision, F1 and F2 as well
as accuracy, and the reverse-transfer macro average pools external classes by the TRUSTLab class
they map to, which changes which multiclass model ranks first.

Revision 2026-09-22: stage 13 now writes TWO per-class attribution profiles.
`per_class` averages |SHAP| for a class over every sampled row -- dominated by
evidence for ruling that class out, since 15 of 16 classes in the sample are not
it -- and remains the input to the Table 30 pair matrix, which is unchanged.
`per_class_own` averages only over rows whose true class is that class, which is
"what pushed these flows here" and is what Table 28 and the interface report.
The leading feature's mean signed value is negative for all 16 classes under the
first and positive for all 16 under the second. No model was retrained; only
shap_global.json changed, and SHA256SUMS.txt was recomputed.
scripts/check_shap_aggregation.py reproduces the comparison.

tables/ and figures/ resynced 2026-09-22 from results/. Two files changed:
07_feature_inventory.csv, because in_top12_of_any_class now reads per_class_own
(46 features used by at least one class, now 48; 14 changed status), and
01_main_comparison.csv, whose train_seconds column was a stale snapshot taken
before the standalone XGBoost and TII-SSRC-23 LSTM retimings -- Table 14 in
thesis_tables_revised.md already quoted the clean figures, so only the CSV was
behind. Every other table and all ten figures are byte-identical.

Integrity: SHA256SUMS.txt covers EVERY file in this bundle -- 305 of them -- not just the model
and retrieval assets. That includes the result JSONs and CSVs (binary_internal/, external_eval/,
mc_random_eval/, phase2_random/, reverse_transfer_mc/, shap/), the nine tables in tables/, the ten
figures in figures/, settings_snapshot.py, thesis_tables_revised.md, RUN_INDEX.md and this README.
The only two files not listed are SHA256SUMS.txt itself and its own hash file.
Coverage was extended on 2026-09-22; before that 90 files, including every table and every figure,
were unhashed.
Verify with:  cd new_deploy_gpu && sha256sum -c SHA256SUMS.txt   (305 entries, all should report OK).
manifest.json inside the bundle carries the first 16 hex characters of the five model files.
_sources/ holds the cited source documents and manifest.json, copied from the application
repository (FORENXAI-Desktop/rag/_sources).

Revision 2026-09-23: the retrieval layer was reconciled with the application.
Three things were wrong here and are corrected.
  1. knowledge/ still carried the PLACEHOLDER playbooks -- prose written to
     exercise the citation path, not sourced from any standard. The application
     had long since replaced them with playbooks compiled from _sources/ by
     rag/config/build_playbooks.py. 29 of the 31 files differed; all are now the
     compiled versions.
  2. config/ held only knowledge_map.py, so the retrieval step could not be run
     from this bundle at all. source_index.py and build_playbooks.py are now here,
     and `python config/source_index.py` rebuilds and reports the index in place.
  3. _sources/manifest.json listed 20 documents against the application's 33, and
     the nine peer-reviewed comparators the thesis is written against were not in
     the archive at all. The manifest now carries 42 entries and the nine papers
     are indexed: 9 to 34 sections each, retrievable through source_index.literature_for().

Revision 2026-09-23, second pass: every cited source is now extracted to text.
Retrieval used to depend on whether a document's headings matched a regular
expression, and four cited documents were readable by no extractor at all --
excused in the code as "covered elsewhere", which is the same failure this
archive exists to prevent: a citation the retrieval step cannot support.

config/extract_sources.py now extracts EVERY entry in _sources/manifest.json
into _extracted/, one Markdown file per source, each carrying its citation,
its source file name with size and hash, and an HTML-comment page marker per
page so a quotation can be checked against the original. _extracted/INDEX.md
lists all of them with part and character counts and the full citation list.

  python config/extract_sources.py           # only what is missing or stale
  python config/extract_sources.py --force   # everything again
  python config/source_index.py              # rebuild and report the index

source_index.py reads _extracted/ as the reader of last resort, so a cited
document is readable or it is absent -- there is no third state, and the
"covered elsewhere" list is gone. NIST.SP.800-53r5.changes and the three OWASP
risk pages, none of which could be quoted before, are now indexed. The free-text
pool that supports a recommendation is unchanged at 814 sections, verified by
re-running retrieval for all sixteen classes: 16 of 16 return identical
passages. Extracted pages and the nine comparators are reachable by name
through source_index.passages_of() and literature_for() instead.

Three manifest entries remain unquotable because the file was never archived:
Lundberg.shap, Lundberg.treeshap and SommerPaxson.closedworld -- the SHAP and
TreeSHAP originals and Sommer & Paxson's closed-world critique. Obtain those
three PDFs, drop them in _sources/ and rerun the two commands above; nothing
else needs changing. `source_index.unreadable()` names them on every build
rather than letting a citation resolve to nothing.
The list itself is hashed from outside: SHA256SUMS.txt.sha256 holds its SHA-256 (a file cannot hold its own hash). Check with: sha256sum -c SHA256SUMS.txt.sha256. Quote that hash in the paper.

Revision 2026-09-25: XGBoost hyperparameters tuned (scripts/18_tune_xgboost.py).
Optuna, 30 trials, selected on validation macro F1 from the 15% leakage-safe validation
split; the test split was read once, after selection. Features, scaler, label encoder,
splits and the four deep models are unchanged. Test macro F1 0.9267 -> 0.9305,
accuracy 0.9313 -> 0.9351 (McNemar p = 1.4e-53, bootstrap 95% CI of the macro-F1 gain
+0.0033 to +0.0044). XGBoost.pkl now holds exactly the 132 early-stopped rounds, so
predict() and SHAP TreeExplainer use the same trees.
Regenerated: XGBoost.pkl, manifest.json, shap_global.json, shap/, mc_random_eval/XGBoost_*,
mc_summary_random_gpu.csv, mc_per_class_random_gpu.csv, decision_thresholds.json,
reverse_transfer_mc/, tables/03, 07, 08, 09, figures 1, 2, 4, 5, 10.
ood_stats.json is byte-identical (it depends on the scaler only).
New: thesis_tables_tuned.md (new Table 17a plus the replacement Tables 15, 17, 19, 24,
reverse transfer, 28, 30). thesis_tables_revised.md is kept as the pre-tuning record.
finetune/ holds the tuning record: VALIDATION.md (validation split, search, per-class
validation F1, test comparison, and the effect on SHAP), xgb_tuning_random.json,
xgb_trials_random.csv, xgb_test_comparison_random.json and a copy of 18_tune_xgboost.py.
thesis_table_24a.md is the single before/after table.
Not rerun: phase2_random/ (script 12 builds its own XGBoost from src/models.py, still
the baseline configuration). Previous versions of every changed file: ../new_deploy_gpu_pre_tune/.

Revision 2026-09-25, second pass: thesis_tables_final.md (complete binary in-distribution
table, up-to-date Table 24, per-class before/after, configuration, decision layer, TreeSHAP
configuration and results, bundle inventory) and figures fig11-fig14 (confusion matrices of
the initial and tuned 66-feature XGBoost, their difference, and the system architecture
including the rule layer). Generated by finetune/19_tuning_report.py from
../new_deploy_gpu_pre_tune/ (initial) and this folder (tuned).
Each table in thesis_tables_final.md is also exported as its own CSV in tables/ (T14_, T17a_, T17b_, T24_, T24a_, T27a_, T28_, T28b_, T30_, bundle_inventory_tuning.csv).
thesis_paragraphs_final.md holds one paragraph per table and figure; finetune/20_verify_paragraphs.py checks every number in it against its source (run from the pipeline root).
