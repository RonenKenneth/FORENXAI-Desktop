# Run index (leakage-safe retrain, 2026-09-20/21)

Stage logs are in logs/. Each run also wrote a timestamped logs/<script>_<date>_<time>.log with the command, package versions, seed and code state.

| Source | Status | Stage | Time / note |
|---|---|---|---|
| runall_status.txt | START | 08_build | 23:42:17 |
| runall_status.txt | OK | 08_build | 23:42:36 |
| runall_status.txt | START | 09_XGBoost | 23:42:36 |
| runall_status.txt | OK | 09_XGBoost | 23:44:34 |
| runall_status.txt | START | 09_MLP | 23:44:34 |
| runall_status.txt | OK | 09_MLP | 23:50:48 |
| runall_status.txt | START | 09_CNN1D | 23:50:48 |
| runall_status.txt | OK | 09_CNN1D | 00:04:23 |
| runall_status.txt | START | 09_CNN_BiLSTM | 00:04:23 |
| runall_status.txt | OK | 09_CNN_BiLSTM | 00:35:35 |
| runall_status.txt | START | 09_LSTM | 00:35:35 |
| runall_status.txt | OK | 09_LSTM | 01:04:16 |
| runall_status.txt | START | 10_eval | 01:04:16 |
| runall_status.txt | OK | 10_eval | 01:04:32 |
| runall_status.txt | START | 05_combined_XGBoost | 01:04:32 |
| runall_status.txt | OK | 05_combined_XGBoost | 01:04:40 |
| runall_status.txt | START | 05_combined_MLP | 01:04:41 |
| runall_status.txt | OK | 05_combined_MLP | 01:09:15 |
| runall_status.txt | START | 05_combined_CNN1D | 01:09:15 |
| runall_status.txt | OK | 05_combined_CNN1D | 01:15:28 |
| runall_status.txt | START | 05_combined_CNN_BiLSTM | 01:15:28 |
| runall_status.txt | OK | 05_combined_CNN_BiLSTM | 01:30:26 |
| runall_status.txt | START | 05_combined_LSTM | 01:30:26 |
| runall_status.txt | OK | 05_combined_LSTM | 01:51:22 |
| runall_status.txt | START | 05_cicids_only_XGBoost | 01:51:22 |
| runall_status.txt | OK | 05_cicids_only_XGBoost | 01:51:31 |
| runall_status.txt | START | 05_cicids_only_MLP | 01:51:31 |
| runall_status.txt | OK | 05_cicids_only_MLP | 01:55:59 |
| runall_status.txt | START | 05_cicids_only_CNN1D | 01:55:59 |
| runall_status.txt | OK | 05_cicids_only_CNN1D | 01:58:56 |
| runall_status.txt | START | 05_cicids_only_CNN_BiLSTM | 01:58:56 |
| runall_status.txt | OK | 05_cicids_only_CNN_BiLSTM | 02:13:53 |
| runall_status.txt | START | 05_cicids_only_LSTM | 02:13:53 |
| runall_status.txt | OK | 05_cicids_only_LSTM | 02:21:47 |
| runall_status.txt | START | 05_tii_only_XGBoost | 02:21:47 |
| runall_status.txt | OK | 05_tii_only_XGBoost | 02:21:52 |
| runall_status.txt | START | 05_tii_only_MLP | 02:21:52 |
| runall_status.txt | OK | 05_tii_only_MLP | 02:23:08 |
| runall_status.txt | START | 05_tii_only_CNN1D | 02:23:08 |
| runall_status.txt | OK | 05_tii_only_CNN1D | 02:25:03 |
| runall_status.txt | START | 05_tii_only_CNN_BiLSTM | 02:25:03 |
| runall_status.txt | OK | 05_tii_only_CNN_BiLSTM | 02:27:58 |
| runall_status.txt | START | 05_tii_only_LSTM | 02:27:58 |
| runall_status.txt | FAIL | 05_tii_only_LSTM | 02:28:02 |
| runall2_status.txt | START | 05_tii_only_LSTM | 06:39:07 |
| runall2_status.txt | OK | 05_tii_only_LSTM | 06:49:38 |
| runall2_status.txt | START | 06_external |  |
| runall2_status.txt | OK | 06_external | 06:50:33 |
| runall2_status.txt | START | 07_aggregate | 06:50:33 |
| runall2_status.txt | OK | 07_aggregate | 06:50:34 |
| runall2_status.txt | START | 11_session | 06:50:34 |
| runall2_status.txt | OK | 11_session | 06:54:14 |
| runall2_status.txt | START | 12_phase2 | 06:54:14 |
| runall2_status.txt | OK | 12_phase2 | 07:00:52 |
| runall2_status.txt | START | 13_shap | 07:00:52 |
| runall2_status.txt | FAIL | 13_shap | 07:01:05 |
| runall3_status.txt | OK | 11_session | (finished by earlier process) 06:54:36 |
| runall3_status.txt | START | 12_phase2 | 06:54:36 |
| runall3_status.txt | OK | 12_phase2 | 07:01:13 |
| runall3_status.txt | START | 13_shap | 07:01:13 |
| runall3_status.txt | FAIL | 13_shap | 07:01:22 |

Notes:
- The first runner was stopped by the operating system at 05_tii_only_LSTM (low memory); that model was retrained in the second runner.
- Stage 13 (SHAP) finishes all its work and writes its files, but the process exits with code 127 at interpreter shutdown, so the runner logged FAIL. Outputs were verified (additivity 1.42e-05, decision check 1.0000).
- Stage 11 was completed by an earlier process after its runner was stopped.
- Stopping the second runner did not stop its shell: it kept going and ran stages 12 and 13 at the same time as the third runner. Its stage 13 overwrote six files in deploy_gpu/ (restored from the backup; XGBoost.pkl hash d243b124da3692ec verified). Stage 12 ran twice concurrently, so it was rerun alone (logs/runall4_12_phase2_clean.txt) and its output is the one kept here.
- The runners status files: logs/runall_status.txt (first), runall2_status.txt (second), runall3_status.txt (third).
## Completeness check

- 08 split: OK
- 09 models: OK
- 10 eval: OK
- 05 binary: OK
- 06 external: OK
- 07 tables: OK
- 11 session: OK
- 12 phase2: OK
- 13 shap: OK
- 16 reverse: OK
- stage console logs: 36 files, empty: none
## Revision run, 2026-09-21

Two evaluation defects were corrected and the affected stages rerun. No model
was retrained: XGBoost.pkl, scaler.pkl, features.pkl, label_encoder.pkl,
manifest.json and shap_global.json are byte-identical to the originals, so
SHA256SUMS.txt still verifies.

| Stage | Log | Time | What changed |
|---|---|---|---|
| 06_external | logs/06_validate_20260921_143209.log | 14:32 | Every prevalence-dependent metric is now reweighted to TRUSTLab's native class balance, not accuracy alone. |
| 07_aggregate | logs/07_aggregate_20260921_143341.log | 14:33 | Rerun on the refreshed external results; tables/ is byte-identical to before, which confirms the capped-partition figures did not move. |
| 16_reverse | logs/16_reverse_20260921_143349.log | 14:33 | External source classes are pooled by mapped TRUSTLab class before the macro average, so both sides of the comparison weight each class once. |

Defects corrected:

1. Script 06 adjusted only accuracy to TRUSTLab's native prevalence while
   printing precision, F1 and F2 from the capped partition beside the
   published baseline. Those metrics move with class balance exactly as
   accuracy does, so four of the five comparisons were between different
   populations. Reweighting now runs through the confusion matrix, so every
   figure is available in both forms. Prevalence-adjusted accuracy is
   unchanged to four decimals except for two cells that move by 0.0001
   (TII-SSRC-23 CNN1D and LSTM), where the earlier figure had been built from
   per-class accuracies already rounded to four decimals.
2. Script 16 averaged over external source class names on one side of the
   comparison and over TRUSTLab class names on the other, so classes with
   several source-dataset counterparts were weighted more heavily on the
   external side than on the reference side. It also wrote one column name,
   ref_macro_recall_mapped, for two different quantities: the value it logged
   was over every mappable class, the value it saved was the mean of the two
   per-dataset references. Pooling fixes the weighting; the all-classes
   reference is now a separate column, ref_macro_recall_all_mapped.

Effect on the reported result: the binary external-validation ranking is
unchanged (CSE-CIC-IDS2018 MLP remains best at 0.6364 prevalence-adjusted
accuracy, -0.2599 against the published 0.8963). The reverse-transfer ranking
changes at the top: CNN-BiLSTM now leads on mean external exact recall
(0.214) where XGBoost led before (it had gained from three separately counted
TII-SSRC-23 benign traffic types). WebBased is scored for the first time,
at 0.000 exact recall for all five models, because the 100-instance minimum
now applies to the pooled class rather than to each source class.

Files refreshed in this bundle: external_eval/ (15 JSON files, new
prevalence-adjusted blocks), external_validation_gpu.csv (new
f1_native_prevalence and f2_native_prevalence columns; vs_baseline is now the
prevalence-adjusted difference), reverse_transfer_mc/ (ranking.csv,
per_class.csv, reverse_transfer_mc.json, and the new per_trustlab_class.csv),
thesis_tables_revised.md (Table 18 gains the adjusted F1 and F2 columns; a
reverse-transfer section is appended). tables/ was regenerated and is
unchanged.

## Confirmation run, 2026-09-21

The trained models were put through the revised tests a second time, as an
independent rerun rather than a continuation of the revision run. Nothing was
retrained: artifacts/mc_random/XGBoost.pkl still hashes to
257f40e37094ccf7..., matching manifest.json.

| Stage | Log | What it tested |
|---|---|---|
| 06_external | logs/06_validate_20260921_144908.log | The fifteen binary models (three arms x five architectures) on the revised TRUSTLab external test partition, threshold 0.445 |
| 10_mc_eval | logs/10_mc_eval_20260921_145019.log | The five multiclass models on the TRUSTLab held-out split |
| 16_reverse | logs/16_reverse_20260921_145044.log | The five multiclass models on the revised, pooled external test |
| 07_aggregate | logs/07_aggregate_20260921_145150.log | Comparison tables rebuilt from the refreshed results |

Every one of the 75 result files under results/ is byte-identical to the
revision run, verified by SHA-256 before and after. The revised tests are
therefore deterministic on these models, and the copies held in this bundle
are current.

Results as retested. Binary external validation, prevalence-adjusted accuracy
against the published 0.8963: CSE-CIC-IDS2018 MLP 0.6364 (-0.2599),
Combined MLP 0.5756 (-0.3207), TII-SSRC-23 MLP 0.5293 (-0.3670). Multiclass
held-out accuracy and macro F1: XGBoost 0.9341 / 0.9293, CNN-BiLSTM
0.9301 / 0.9241, CNN1D 0.9242 / 0.9186, MLP 0.9202 / 0.9146, LSTM
0.9198 / 0.9146. Multiclass external, mean exact recall over the pooled
classes: CNN-BiLSTM 0.214, XGBoost 0.201, MLP 0.151, LSTM 0.098, CNN1D 0.035.

Stages 11, 12 and 13 were rerun as well, to close the question rather than
argue it from the imports:

| Stage | Log | Exit | Outcome |
|---|---|---|---|
| 11_session | logs/11_session_20260921_154319.log | 0 | Session-artifact test; the feature-ablation rungs reproduce (74 features 0.8442 accuracy, 0.8329 macro F1; removing up to four candidate features moves accuracy by at most +0.0045). |
| 12_phase2 | logs/12_phase2_20260921_154718.log | 0 | Phase-2 protocol, all three rungs (oracle, matched, learned); the hard classes reproduce at DoS 0.6723, Exploitation 0.7967 and Slowloris 0.7635 on the matched rung. |
| 13_shap | logs/13_shap_20260921_155037.log | 127 | SHAP; writes all of its files and then exits 127 at interpreter shutdown, as in the original run. Outputs written and verified. |

Their outputs are byte-identical to the original run, which confirms what the
imports implied: neither stage uses binary_metrics, and per_class_f1_ci was
not modified, so the revision could not have moved them. Note that stage 13
writes into deploy/, the CPU bundle, and does not touch this folder;
SHA256SUMS.txt still verifies at 127 of 127 after the rerun.

## Training tables re-verified, 2026-09-21

The training-time and internal-validation figures were rebuilt cell by cell
from binary_internal/ and compared with the thesis tables. All fifteen binary
rows match, as do the derived totals: binary training 5,557.3 seconds, the
four XGBoost models 118.1 seconds (1.14% of the 10,402.8 second grand total),
and LSTM plus CNN-BiLSTM 4,293.0 seconds (77.2% of binary training). Nothing
moved, which is expected: the revision changed only how external results are
scored, and script 05 was neither modified nor rerun. These figures are
validation on each configuration's own held-out 15% at the default threshold
of 0.5, not on TRUSTLab, and are not comparable with the published baseline.

## Why the binary detectors lose accuracy on TRUSTLab, 2026-09-21

Five diagnostics were run to attribute the external-validation collapse rather
than assert a cause for it. They are written up in thesis_tables_revised.md
under "Discussion of Table 18" and every figure is reproducible from
external_shift_diagnostic.json and clip_diagnostic.csv in this folder.

| Diagnostic | Question | Result |
|---|---|---|
| ROC-AUC and oracle threshold | Calibration, or no signal? | Mean ROC-AUC 0.4886; best prevalence-adjusted accuracy at any threshold 0.5620, below the 0.5714 of a benign-always classifier. Not calibration. |
| Target topline | Are the features adequate for TRUSTLab? | The same 74 features trained on TRUSTLab reach 0.9341. The features are adequate; the transferred mapping is not. |
| Domain classifier | How far apart are the domains? | Training rows and TRUSTLab rows separate at ROC-AUC 1.0000, proxy A-distance 2.000, the maximum. |
| Feature attribution and ablation | Which features, and does removing them help? | Packet Length Min carries 0.89 of the domain classifier's importance. Dropping the nine worst lifts accuracy 0.4995 to 0.5329 and F2 0.2124 to 0.3197, but ROC-AUC stays at chance. |
| Seen against unseen families, and range clipping | Attack semantics, or out-of-range input? | Families present in training 0.3200, absent 0.3645; clipping to plus or minus five training SD moves mean weighted ROC-AUC from 0.4906 to 0.4897. Neither. |

### A schema defect found by these diagnostics, not yet corrected

TRUSTLab exports the Active and Idle statistics in seconds; both training
sources export them in microseconds. In TRUSTLab the median ratio of Flow
Duration to Active Max is 999,999.9 and Active Max correlates with Flow
Duration divided by 10^6 at exactly 1.0, and four of those columns (Active Min,
Active Std, Idle Min, Idle Std) are identically zero in every row. Packet
Length Min has near-disjoint supports: zero in 77.2% of Combined training rows
and never zero in TRUSTLab, whose minimum is 37. src/schema.py reconciles the
three CICFlowMeter variants by column name and does not check units, so this
passed silently through every stage.

This affects the reverse-transfer experiment as well, in the opposite
direction. Nothing in this bundle has been corrected for it; the results here
are as measured. Correcting it means either dropping the nine features or
rescaling TRUSTLab's Active and Idle columns in src/schema.py and rerunning
from script 03, and either choice changes the external-validation and
reverse-transfer numbers.

## 66-feature rebuild, 2026-09-21 evening

TRUSTLab exports the eight Active and Idle columns without populating them:
Active Min, Active Std, Idle Min and Idle Std are identically zero in all
1,400,000 rows; Active Max equals Idle Max in 100% of rows; Active Mean is
exactly half of Active Max; and Active Max equals Flow Duration divided by 1e6.
Both training sources populate all eight properly, so every binary detector
learned a genuine response to features that arrive as a copy of Flow Duration
at test time. They were removed from the shared feature contract (74 to 66) in
src/schema.py, applied in scripts 04 and 08, and all twenty models retrained.

| Stage | Log | Result |
|---|---|---|
| 05_train | logs/rerun66_05.txt, rerun66_05b.txt | 15 binary detectors, 19:58:37 |
| 06_extern | logs/rerun66_06.txt | 19:59:41 |
| 07_tables | logs/rerun66_07.txt | 19:59:42 |
| 08_build | logs/rerun66_08.txt | both strategies, 19:59:55 |
| 09_mctrain | logs/rerun66_09.txt | 5 multiclass models, 21:40:02 |
| 10_mceval | logs/rerun66_10.txt | 21:40:18 |
| 11_session | logs/rerun66_11.txt | 21:43:39 |
| 12_phase2 | logs/rerun66_12.txt | 21:46:38 |
| 16_reverse | logs/rerun66_16.txt | 21:47:34 |
| 13_shap | logs/rerun66_13.txt | outputs written; exits 127 at shutdown as always. Run with --no-deploy, so deploy/ was not touched. |

What the rebuild changed. External transfer got WORSE, not better: best
prevalence-adjusted accuracy fell from 0.6364 to 0.5852, mean ROC-AUC from
0.4886 to 0.4698, and the count of detectors beating a trivial always-benign
classifier from 4 of 15 to 1 of 15. The neural detectors lost 0.07 to 0.08 while
XGBoost gained 0.01 to 0.02, so the removed columns were acting as a duplicate
duration channel the networks leaned on. Intra-TRUSTLab multiclass performance
is unchanged within 0.01 (XGBoost 0.9341 to 0.9313 accuracy), as expected from
those columns having zero SHAP contribution.

One anomaly found, explained and corrected. The chain trained all five models
inside one process per arm, and every model that ran after four PyTorch models
was sharply slowed: the three binary XGBoosts recorded 98.2, 75.9 and 10.5
seconds, the multiclass XGBoost 2,002.8, and the TII-SSRC-23 LSTM 1,048.3. Each
was retrained standalone afterwards and returned to normal -- 4.0, 4.0, 1.3,
77.3 and 119.8 seconds -- with metrics identical to the last decimal, and the
multiclass XGBoost produced a byte-identical model file (25ca234168549112). The
cause is PyTorch's caching allocator holding GPU memory after each model
finishes, leaving XGBoost unable to obtain clean GPU memory. Releasing it
before XGBoost runs restores the normal time, which is how the cause was
confirmed rather than assumed. The tables carry the clean standalone timings. The
other eleven neural models were within 20 percent of their 74-feature per-epoch
rates and were left as measured. Corrected totals: binary 5,140.3 s, multiclass
4,074.8 s, grand 9,215.1 s = 2.56 h, of which the four XGBoost models are 86.9 s
(0.94 percent). No accuracy figure changed at any point.

The cause was then fixed in the code rather than worked around. src/models.py
gains free_gpu(), which synchronises and empties PyTorch's CUDA cache, and
scripts 05, 09 and 12 call it immediately before handing the GPU to XGBoost.
Verified under the exact failing condition -- a full five-model sweep on the
TII-SSRC-23 arm -- where XGBoost now trains in 2 s against the 10.5 s the same
position cost before, with identical metrics and a byte-identical model file
(bdb5998b0d4c4948). Every model in this pipeline now gets the GPU it asks for.

Integrity: manifest.json and SHA256SUMS.txt regenerated; 127 of 127 verify, and
SHA256SUMS.txt.sha256 is 3790d15dd59a3fc66fd4312a5dbc7abc3c5838d08387c3e1bcb4943915f674cb.
knowledge/features/glossary.md was regenerated so it no longer documents the
eight removed columns.

## Retrieval-layer metrics refreshed, 2026-09-21

config/knowledge_map.py and scripts/15_eval_reports.py bake per-class figures
into the prose the RAG serves to an investigator, and those figures were still
from the 74-feature run. They were refreshed from results/mc_random/: DoS F1
0.6882 to 0.6714, Slowloris 0.7547 to 0.7639, Exploitation 0.7847 to 0.7838,
BufferOverflow 0.8014 to 0.8017, the Slowloris/DoS SHAP importance correlation
0.89 to 0.92, and the Exploitation-to-BufferOverflow confusion 8.5% to 8.7%.
The copy of knowledge_map.py in this bundle was updated to match and
SHA256SUMS.txt regenerated; the list hash is now
912b084726eb49706fc891246fc60d005ac59ad7cf4a144eb6af8fb524a229cf.

Every model in this pipeline was confirmed to run on the GPU: all four PyTorch
architectures place their parameters on cuda, both XGBoost builders request
device=cuda, and all four saved XGBoost models record device=cuda.

The code that produced everything here is committed on branch
fix/checkpoint-filter-and-runner as 643d577 (the 66-feature contract, free_gpu,
the prevalence-weighted metrics, the script 16 pooling fix) and a0530ca (the
leakage-safe splits and these refreshed figures). artifacts/shared_features.json
is tracked, so the frozen 66-feature list is versioned rather than living only
in a gitignored pickle.

## Retrieval corpus corrected, 2026-09-21

knowledge/ is what the deployed tool serves an investigator as model
reliability, and six of its files still carried figures from a run older than
either of today's. Corrected against results/mc_random/ and results/shap/:

| File | Was | Now |
|---|---|---|
| datasets/scope.md | accuracy 0.9337, macro F1 0.9287 | 0.9313, 0.9267 |
| datasets/scope.md | DoS 0.6703, Slowloris 0.7593, Exploitation 0.7860, BufferOverflow 0.8021 | 0.6714, 0.7639, 0.7838, 0.8017 |
| datasets/scope.md | mean ROC-AUC 0.4665, eleven of fifteen below 0.50 | 0.4698, ten of fifteen |
| datasets/scope.md | 952,000 training flows, 280,000 test | 951,944 train, 167,993 validation, 280,063 test |
| datasets/scope.md | twenty-one of the 74 features beyond 3 SD | seventeen of 66, and twenty-five for the CICIDS2018-only detector |
| datasets/scope.md | scoring 0.95-0.99 on their own data | 0.84-0.99, which the TII-SSRC-23 LSTM's 0.8386 now sets |
| detection/attack_dos.md, attack_slowloris.md, interpretability/caveats.md | SHAP correlation 0.9044, six of the top ten shared | 0.9159, seven shared |
| detection/attack_bufferoverflow.md, attack_exploitation.md | confused in 8.9% of cases | 8.7% |

The claim that twelve of sixteen classes sit at F1 0.94 or above was checked
and still holds. SHA256SUMS.txt regenerated; the list hash is now
d4c22548bf877aa3a10a0de786c01d4f6c8654f08e5d2186d1aba78809e007fd.

## The corpus now regenerates from results, 2026-09-21

config/knowledge_facts.py closes the drift permanently. It recomputes the
twenty-four measured figures knowledge/ states -- from results/mc_random/,
results/external_validation.csv, results/shap/ and results/external_shift_66.json
-- and either checks them or writes them back:

  python config/knowledge_facts.py           # check, exit 1 on drift
  python config/knowledge_facts.py --write   # rewrite the numbers in place

The prose stays hand-written. Each claim is a file, a regex whose single group
is the number, and the fact that belongs there, so a sentence can be reworded
freely as long as the pattern still matches. A pattern that stops matching is
reported as a failure rather than skipped, because a figure that has quietly
stopped being checked is how the corpus drifted in the first place. Script 07 also runs
this check at the end of every results refresh and warns when the corpus has
fallen behind, naming each figure and the command that fixes it. That warning
never changes 07's exit code, and a missing knowledge/ is passed over in
silence, so reproducing the tables without the retrieval assets is unaffected.
After a rerun, apply --write, then copy knowledge/ into this bundle and
regenerate SHA256SUMS.txt.

Two figures were corrected while building it. The training and validation
sizes now come from the n_train script 09 recorded rather than from
MC_VAL_FRACTION: the grouped split cannot land on the fraction exactly, and
the approximation disagreed by two rows. The internal accuracy range is quoted
to three decimals rather than two, because the best arm scores 0.9989 and
renders as "1.00" at two decimals, which would claim a perfect detector.

The list hash is now
e702d31b38618fd03cae5089eab6fefe1dedbcae2b3632bf85730ff8ebdd44a8.

## Script prose audited against the run, 2026-09-22

Every script header and comment was checked figure by figure against the
current results. Three claims were stale and are corrected in the code:

| Where | Was | Now |
|---|---|---|
| 12_phase2_protocol.py | the learned rung "passes about a quarter of all flows", range 0% (API) to 93% (DoS) | passes 27.5%, range 0.1% (BufferOverflow) to 80.4% (DoS); API is 2.5% |
| 12_phase2_protocol.py | MIN_SUPPORT justified by BufferOverflow at 1.0000 [1.000, 1.000] on eleven flows | reworded as the observation that prompted the rule; that class now scores 0.8333 on 13 flows, and zero-width intervals remain only where support supports them, DNS at 1,284 flows |
| 01_prepare_cicids2018.py, config/settings.py | combined corpus "roughly 1.17:1 benign-to-attack" | 1.18:1, from 13,486,009 against 11,403,701; script 01 also called it the training set, which is capped to 1:1 |
| 13_explain_shap.py (earlier) | multiclass XGBoost at accuracy 0.9337, macro F1 0.9287 | 0.9313 and 0.9267 |
| 16_reverse_transfer.py (earlier) | mc_random/XGBoost.pkl byte-identical to deploy_gpu/XGBoost.pkl | byte-identical to new_deploy_gpu/XGBoost.pkl; deploy_gpu holds the 74-feature model |

Checked and left alone: the corpus volumes in scripts 01, 02, 03 and 08, the
published baseline figures quoted in 06, 09, 10 and 12, and the narrated
earlier experiments in 14 and 15, which are in past tense and describe runs
that did happen.

knowledge/ in this bundle is now byte-identical to the project copy, and
settings_snapshot.py and config/knowledge_map.py match their sources. The list
hash is 176448a332d524ace3ca8898c69216d873701606902ec1a40caade89c72b89cb.

### Qualitative claims verified too, 2026-09-22

The figure-by-figure audit above covered numbers. The design claims in the
same headers were then checked against the data rather than taken on trust:

| Claim | Where | Verified |
|---|---|---|
| Three TRUSTLab column layouts: 79 with CWR Flag Cnt, 79 with CWE Flag Count for DDoS/DoS/PortScan/Slowloris, 81 with both plus Source File for Benign | src/schema.py | Exact. Eleven classes in the first, precisely those four in the second, Benign alone in the third |
| Benign spans eight capture sessions | 03_prepare_trustlab.py | Eight distinct Source File values in the first 218,124 rows alone |
| CICIDS2018 has 59 header rows pasted in as data | src/common.py | The prep log reports 59 dropped as non-data |
| Bot and SSH-Bruteforce are about half exact duplicates | 16_reverse_transfer.py | 47.7% and 50.0% dropped |
| External flows stop at 120 s, TRUSTLab runs to hours | 16_reverse_transfer.py | Exactly 120.0 s against 15,716.7 s, 4.4 hours |
| CICFlowMeter writes -1 in window features TRUSTLab never contains | 16_reverse_transfer.py | Half right, and corrected. CSE-CIC-IDS2018 writes -1 in 17.3% of FWD Init Win Bytes and 52.1% of Bwd Init Win Bytes; TII-SSRC-23 writes it in neither. The header now says so |

One correction resulted, in commit 347b366. Everything else held as written.

## Two GPU effects separated, 2026-09-22

The rebuild note above originally treated XGBoost's "mismatched devices"
warning as a symptom of the memory contention. It is not, and the two were
separated after testing:

| Effect | Cause | Consequence | Fixed |
|---|---|---|---|
| Slowdown | PyTorch's caching allocator holds GPU memory after each deep model, so XGBoost cannot obtain a clean allocation | 98.2 s against 4.0 s in script 05, 2,002.8 s against 77.3 s in script 09 | Yes -- free_gpu() in src/models.py, called by scripts 05, 09, 12 and 16 before XGBoost runs. Verified at 2 s in the same position afterwards |
| "mismatched devices" warning | The booster is on cuda while the input array is in host memory, so XGBoost builds a DMatrix instead of predicting in place | None worth acting on | No, deliberately. Measured on 200,000 rows: 0.74 s as saved against 4.26 s with the booster moved to the CPU, for identical predictions. The warned-about path is six times the faster one |

The warning still appears after free_gpu(), which the earlier note implied it
would not. Script 16 filters it because fifteen predictions would bury the
results, and its comment now says why that is safe. Comments in scripts 05, 09
and 16 were corrected to match. No number changed: script 16 reruns
byte-identical, and the models are untouched.

## SHAP scope widened and verification made reproducible, 2026-09-22

Two problems with the attribution work, found by asking why only one class
pair was analysed.

The pair diagnostic covered one pair of 120. TreeSHAP itself always covered
all sixteen classes and all 66 features -- that was never in doubt -- but the
similarity check was hardcoded to Slowloris and DoS, and its conclusion, that
sharing evidence is what makes a pair inseparable, was drawn from that single
case. Across all 120 pairs it does not hold:

| Pair | Importance correlation | Rank | Largest confusion |
|---|---|---|---|
| DDoS / PortScan | 0.959 | 1 of 120 | 0.9% |
| DoS / Slowloris | 0.916 | 2 of 120 | 44.0% |
| BufferOverflow / Exploitation | 0.337 | 27 of 120 | 22.0% |

Shared evidence is neither necessary nor sufficient for confusion. Script 13
now computes the full matrix to results/shap/pair_matrix_random.json, the
Slowloris/DoS record carries its rank among all pairs, and figure 10 plots
correlation against confusion for every pair so the claim cannot be
over-read.

The verification table quoted figures the script did not compute. Additivity
over the full sample, the decision check over the full sample, the missingness
list and the coverage share were all stated in the write-up while script 13
recorded only the 200-row additivity error. All four are now computed and
saved in shap_global.json, and missingness aborts the run if an unused feature
ever carries non-zero attribution. Measured on the deployed model: additivity
1.54972e-05 over 200 rows and over all 8,000, against a 1e-3 tolerance, so
64.5 times inside it; reconstruction picks the predicted class on 100% of
rows; five of 66 features are never split on -- Bwd URG Flags, CWR Flag Count,
ECE Flag Count, Fwd URG Flags and URG Flag Count, all TCP flag counters --
each with attribution exactly zero; and the six displayed features carry
0.7275 of each decision's attribution mass.

Correction on the attribution device. An earlier note here recorded SHAP as
running on the CPU and the GPU as worth 2.4 seconds. Both were wrong.
shap.TreeExplainer delegates to the booster, and a model trained with
device="cuda" keeps that setting through joblib, so the attribution has
always run on the GPU. Forcing the CPU costs 71.6 s against 2.8 s for 8,000
rows, about 26x, which on the full 280,063-row test set is eighty-four
minutes against three. The two earlier observations that should have exposed
this -- "bitwise identical" CPU and GPU values, and no speedup as the sample
grew -- were both GPU compared against GPU. Script 13 now reads the device
off the model, logs it, records it as attribution_device in
shap_global.json, and warns when it is not cuda.

manifest.json and SHA256SUMS.txt regenerated; the list hash is
e4ff8b560496b565fc1bfaf4a436ea69079e04223b2a3fa718d5e3a184817055.

## Table 30 written into the tables file, 2026-09-22

thesis_tables_revised.md now carries Table 30 with its three-part discussion:
the columns and why the comparison is made, the results, and what they mean.

The table lists the nine class pairs confused above 1% plus DDoS/PortScan, the
most similar pair of all 120, for contrast -- ten rows under a stated rule
rather than a selection. An earlier five-row version showed only the extremes
and the two confusable pairs, which omitted seven confused pairs and spent two
rows on pairs at 0.0% confusion.

Two figures were corrected while assembling it. An earlier draft said
Exploitation, BufferOverflow and Bruteforce each appear in three of the nine
confused pairs; Exploitation appears in four. And the rank of
BufferOverflow/Exploitation is metric-dependent -- twenty-seventh under
Pearson, fifteenth under Spearman -- so the text says it falls outside the ten
most similar pairs under either measure rather than quoting one rank.

SHA256SUMS.txt regenerated; the list hash is
45d9f63493cfce764f9bfe849fcec7e70a9171edbaa738f0032adfd292ea149d.
