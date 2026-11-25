# FORENXAI Repository Structure Guide

**Source branch:** `merge-main-forenxai-v3` at commit `8aef4d5`. This guide is
stored on `main`, but its structure and 371-file inventory describe the source
branch, not the smaller `main` checkout.

## Application flow

The desktop client in `frontend/` sends captures and case requests to the
Python service in `backend/`. The service extracts packet and flow evidence,
combines model predictions with rule-based detections, and returns results for
investigation, explanation, recommendations, and reports. `rag/` contains the
runtime retrieval knowledge; `training/` contains the research pipeline,
knowledge copy, and its experiment outputs.

## Top-level files

```text
.gitattributes
.gitignore
README.md
README_finetuned-xgboost.md
SETUP.md
```

- `README.md` — project overview and merge history.
- `README_FORENXAI.md` — application behavior and detection design.
- `README_finetuned-xgboost.md` — model bundle and fine-tuning details.
- `SETUP.md` — machine setup and operational instructions.
- `.gitignore`, `.gitattributes` — Git ignore and text/binary handling rules.

## Backend

`backend/app/` is the runtime API and analysis service. `models/` holds shipped
model assets; root-level scripts support running, testing, validating, and
tuning the service.

```text
backend/FORENXAI.Backend.spec
backend/requirements.txt
backend/run_backend.py
backend/run_tests.py
backend/app/main.py
backend/app/analysis/traffic_analysis.py
backend/app/api/analysis.py
backend/app/api/cases.py
backend/app/rules/rules.json
backend/app/rules/rules_tuning.json
backend/app/services/case_service.py
backend/app/services/cicflowmeter_service.py
backend/app/services/flow_service.py
backend/app/services/llm_provider.py
backend/app/services/logging_service.py
backend/app/services/model_facts.py
backend/app/services/model_service.py
backend/app/services/narration_service.py
backend/app/services/packet_rule_service.py
backend/app/services/packet_store.py
backend/app/services/pcap_service.py
backend/app/services/recommendation_service.py
backend/app/services/report_service.py
backend/app/services/review_service.py
backend/app/services/rule_service.py
backend/app/services/shap_service.py
backend/app/utils/runtime_paths.py
backend/models/forenxai/CHANGES.md
backend/models/forenxai/XGBoost.pkl
backend/models/forenxai/decision_thresholds.json
backend/models/forenxai/features.pkl
backend/models/forenxai/label_encoder.pkl
backend/models/forenxai/manifest.json
backend/models/forenxai/model_facts.json
backend/models/forenxai/ood_stats.json
backend/models/forenxai/scaler.pkl
backend/models/forenxai/shap_global.json
backend/models/llm/README.md
backend/sample_data/heldout_sample.csv
backend/sample_data/synthetic_test.pcap
backend/sample_data/synthetic_test.pcapng
backend/bench_recommendations.py
backend/compare_flow_features.py
backend/inspect_bundle.py
backend/test_cases.py
backend/test_classifier.py
backend/test_model_preprocessing.py
backend/test_model_service.py
backend/test_narration_rag.py
backend/test_packet_parsing.py
backend/test_packet_rules.py
backend/test_rag_pipeline.py
backend/test_recommendations.py
backend/test_recommendations_all_classes.py
backend/test_rules.py
backend/test_shap.py
backend/test_shap_service.py
backend/trace_flow.py
backend/tune_rules.py
backend/update_suricata_rules.py
backend/validate_rules.py
backend/verify_bundle.py
```

## Desktop client

`frontend/FORENXAI.Desktop/` is the Windows WPF application. `Views/` contains
the user-facing pages and dialogs, `Services/` handles backend communication,
process management, and PDF output, and `Models/` contains API/UI data models.

```text
frontend/FORENXAI.Desktop/App.xaml
frontend/FORENXAI.Desktop/App.xaml.cs
frontend/FORENXAI.Desktop/AssemblyInfo.cs
frontend/FORENXAI.Desktop/FORENXAI.Desktop.csproj
frontend/FORENXAI.Desktop/MainWindow.xaml
frontend/FORENXAI.Desktop/MainWindow.xaml.cs
frontend/FORENXAI.Desktop/Assets/logo.ico
frontend/FORENXAI.Desktop/Assets/logo.jpg
frontend/FORENXAI.Desktop/Assets/logo.png
frontend/FORENXAI.Desktop/Models/AnalysisModels.cs
frontend/FORENXAI.Desktop/Services/BackendApiService.cs
frontend/FORENXAI.Desktop/Services/BackendProcessService.cs
frontend/FORENXAI.Desktop/Services/PdfReportService.cs
frontend/FORENXAI.Desktop/Views/CasesView.xaml
frontend/FORENXAI.Desktop/Views/CasesView.xaml.cs
frontend/FORENXAI.Desktop/Views/DashboardView.xaml
frontend/FORENXAI.Desktop/Views/DashboardView.xaml.cs
frontend/FORENXAI.Desktop/Views/EvidenceView.xaml
frontend/FORENXAI.Desktop/Views/EvidenceView.xaml.cs
frontend/FORENXAI.Desktop/Views/InvestigationView.xaml
frontend/FORENXAI.Desktop/Views/InvestigationView.xaml.cs
frontend/FORENXAI.Desktop/Views/ReportsView.xaml
frontend/FORENXAI.Desktop/Views/ReportsView.xaml.cs
frontend/FORENXAI.Desktop/Views/RetentionDialog.cs
frontend/FORENXAI.Desktop/Views/XaiView.xaml
frontend/FORENXAI.Desktop/Views/XaiView.xaml.cs
```

## Retrieval knowledge (`rag/`)

This is the runtime RAG documentation and source index. `config/` builds and
indexes knowledge; `knowledge/` groups the material by dataset scope,
detection category, features, incident response, and interpretability.

```text
rag/README.md
rag/RAG_PIPELINE.md
rag/SOURCES_ACM.md
rag/_sources/SHA256SUMS.txt
rag/_sources/manifest.json
rag/config/build_playbooks.py
rag/config/extract_sources.py
rag/config/knowledge_map.py
rag/config/rag_index.py
rag/config/source_index.py
rag/knowledge/INDEX.md
rag/knowledge/datasets/scope.md
rag/knowledge/detection/attack_api.md
rag/knowledge/detection/attack_bruteforce.md
rag/knowledge/detection/attack_bufferoverflow.md
rag/knowledge/detection/attack_c2.md
rag/knowledge/detection/attack_ddos.md
rag/knowledge/detection/attack_dns.md
rag/knowledge/detection/attack_dos.md
rag/knowledge/detection/attack_evasion.md
rag/knowledge/detection/attack_exfiltration.md
rag/knowledge/detection/attack_exploitation.md
rag/knowledge/detection/attack_mitm.md
rag/knowledge/detection/attack_portscan.md
rag/knowledge/detection/attack_slowloris.md
rag/knowledge/detection/attack_tls.md
rag/knowledge/detection/attack_webbased.md
rag/knowledge/features/glossary.md
rag/knowledge/incident_response/command_and_control.md
rag/knowledge/incident_response/credential_attack.md
rag/knowledge/incident_response/crypto_weakness.md
rag/knowledge/incident_response/data_exfiltration.md
rag/knowledge/incident_response/denial_of_service.md
rag/knowledge/incident_response/dns_abuse.md
rag/knowledge/incident_response/evasion.md
rag/knowledge/incident_response/exploitation.md
rag/knowledge/incident_response/mitm.md
rag/knowledge/incident_response/reconnaissance.md
rag/knowledge/incident_response/web_application.md
rag/knowledge/interpretability/caveats.md
```

## Supporting tools (`tools/`)

```text
tools/README.md
tools/jdk.path
```

## Training and evaluation (`training/`)

This is the offline research and model-development pipeline; it is separate
from the runtime backend. `scripts/` runs the ordered experiments, `src/`
contains shared training utilities, `config/` stores experiment and knowledge
configuration, and `results/` contains evaluation artifacts, figures, and
tables. `bundle_docs/` records the shipped model bundle and its supporting
diagnostics. The `knowledge/` tree mirrors the runtime RAG topics.

```text
training/.gitignore
training/README.md
training/requirements.txt
training/run_pipeline.py
training/test_pipeline.py
training/config/__init__.py
training/config/claim_schema.py
training/config/doc_tree.py
training/config/feature_glossary.py
training/config/finetune_log.py
training/config/knowledge_facts.py
training/config/knowledge_map.py
training/config/llm_provider.py
training/config/settings.py
training/src/__init__.py
training/src/common.py
training/src/harmonise.py
training/src/metrics.py
training/src/models.py
training/src/schema.py
training/src/trustlab_io.py
training/scripts/00_verify_environment.py
training/scripts/01_prepare_cicids2018.py
training/scripts/02_prepare_tii.py
training/scripts/03_prepare_trustlab.py
training/scripts/04_align_and_build.py
training/scripts/05_train_binary.py
training/scripts/06_validate_external.py
training/scripts/07_aggregate_results.py
training/scripts/08_build_multiclass.py
training/scripts/09_train_multiclass.py
training/scripts/10_evaluate_multiclass.py
training/scripts/11_session_artifact_test.py
training/scripts/12_phase2_protocol.py
training/scripts/13_reverse_transfer.py
training/scripts/14_tune_xgboost.py
training/scripts/15_explain_shap.py
training/scripts/16_tuning_report.py
training/scripts/17_harmonisation_report.py
training/scripts/18_external_summary.py
training/scripts/19_key_results.py
training/scripts/check_shap_aggregation.py
training/knowledge/INDEX.md
training/knowledge/datasets/scope.md
training/knowledge/detection/attack_api.md
training/knowledge/detection/attack_bruteforce.md
training/knowledge/detection/attack_bufferoverflow.md
training/knowledge/detection/attack_c2.md
training/knowledge/detection/attack_ddos.md
training/knowledge/detection/attack_dns.md
training/knowledge/detection/attack_dos.md
training/knowledge/detection/attack_evasion.md
training/knowledge/detection/attack_exfiltration.md
training/knowledge/detection/attack_exploitation.md
training/knowledge/detection/attack_mitm.md
training/knowledge/detection/attack_portscan.md
training/knowledge/detection/attack_slowloris.md
training/knowledge/detection/attack_tls.md
training/knowledge/detection/attack_webbased.md
training/knowledge/features/glossary.md
training/knowledge/incident_response/command_and_control.md
training/knowledge/incident_response/credential_attack.md
training/knowledge/incident_response/crypto_weakness.md
training/knowledge/incident_response/data_exfiltration.md
training/knowledge/incident_response/denial_of_service.md
training/knowledge/incident_response/dns_abuse.md
training/knowledge/incident_response/evasion.md
training/knowledge/incident_response/exploitation.md
training/knowledge/incident_response/mitm.md
training/knowledge/incident_response/reconnaissance.md
training/knowledge/incident_response/web_application.md
training/knowledge/interpretability/caveats.md
training/bundle_docs/CHANGES.md
training/bundle_docs/README.md
training/bundle_docs/RUN_INDEX.md
training/bundle_docs/SHA256SUMS.txt
training/bundle_docs/SHA256SUMS.txt.sha256
training/bundle_docs/clip_diagnostic.csv
training/bundle_docs/decision_thresholds.json
training/bundle_docs/external_shift_diagnostic.json
training/bundle_docs/external_validation_gpu.csv
training/bundle_docs/manifest.json
training/bundle_docs/mc_per_class_random_gpu.csv
training/bundle_docs/mc_summary_random_gpu.csv
training/bundle_docs/ood_stats.json
training/bundle_docs/session_artifact_analysis_gpu.json
training/bundle_docs/shap_global.json
training/bundle_docs/thesis_paragraphs_final.md
training/bundle_docs/thesis_table_24a.md
training/bundle_docs/thesis_tables_final.md
training/bundle_docs/thesis_tables_revised.md
training/bundle_docs/thesis_tables_tuned.md
training/results/.gitkeep
training/results/arms/cicids_only_composition.json
training/results/arms/combined_composition.json
training/results/arms/tii_only_composition.json
training/results/cicids_only/CNN1D_internal.json
training/results/cicids_only/CNN_BiLSTM_internal.json
training/results/cicids_only/LSTM_internal.json
training/results/cicids_only/MLP_internal.json
training/results/cicids_only/XGBoost_internal.json
training/results/clip_diagnostic.csv
training/results/combined/CNN1D_internal.json
training/results/combined/CNN_BiLSTM_internal.json
training/results/combined/LSTM_internal.json
training/results/combined/MLP_internal.json
training/results/combined/XGBoost_internal.json
training/results/eval/report_grounding.json
training/results/external/cicids_only__CNN1D.json
training/results/external/cicids_only__CNN_BiLSTM.json
training/results/external/cicids_only__LSTM.json
training/results/external/cicids_only__MLP.json
training/results/external/cicids_only__XGBoost.json
training/results/external/combined__CNN1D.json
training/results/external/combined__CNN_BiLSTM.json
training/results/external/combined__LSTM.json
training/results/external/combined__MLP.json
training/results/external/combined__XGBoost.json
training/results/external/tii_only__CNN1D.json
training/results/external/tii_only__CNN_BiLSTM.json
training/results/external/tii_only__LSTM.json
training/results/external/tii_only__MLP.json
training/results/external/tii_only__XGBoost.json
training/results/external_shift_66.json
training/results/external_validation.csv
training/results/figures/fig10_shared_evidence_vs_confusion.png
training/results/figures/fig1_confusion_matrix.png
training/results/figures/fig2_shap_confusable_pairs.png
training/results/figures/fig3_generalisation_gap.png
training/results/figures/fig4_reverse_transfer.png
training/results/figures/fig5_multiclass_per_class_f1.png
training/results/figures/fig6_binary_per_class_heatmap.png
training/results/figures/fig7_roc_auc_vs_chance.png
training/results/figures/fig8_phase1_ladder.png
training/results/figures/fig9_prevalence_contrast.png
training/results/finetune/xgb_test_comparison_random.json
training/results/finetune/xgb_trials_random.csv
training/results/finetune/xgb_tuning_random.json
training/results/harmonised/fixes/external/cicids_only__CNN1D.json
training/results/harmonised/fixes/external/cicids_only__CNN_BiLSTM.json
training/results/harmonised/fixes/external/cicids_only__LSTM.json
training/results/harmonised/fixes/external/cicids_only__MLP.json
training/results/harmonised/fixes/external/cicids_only__XGBoost.json
training/results/harmonised/fixes/external/combined__CNN1D.json
training/results/harmonised/fixes/external/combined__CNN_BiLSTM.json
training/results/harmonised/fixes/external/combined__LSTM.json
training/results/harmonised/fixes/external/combined__MLP.json
training/results/harmonised/fixes/external/combined__XGBoost.json
training/results/harmonised/fixes/external/tii_only__CNN1D.json
training/results/harmonised/fixes/external/tii_only__CNN_BiLSTM.json
training/results/harmonised/fixes/external/tii_only__LSTM.json
training/results/harmonised/fixes/external/tii_only__MLP.json
training/results/harmonised/fixes/external/tii_only__XGBoost.json
training/results/harmonised/fixes/external_validation.csv
training/results/harmonised/fixes/reverse_transfer_mc/per_class.csv
training/results/harmonised/fixes/reverse_transfer_mc/per_trustlab_class.csv
training/results/harmonised/fixes/reverse_transfer_mc/ranking.csv
training/results/harmonised/fixes/reverse_transfer_mc/reverse_transfer_mc.json
training/results/harmonised/fixes/reverse_transfer_mc/shift.json
training/results/harmonised/fixes_120s/external/cicids_only__CNN1D.json
training/results/harmonised/fixes_120s/external/cicids_only__CNN_BiLSTM.json
training/results/harmonised/fixes_120s/external/cicids_only__LSTM.json
training/results/harmonised/fixes_120s/external/cicids_only__MLP.json
training/results/harmonised/fixes_120s/external/cicids_only__XGBoost.json
training/results/harmonised/fixes_120s/external/combined__CNN1D.json
training/results/harmonised/fixes_120s/external/combined__CNN_BiLSTM.json
training/results/harmonised/fixes_120s/external/combined__LSTM.json
training/results/harmonised/fixes_120s/external/combined__MLP.json
training/results/harmonised/fixes_120s/external/combined__XGBoost.json
training/results/harmonised/fixes_120s/external/tii_only__CNN1D.json
training/results/harmonised/fixes_120s/external/tii_only__CNN_BiLSTM.json
training/results/harmonised/fixes_120s/external/tii_only__LSTM.json
training/results/harmonised/fixes_120s/external/tii_only__MLP.json
training/results/harmonised/fixes_120s/external/tii_only__XGBoost.json
training/results/harmonised/fixes_120s/external_validation.csv
training/results/harmonised/fixes_120s/reverse_transfer_mc/per_class.csv
training/results/harmonised/fixes_120s/reverse_transfer_mc/per_trustlab_class.csv
training/results/harmonised/fixes_120s/reverse_transfer_mc/ranking.csv
training/results/harmonised/fixes_120s/reverse_transfer_mc/reverse_transfer_mc.json
training/results/harmonised/fixes_120s/reverse_transfer_mc/shift.json
training/results/mc_per_class_random.csv
training/results/mc_random/CNN1D_confusion.csv
training/results/mc_random/CNN1D_internal.json
training/results/mc_random/CNN1D_test.json
training/results/mc_random/CNN_BiLSTM_confusion.csv
training/results/mc_random/CNN_BiLSTM_internal.json
training/results/mc_random/CNN_BiLSTM_test.json
training/results/mc_random/LSTM_confusion.csv
training/results/mc_random/LSTM_internal.json
training/results/mc_random/LSTM_test.json
training/results/mc_random/MLP_confusion.csv
training/results/mc_random/MLP_internal.json
training/results/mc_random/MLP_test.json
training/results/mc_random/XGBoost_confusion.csv
training/results/mc_random/XGBoost_internal.json
training/results/mc_random/XGBoost_test.json
training/results/mc_summary_random.csv
training/results/phase2_random/phase1_learned.json
training/results/phase2_random/phase1_learned_confusion.csv
training/results/phase2_random/phase1_matched.json
training/results/phase2_random/phase1_matched_confusion.csv
training/results/phase2_random/phase1_oracle.json
training/results/phase2_random/phase1_oracle_confusion.csv
training/results/rag/report_demo.json
training/results/reverse_transfer_mc/per_class.csv
training/results/reverse_transfer_mc/per_trustlab_class.csv
training/results/reverse_transfer_mc/ranking.csv
training/results/reverse_transfer_mc/reverse_transfer_mc.json
training/results/reverse_transfer_mc/shift.json
training/results/runs/run_20260906T163224.json
training/results/runs/run_20260906T163425.json
training/results/runs/run_20260906T163445.json
training/results/runs/run_20260906T212137.json
training/results/session_artifact_analysis.json
training/results/shap/audit_66.json
training/results/shap/examples_random.json
training/results/shap/global_random.json
training/results/shap/pair_matrix_random.json
training/results/shap/pair_slowloris_dos_random.json
training/results/tables/01_main_comparison.csv
training/results/tables/02_generalisation_gap.csv
training/results/tables/03_vs_published.csv
training/results/tables/04_arm_comparison.csv
training/results/tables/05_architecture.csv
training/results/tables/06_per_class.csv
training/results/tables/07_feature_inventory.csv
training/results/tables/08_confusion_XGBoost.csv
training/results/tables/09_confusion_XGBoost_rownorm.csv
training/results/tables/10_harmonisation_before_after.csv
training/results/tables/11_external_validation_summary.csv
training/results/tables/12_key_ml_results.csv
training/results/tii_only/CNN1D_internal.json
training/results/tii_only/CNN_BiLSTM_internal.json
training/results/tii_only/LSTM_internal.json
training/results/tii_only/MLP_internal.json
training/results/tii_only/XGBoost_internal.json
```
