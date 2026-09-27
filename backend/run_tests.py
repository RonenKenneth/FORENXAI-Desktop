"""
Run every maintained backend check and report one line each.

Run: .venv\Scripts\python.exe run_tests.py

The four older scripts (test_classifier, test_model_service, test_shap,
test_shap_service) are not included: they date from the first commit and
call functions that no longer exist.
"""

import subprocess
import sys

SUITES = [
    "test_model_preprocessing.py",   # float32 scaling, model on CPU
    "test_rules.py",                 # Tier 1 flow rules
    "test_packet_rules.py",          # Tier 2 packet rules
    "test_packet_parsing.py",        # protocol/info, padding, encryption, packet store
    "test_rag_pipeline.py",          # retrieval index
    "test_narration_rag.py",         # AI summary
    "test_recommendations.py",       # recommendations
    "test_recommendations_all_classes.py",
]

failed = 0
for suite in SUITES:
    result = subprocess.run([sys.executable, suite], capture_output=True, text=True)
    last = (result.stdout.strip().splitlines() or [""])[-1]
    ok = result.returncode == 0
    failed += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {suite:<40} {last[:70]}")

print(f"\n{len(SUITES) - failed}/{len(SUITES)} suites passed")
sys.exit(1 if failed else 0)
