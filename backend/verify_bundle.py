"""
Smoke test for the FORENXAI model bundle.

Needs no PCAP, CICFlowMeter, Java or language model. It checks that the bundle
in backend/models/forenxai/ verifies, loads, classifies a bundled sample of
held-out TRUSTLab flows, and that TreeSHAP still reconstructs the model output.

Usage, from the backend folder:
    python verify_bundle.py            # bundle, accuracy, SHAP additivity
    python verify_bundle.py --llm      # also hash models/llm/qwen2.5-3b-q4.gguf

Exit code 0 means every check passed.
"""
import sys
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND))

from app.services.model_service import verify_model_bundle, load_model_bundle

SAMPLE = BACKEND / "sample_data" / "heldout_sample.csv"
LLM = BACKEND / "models" / "llm" / "qwen2.5-3b-q4.gguf"
LLM_SHA256 = "5ee4f07cdb9beadb"          # first 16 hex characters
MIN_ACCURACY = 0.90                       # measured 0.93 on the full test split
MAX_ADDITIVITY_ERROR = 1e-3               # the pipeline aborts above this

failures = []


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}  {detail}")
    if not ok:
        failures.append(name)


verify_model_bundle()                     # sizes and SHA-256 from manifest.json
bundle = load_model_bundle()
model, scaler = bundle["model"], bundle["scaler"]
model.set_params(device="cpu")   # trained on GPU; the test runs on any machine
encoder, features = bundle["label_encoder"], list(bundle["features"])
check("bundle verifies and loads", True,
      f"{len(bundle['classes'])} classes, {len(features)} features")

df = pd.read_csv(SAMPLE)
# Same cleaning as training and the backend: infinities and gaps become 0.
clean = (df[features].apply(pd.to_numeric, errors="coerce")
         .replace([np.inf, -np.inf], np.nan).fillna(0.0).astype("float32"))
X = scaler.transform(clean.values)
pred = encoder.inverse_transform(model.predict(X))
acc = float((pred == df["folder_class"].values).mean())
check("sample accuracy", acc >= MIN_ACCURACY,
      f"{acc:.4f} on {len(df):,} held-out flows (minimum {MIN_ACCURACY})")

import shap  # noqa: E402  (imported late so a missing package fails only here)
rows = X[:200]
explainer = shap.TreeExplainer(model)     # one instance for values and base value
sv = explainer.shap_values(rows)
sv = np.stack(sv, axis=-1) if isinstance(sv, list) else sv
base = np.asarray(explainer.expected_value, dtype=float)
margin = model.predict(rows, output_margin=True)
err = float(np.abs(sv.sum(axis=1) + base - margin).max())
check("SHAP additivity", err <= MAX_ADDITIVITY_ERROR, f"max error {err:.2e}")
check("SHAP picks the predicted class",
      bool(((sv.sum(axis=1) + base).argmax(1) == model.predict(rows)).all()))

if "--llm" in sys.argv:
    if not LLM.exists():
        check("language model present", False, str(LLM))
    else:
        h = hashlib.sha256()
        with open(LLM, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 22), b""):
                h.update(block)
        check("language model SHA-256", h.hexdigest().startswith(LLM_SHA256),
              h.hexdigest()[:16])

print()
print("ALL CHECKS PASSED" if not failures else f"FAILED: {failures}")
sys.exit(1 if failures else 0)
