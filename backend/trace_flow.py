"""
trace_flow.py
-------------
Print what FORENXAI stored for one flow, stage by stage: the CICFlowMeter
record, the model's prediction, TreeSHAP, the rule hits and the verdict.

    python trace_flow.py <flow number> [case id]

Reads the case's analysis.json and CICFlowMeter CSV; nothing is recomputed
(verify_bundle.py and the test suites check the computations). Without a case
id the most recently analysed case is used. Cases are read from
FORENXAI_DATA_DIR if it is set, else %LOCALAPPDATA%\\FORENXAI.
"""
import glob
import json
import os
import sys

import pandas as pd

if len(sys.argv) < 2 or not sys.argv[1].isdigit():
    sys.exit(__doc__)

flow_index = int(sys.argv[1])
data_dir = os.environ.get("FORENXAI_DATA_DIR") or os.path.join(os.environ.get("LOCALAPPDATA", ""), "FORENXAI")
root = os.path.join(data_dir, "cases")
if len(sys.argv) > 2:
    path = os.path.join(root, sys.argv[2], "analysis.json")
else:
    found = glob.glob(os.path.join(root, "FX-*", "analysis.json"))
    if not found:
        sys.exit(f"No analysed case in {root}")
    path = max(found, key=os.path.getmtime)
d = json.load(open(path, encoding="utf-8"))
f = next((x for x in d["ml_analysis"]["findings"] if x["flow_index"] == flow_index), None)
if f is None:
    sys.exit(f"Flow {flow_index} is not in {path}")
m = f["metadata"]

print("case:", os.path.basename(os.path.dirname(path)))
print("1 flow record:", m.get("Flow ID"), "| protocol", m["Protocol"], "| time", m.get("Timestamp"))
csv = glob.glob(os.path.join(os.path.dirname(path), "flows", "*.csv"))[0]
df = pd.read_csv(csv)
print(f"  CSV row {flow_index} of {len(df)} in {os.path.basename(csv)}")
print("  packets of this connection:", f.get("connection"))
print("2 ML:", f["predicted_class"], f"confidence {f['confidence']:.4f}",
      "| abstained", f.get("abstained"), f.get("abstain_reason") or "")
# SHAP is stored per flow in its own section, not inside the finding.
e = next((x for x in d["shap_analysis"]["explanations"] if x["flow_index"] == flow_index), None)
if e:
    print(f"3 TreeSHAP (log-odds), base value {e['base_value']:.3f}:")
    for c in e["contributors"][:5]:
        print(f"  {c['rank']}. {c['feature']} = {c['raw_value']} -> {c['shap_value']:+.3f} ({c['direction']})")
for h in f.get("rule_findings") or []:
    print(f"4 rule {h['rule_id']} ({h['class']}, tier {h.get('tier')}): "
          f"measured {h.get('measured')}, threshold {h.get('threshold')}")
    print("  ", h["evidence"])
if not f.get("rule_findings"):
    print("4 rules: none fired")
print("5 verdict:", f.get("verdict"), "| decided by:", f.get("verdict_source"))
