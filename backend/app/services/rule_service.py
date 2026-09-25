"""
rule_service.py
---------------
Extension point for the rule-based detector (Tier 1 flow rules, Tier 2
Suricata / ARP). It runs beside XGBoost, never after it, and its output is
read by the recommendation stage next to the model prediction and SHAP.

The engine itself is not built yet. Until it is, evaluate() returns None and
every recommendation reports the rule layer as "not evaluated" rather than
as "no rule fired" -- the two mean different things to an analyst.

CONTRACT FOR THE ENGINE
evaluate() returns {flow_index: [hit, ...]} for the flows it examined. A flow
it examined with no hit maps to []. Each hit is a dict:

    {
        "rule_id":   "T1-PORTSCAN-01",          # stable identifier
        "class":     "PortScan",                # one of the sixteen classes
        "tier":      1,                         # 1 flow CSV, 2 pcap
        "evidence":  "25 distinct ports from 10.0.0.5 to 10.0.0.20 in 60 s",
        "measured":  25,                        # value the rule compared
        "threshold": 20,                        # value it was compared with
        "severity":  "medium",                  # low / medium / high
    }

`evidence` is shown to the analyst and given to Qwen as a citable source, so
write it as a factual sentence about the traffic, with numbers.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def evaluate(flow_csv: str,
             findings: List[Dict[str, Any]]
             ) -> Optional[Dict[int, List[Dict[str, Any]]]]:
    """Rule hits per flow, or None when no rule engine is configured."""
    return None
