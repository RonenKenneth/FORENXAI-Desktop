"""
test_cases.py
-------------
Case list: totals come from analysis.json, are cached in summary.json, and
a re-analysis (newer analysis.json) replaces the cached totals.

    python test_cases.py
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

root = Path(tempfile.mkdtemp())
os.environ["FORENXAI_DATA_DIR"] = str(root)
sys.path.insert(0, str(Path(__file__).parent))
from app.services import case_service  # noqa: E402


def write_case(case_id, threats):
    case = root / "cases" / case_id
    (case / "evidence").mkdir(parents=True, exist_ok=True)
    (case / "evidence" / "capture.pcapng").write_bytes(b"x")
    (case / "analysis.json").write_text(json.dumps({
        "file_name": "capture.pcapng",
        "traffic_summary": {"total_packets": 10584},
        "flow_summary": {"total_flows": 6996},
        "ml_analysis": {"summary": {"total_flows": 2016, "benign_flows": 2016 - threats,
                                    "threat_flows": threats, "threat_percentage": round(100 * threats / 2016, 2)},
                        "findings": [{"flow_index": i} for i in range(50)]},
    }), encoding="utf-8")
    return case


case = write_case("FX-20260101-000000", threats=2015)
(root / "cases" / "FX-20260101-000001").mkdir()                      # no analysis yet
rows = {r["case_id"]: r for r in case_service.list_cases()}
first = rows["FX-20260101-000000"]
assert first["status"] == "Analyzed" and first["total_packets"] == 10584 and first["total_flows"] == 6996
assert first["ml_total_flows"] == 2016 and first["threat_flows"] == 2015 and first["evidence_file"] == "capture.pcapng"
assert rows["FX-20260101-000001"]["status"] == "Incomplete"
assert (case / "summary.json").exists(), "totals are cached"
assert "findings" not in (case / "summary.json").read_text(encoding="utf-8"), "cache holds totals only"

time.sleep(0.05)
write_case("FX-20260101-000000", threats=10)                          # re-analysis
again = {r["case_id"]: r for r in case_service.list_cases()}["FX-20260101-000000"]
assert again["threat_flows"] == 10, "a newer analysis.json replaces the cached totals"

try:
    case_service.delete_case("../evil")
    raise AssertionError("path outside the cases folder was accepted")
except (ValueError, FileNotFoundError):
    pass

# Scheduled deletion: past deadline deleted, future kept, busy case waits,
# cancel removes the schedule, a bad id or date is refused.
past, future, busy = "FX-20260102-000000", "FX-20260102-000001", "FX-20260102-000002"
for cid in (past, future, busy):
    write_case(cid, threats=1)
case_service.set_retention(past, "2026-01-01T00:00:00+08:00")
case_service.set_retention(future, "2999-01-01T00:00")                  # local time, no offset
case_service.set_retention(busy, "2026-01-01T00:00:00Z")
assert {r["case_id"]: r for r in case_service.list_cases()}[future]["delete_after"].startswith("2999-01-01T00:00:00")
case_service.ACTIVE_CASES.add(busy)
assert case_service.purge_expired_cases() == [past]
assert not (root / "cases" / past).exists() and (root / "cases" / future).exists() and (root / "cases" / busy).exists()
try:
    case_service.delete_case(busy)
    raise AssertionError("a case under analysis was deleted")
except ValueError:
    pass
case_service.ACTIVE_CASES.discard(busy)
assert case_service.purge_expired_cases() == [busy], "deleted once the analysis finished"
case_service.set_retention(future, None)
assert {r["case_id"]: r for r in case_service.list_cases()}[future]["delete_after"] is None
for bad in (lambda: case_service.set_retention("../evil", None),
            lambda: case_service.set_retention(future, "next tuesday")):
    try:
        bad()
        raise AssertionError("bad retention request accepted")
    except (ValueError, FileNotFoundError):
        pass
print("ALL CHECKS PASSED")
