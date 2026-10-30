import csv
import io
from pathlib import Path

from purplesync.correlator import correlate
from purplesync.assessment import build_assessment
from purplesync.parsers import parse_blue_team, parse_red_team
from purplesync.report import results_to_csv

ROOT = Path(__file__).resolve().parents[1]


def test_report_includes_context_verification_and_approval():
    tests = parse_red_team((ROOT / "sample_data" / "red_team_tests.json").read_bytes())
    logs = parse_blue_team((ROOT / "sample_data" / "blue_team_logs.json").read_bytes())
    result = correlate([tests[0]], logs)[0]
    result.verification_status = "verified"
    result.remediation_mode = "simulated"
    result.reviewer = "Reviewer"
    result.approval_note = "=SUM(1,1)"
    result.approved_at = "2026-10-30T00:00:00+00:00"
    result.assessment = build_assessment(result, [])

    rows = list(csv.DictReader(io.StringIO(results_to_csv([result]))))
    assert rows[0]["asset_id"] == "lab-web-01"
    assert rows[0]["verification_status"] == "verified"
    assert rows[0]["reviewer"] == "Reviewer"
    assert rows[0]["approval_note"].startswith("'=")
    assert rows[0]["review_priority_band"] == "High"
    assert "identify whether" in rows[0]["blue_team_actions"]
