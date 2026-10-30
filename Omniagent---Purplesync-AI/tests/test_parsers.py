from pathlib import Path

import pytest

from purplesync.parsers import ParseError, parse_blue_team, parse_red_team

ROOT = Path(__file__).resolve().parents[1]


def test_parse_sample_json():
    tests = parse_red_team((ROOT / "sample_data" / "red_team_tests.json").read_bytes())
    logs = parse_blue_team((ROOT / "sample_data" / "blue_team_logs.json").read_bytes())
    assert len(tests) == 5
    assert tests[0].test_id == "RT-001"
    assert logs[1].alert_name == "Phishing email detected"


def test_parse_csv():
    tests = parse_red_team((ROOT / "sample_data" / "red_team_tests.csv").read_bytes())
    assert tests[0].expected_detection == "IDS rule Y"


def test_csv_formula_sanitized():
    payload = "test_id,name,expected_detection\n" "RT-X,=cmd|'/c calc'!A0,IDS rule Y\n"
    tests = parse_red_team(payload)
    assert tests[0].name.startswith("'")


def test_rejects_empty():
    with pytest.raises(ParseError):
        parse_red_team("   ")


def test_blue_requires_message_fields():
    with pytest.raises(ParseError):
        parse_blue_team('[{"timestamp":"now"}]')


def test_context_fields_parse_for_asset_and_time():
    tests = parse_red_team(
        "test_id,name,expected_detection,asset_id,executed_at,time_window_minutes\n"
        "RT-CTX,lab login,Impossible travel,lab-idp-01,2026-10-29T14:12:00Z,10\n"
    )
    assert tests[0].asset_id == "lab-idp-01"
    assert tests[0].executed_at == "2026-10-29T14:12:00Z"
    assert tests[0].time_window_minutes == 10


def test_rejects_duplicate_test_ids():
    payload = (
        '[{"test_id":"RT-X","name":"one","expected_detection":"alert"},'
        '{"test_id":"RT-X","name":"two","expected_detection":"alert"}]'
    )
    with pytest.raises(ParseError, match="Duplicate test_id"):
        parse_red_team(payload)


def test_rejects_invalid_test_timestamp():
    payload = (
        "test_id,name,expected_detection,executed_at\n"
        "RT-X,login,alert,not-a-timestamp\n"
    )
    with pytest.raises(ParseError, match="ISO 8601"):
        parse_red_team(payload)


def test_rejects_invalid_blue_team_timestamp():
    payload = "timestamp,alert_name\n" "yesterday,Some alert\n"
    with pytest.raises(ParseError, match="ISO 8601"):
        parse_blue_team(payload)
