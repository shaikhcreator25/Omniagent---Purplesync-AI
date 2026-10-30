from pathlib import Path

from purplesync.correlator import correlate
from purplesync.mitre import lookup_technique
from purplesync.parsers import parse_blue_team, parse_red_team
from purplesync.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]


def _sample():
    tests = parse_red_team((ROOT / "sample_data" / "red_team_tests.json").read_bytes())
    logs = parse_blue_team((ROOT / "sample_data" / "blue_team_logs.json").read_bytes())
    return tests, logs


def test_known_sample_classifications():
    tests, logs = _sample()
    results = {item.test_id: item for item in correlate(tests, logs)}
    assert results["RT-002"].status == "Detected"
    assert results["RT-004"].status == "Detected"
    assert results["RT-001"].status == "Gap – missing evidence"
    assert results["RT-003"].status == "Gap – missing evidence"
    assert results["RT-005"].status == "Insufficient Data"
    assert results["RT-002"].technique_id == "T1566"


def test_mitre_alias():
    tech = lookup_technique("Simulated phishing", None)
    assert tech is not None
    assert tech.technique_id == "T1566"


def test_malformed_does_not_match_everything():
    tests, logs = _sample()
    tests[0].expected_detection = "totally-unrelated-signature-xyz"
    tests[0].keywords = []
    tests[0].technique_id = None
    tests[0].name = "Obscure lab action"
    result = correlate([tests[0]], logs)[0]
    assert result.status in {
        "Insufficient Data",
        "Gap – missing evidence",
        "Requiring investigation",
    }
    assert result.status != "Detected"


def test_contextual_correlation_respects_asset_and_time_window():
    tests, logs = _sample()
    test = tests[0]
    target_log = logs[0]
    matched = correlate([test], [target_log])[0]
    assert matched.evidence
    assert matched.evidence[0].asset_id == test.asset_id

    wrong_asset = target_log.model_copy(update={"asset_id": "lab-other-01"})
    wrong_asset_result = correlate([test], [wrong_asset])[0]
    assert wrong_asset_result.status == "Insufficient Data"
    assert wrong_asset_result.excluded_context_logs == 1

    old_event = target_log.model_copy(update={"timestamp": "2026-10-28T14:01:12Z"})
    old_event_result = correlate([test], [old_event])[0]
    assert old_event_result.status == "Insufficient Data"
    assert old_event_result.excluded_context_logs == 1


def test_pipeline_demo_tinyfish(monkeypatch):
    from purplesync.config import Settings

    tests, logs = _sample()
    settings = Settings(demo_mode=True, tinyfish_api_key="", openai_api_key="")
    results = run_pipeline(
        tests, logs, run_tinyfish=True, run_llm=True, settings=settings
    )
    first = next(item for item in results if item.test_id == "RT-001")
    assert first.siem_before is not None
    assert first.siem_before["alert_found"] is False
    assert first.siem_after is None
    assert first.llm_summary
    assert first.assessment is not None
    assert first.assessment.web_research_summary


def test_live_pipeline_uses_agent_and_search_for_findings(monkeypatch):
    from purplesync.config import Settings
    from purplesync.models import ReferenceEvidence

    tests, logs = _sample()
    settings = Settings(
        demo_mode=False,
        tinyfish_api_key="tf_test_key",
        max_tinyfish_queries=10,
    )
    agent_queries = []
    search_queries = []

    def fake_agent(query, phase, settings):
        agent_queries.append((query, phase))
        return {
            "mode": "live",
            "alert_found": query in {"Phishing email detected", "Encoded PowerShell"},
            "evidence": "Synthetic test response.",
        }

    def fake_references(technique_id, settings):
        search_queries.append(technique_id)
        return [
            ReferenceEvidence(
                source="MITRE ATT&CK",
                title=f"Technique {technique_id}",
                url=f"https://attack.mitre.org/techniques/{technique_id}/",
                snippet="Public detection guidance.",
            )
        ]

    monkeypatch.setattr("purplesync.pipeline.check_alert", fake_agent)
    monkeypatch.setattr(
        "purplesync.pipeline.search_and_fetch_references", fake_references
    )

    results = run_pipeline(tests, logs, settings=settings)

    assert len(agent_queries) == len(tests)
    assert all(phase == "before" for _, phase in agent_queries)
    assert len(search_queries) == len(tests)
    assert all(result.assessment.sources for result in results)
    assert all(result.assessment.red_team_actions for result in results)
    assert all(result.assessment.blue_team_actions for result in results)


def test_live_pipeline_requires_tinyfish_credentials():
    import pytest

    from purplesync.config import Settings
    from purplesync.tinyfish_agent import TinyFishError

    tests, logs = _sample()
    with pytest.raises(TinyFishError, match="TINYFISH_API_KEY"):
        run_pipeline(tests, logs, settings=Settings(demo_mode=False))


def test_search_failure_is_explicit_and_does_not_claim_public_grounding(monkeypatch):
    from purplesync.config import Settings
    from purplesync.tinyfish_references import ReferenceLookupError

    tests, logs = _sample()
    monkeypatch.setattr(
        "purplesync.pipeline.check_alert",
        lambda query, phase, settings: {
            "mode": "live",
            "alert_found": False,
            "evidence": "No matching alert.",
        },
    )

    def fail_search(technique_id, settings):
        raise ReferenceLookupError("TinyFish Search timed out.")

    monkeypatch.setattr("purplesync.pipeline.search_and_fetch_references", fail_search)
    settings = Settings(
        demo_mode=False,
        tinyfish_api_key="tf_test_key",
        max_tinyfish_queries=1,
    )

    result = run_pipeline(tests[:1], logs, settings=settings)[0]

    assert result.assessment is not None
    assert not result.assessment.sources
    assert "did not complete successfully" in result.assessment.web_research_summary
    assert "not externally grounded" in result.assessment.web_research_summary
