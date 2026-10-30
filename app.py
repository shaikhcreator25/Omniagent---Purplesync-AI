"""PurpleSync AI Streamlit front-end."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pandas as pd
import streamlit as st

from purplesync.config import load_settings
from purplesync.logging_setup import configure_logging
from purplesync.models import CorrelationResult, RedTeamTest
from purplesync.parsers import MAX_ROWS, ParseError, parse_blue_team, parse_red_team
from purplesync.pipeline import run_pipeline
from purplesync.preflight import run_preflight
from purplesync.report import results_to_csv
from purplesync.tinyfish_agent import TinyFishError
from purplesync.workflow import (
    ReviewError,
    approve_finding,
    retest_finding,
)

logger = configure_logging()
ROOT = Path(__file__).resolve().parent
SAMPLE_RED = ROOT / "sample_data" / "red_team_tests.json"
SAMPLE_BLUE = ROOT / "sample_data" / "blue_team_logs.json"

st.set_page_config(
    page_title="PurpleSync AI",
    page_icon="🟣",
    layout="wide",
)

st.markdown(
    """
    <style>
      .status-Detected { color: #86efac; font-weight: 600; }
      .status-Gap { color: #fca5a5; font-weight: 600; }
      .hero { font-size: 0.95rem; color: #c4b5fd; }
    </style>
    """,
    unsafe_allow_html=True,
)


def _settings():
    return load_settings()


def _read_upload(upload) -> bytes:
    return upload.getvalue()


def _results_table(results: list[CorrelationResult]) -> pd.DataFrame:
    rows = []
    for item in results:
        rows.append(
            {
                "Test ID": item.test_id,
                "Test": item.test_name,
                "MITRE": item.technique_id or "—",
                "Technique": item.technique_name or "—",
                "Status": item.status,
                "Asset": item.asset_id or "not provided",
                "Executed at": item.executed_at or "not provided",
                "Match confidence (heuristic)": item.confidence,
                "Out-of-scope logs": item.excluded_context_logs,
                "Review priority": (
                    f"{item.assessment.priority_band} "
                    f"({item.assessment.priority_score}/100)"
                    if item.assessment
                    else "Not assessed"
                ),
                "Retest": item.verification_status.replace("_", " ").title(),
                "Reviewer": item.reviewer or "pending",
                "Comments": item.comments,
            }
        )
    return pd.DataFrame(rows)


with st.sidebar:
    st.title("PurpleSync AI")
    st.caption("Red Team tests × Blue Team logs × MITRE × TinyFish")
    base_settings = _settings()
    demo_mode = st.checkbox(
        "Offline synthetic demo (no live TinyFish API)",
        value=base_settings.demo_mode,
        help="Off means live TinyFish Agent checks are used to run analysis.",
    )
    settings = replace(base_settings, demo_mode=demo_mode)
    st.subheader("Runtime")
    st.write(f"Demo mode: **{settings.demo_mode}**")
    if settings.demo_mode:
        st.info("📴 Synthetic snapshots replace TinyFish calls in offline demo mode.")
    else:
        if not settings.tinyfish_api_key:
            st.error(
                "🔴 TinyFish: `TINYFISH_API_KEY` not set.\n\n"
                "Configure it in `.env` or enter below:"
            )
            key_input = st.text_input(
                "TinyFish API Key",
                type="password",
                help="Key stays in backend memory for this session; not committed to git.",
                key="manual_api_key_input",
            )
            if key_input:
                clean_key = key_input.strip()
                st.session_state["TINYFISH_API_KEY"] = clean_key
                import os

                os.environ["TINYFISH_API_KEY"] = clean_key
                st.rerun()
        else:
            # Masked key display
            masked = (
                settings.tinyfish_api_key[:12] + "••••••••"
                if len(settings.tinyfish_api_key) > 12
                else "••••••••"
            )
            st.caption(f"API key: `{masked}`")
            if st.session_state.get("tinyfish_live_verified"):
                st.success("🟢 TinyFish: Connected & Live Verified")
            elif st.session_state.get("tinyfish_live_verified") is False:
                st.error("🔴 TinyFish: Live verification failed — check preflight")
            else:
                st.warning(
                    "🟡 TinyFish: Key loaded (Unverified — click Preflight below)"
                )
    st.write(
        "LLM key: **configured**"
        if settings.has_llm
        else "LLM key: **not set** (local summaries)"
    )
    st.write(f"SIEM allowlist: `{', '.join(settings.allowed_siem_hosts)}`")
    st.caption(
        f"Budget: **{settings.max_tinyfish_queries} findings** per run "
        "(each finding = up to 5 HTTP calls to TinyFish)."
    )
    run_llm = st.checkbox("Generate local explanations", value=True)
    allow_external_llm = st.checkbox(
        "Send redacted context to OpenAI",
        value=False,
        disabled=not settings.has_llm,
        help="Only redacted finding text and evidence snippets are sent. Off by default.",
    )
    st.markdown(
        "Keys load from `.env` or `.streamlit/secrets.toml`. "
        "Never paste production secrets into this form."
    )
    st.divider()
    st.subheader("🔍 Preflight check")
    st.caption(
        "Test connectivity to each service independently. "
        "Does not start analysis or expose credentials."
    )
    if st.button("Run preflight checks", key="preflight_btn"):
        if settings.demo_mode:
            st.info("Preflight not needed in offline demo mode — no live calls made.")
        else:
            with st.spinner("Checking Agent, Search, Fetch, SIEM…"):
                pf = run_preflight(settings)
            st.session_state["tinyfish_live_verified"] = (
                pf["agent"]["ok"] and pf["search"]["ok"] and pf["fetch"]["ok"]
            )
            _icons = {True: "✅", False: "❌"}
            _error_labels = {
                "auth_failure": "🔑 Auth failure — API key invalid or expired.",
                "upstream_unavailable": "🌐 Upstream unreachable (SIEM/ngrok down?).",
                "ngrok_error": "🔌 ngrok ERR — upstream service not listening on its port.",
                "network_error": "📡 Network error — connectivity issue.",
                "config_error": "⚙️ Config missing — check .env.",
                "http_error": "⚠️ Unexpected HTTP error.",
            }
            for svc_key, label in [
                ("agent", "TinyFish Agent"),
                ("search", "TinyFish Search"),
                ("fetch", "TinyFish Fetch"),
                ("siem", "Mock SIEM"),
            ]:
                svc = pf[svc_key]
                icon = _icons[svc["ok"]]
                detail = svc.get("detail", "")
                action = svc.get("action", "")
                error_code = svc.get("error_code", "")
                if svc["ok"]:
                    st.success(f"{icon} **{label}**: {detail}")
                else:
                    err_label = _error_labels.get(error_code, "")
                    msg = f"{icon} **{label}**: {detail}"
                    if err_label:
                        msg += f"\n\n{err_label}"
                    if action:
                        msg += f"\n\n**Action:** {action}"
                    st.error(msg)
            if (
                pf["agent"]["error_code"] == "auth_failure"
                or pf["search"]["error_code"] == "auth_failure"
            ):
                st.warning(
                    "**🔑 Key action required:** TinyFish uses **one unified key** for Agent, "
                    "Search, and Fetch. Generate a fresh key at "
                    "[agent.tinyfish.ai/api-keys](https://agent.tinyfish.ai/api-keys), "
                    "update `TINYFISH_API_KEY` in `.env`, and restart Streamlit."
                )
            if pf["siem"]["error_code"] in ("upstream_unavailable", "config_error"):
                st.warning(
                    "**🔌 Mock SIEM status:** Direct local backend communication is available. "
                    "Ensure `sample_data/siem_snapshots.json` is present or configure a remote SIEM URL."
                )

st.title("PurpleSync AI")
st.markdown(
    '<p class="hero">Correlate Red/Blue evidence, identify detection gaps, and use TinyFish '
    "Agent + Search/Fetch to check the mock SIEM and research actionable guidance "
    "for both teams.</p>",
    unsafe_allow_html=True,
)

tabs = st.tabs(["1 · Ingest", "2 · Verify & review", "3 · Architecture", "4 · Demo"])

with tabs[0]:
    st.subheader("Load test data")
    col_a, col_b = st.columns(2)
    with col_a:
        red_file = st.file_uploader(
            "Red Team tests (JSON or CSV)", type=["json", "csv"]
        )
        use_sample_red = st.checkbox(
            "Use sample Red Team tests", value=red_file is None
        )
    with col_b:
        blue_file = st.file_uploader(
            "Blue Team logs (JSON or CSV)", type=["json", "csv"]
        )
        use_sample_blue = st.checkbox(
            "Use sample Blue Team logs", value=blue_file is None
        )

    st.divider()
    st.subheader("Or add one test manually")
    with st.form("manual_test"):
        m1, m2, m3 = st.columns(3)
        test_id = m1.text_input("Test ID", "RT-MAN")
        test_name = m2.text_input("Scenario name", "Simulated phishing")
        technique = m3.text_input("MITRE technique", "T1566")
        asset_id = st.text_input("Asset ID (optional)")
        executed_at = st.text_input(
            "Test time in ISO 8601 (optional)",
            help="When supplied, logs without a parseable timestamp are excluded.",
        )
        time_window = st.number_input(
            "Correlation window (minutes)", min_value=0, max_value=1440, value=30
        )
        expected = st.text_input(
            "Expected detection / alert", "Phishing email detected"
        )
        description = st.text_area("Description", "Optional notes for the correlator.")
        submitted = st.form_submit_button("Add to session")
        if submitted:
            st.session_state.setdefault("manual_red", [])
            if len(st.session_state["manual_red"]) >= MAX_ROWS:
                st.error(f"A maximum of {MAX_ROWS} manual tests can be queued.")
            else:
                st.session_state["manual_red"].append(
                    {
                        "test_id": test_id,
                        "name": test_name,
                        "technique_id": technique,
                        "expected_detection": expected,
                        "description": description,
                        "asset_id": asset_id,
                        "executed_at": executed_at or None,
                        "time_window_minutes": int(time_window),
                    }
                )
                st.success(f"Queued {test_id}")

    if st.button(
        "Run TinyFish-assisted analysis",
        type="primary",
        disabled=not settings.demo_mode and not settings.has_tinyfish,
    ):
        try:
            if red_file is not None:
                tests = parse_red_team(_read_upload(red_file))
            elif use_sample_red:
                tests = parse_red_team(SAMPLE_RED.read_bytes())
            else:
                tests = []
            extra = st.session_state.get("manual_red") or []
            if extra:
                tests.extend(RedTeamTest.model_validate(item) for item in extra)
            if not tests:
                st.error("Provide Red Team tests (upload, sample, or manual).")
            elif len(tests) > MAX_ROWS:
                st.error(f"A maximum of {MAX_ROWS} tests can be analyzed per run.")
            elif len({test.test_id for test in tests}) != len(tests):
                st.error("Test IDs must be unique across uploaded and manual tests.")
            else:
                if blue_file is not None:
                    logs = parse_blue_team(_read_upload(blue_file))
                elif use_sample_blue:
                    logs = parse_blue_team(SAMPLE_BLUE.read_bytes())
                else:
                    logs = []
                with st.spinner(
                    "Correlating evidence, checking the SIEM with TinyFish, "
                    "fetching public references…"
                ):
                    results = run_pipeline(
                        tests,
                        logs,
                        run_tinyfish=True,
                        run_llm=run_llm,
                        allow_external_llm=allow_external_llm,
                        run_references=True,
                        settings=settings,
                    )
                st.session_state["results"] = results
                st.session_state["manual_red"] = []
                st.success(f"Finished {len(results)} tests. Open Verify & review.")
                logger.info("UI correlation complete for %s tests", len(results))
        except ParseError as exc:
            st.error(f"Could not parse input: {exc}")
        except Exception:
            logger.exception("Correlation run failed")
            st.error(
                "Correlation failed. Check logs/purplesync.log (secrets are redacted)."
            )

with tabs[1]:
    results: list[CorrelationResult] = st.session_state.get("results") or []
    if not results:
        st.info("Run a correlation from the Input tab to populate this dashboard.")
    else:
        frame = _results_table(results)
        approved = [item for item in results if item.approved_at]
        completed_retests = sum(
            event.action == "retest_completed"
            for item in results
            for event in item.audit_events
        )
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Tests", len(results))
        c2.metric("Detected", int((frame["Status"] == "Detected").sum()))
        c3.metric("Gaps", int((frame["Status"] == "Gap – missing evidence").sum()))
        c4.metric("Human approved", len(approved))

        st.dataframe(frame, use_container_width=True, hide_index=True)
        st.caption(
            "Local correlation stays deterministic. TinyFish checks the allowlisted "
            "SIEM and grounds unresolved findings in public references; it never "
            "changes real SIEM rules."
        )

        st.subheader("Finding detail")
        for index, item in enumerate(results):
            with st.expander(f"{item.test_id} · {item.test_name} · {item.status}"):
                st.write(
                    f"**MITRE:** {item.technique_id or 'unmapped'} "
                    f"({item.technique_name or 'n/a'}) · tactic: {item.tactic or 'n/a'}"
                )
                st.write(
                    f"**Scope:** asset `{item.asset_id or 'not supplied'}` · "
                    f"time `{item.executed_at or 'not supplied'}` · "
                    f"window ±{item.time_window_minutes or 0} min"
                )
                st.write(f"**Expected detection:** {item.expected_detection}")
                st.write(f"**Match confidence (heuristic):** {item.confidence}")
                if item.excluded_context_logs:
                    st.caption(
                        f"Excluded {item.excluded_context_logs} log(s) outside the "
                        "specified asset/time scope."
                    )
                st.write(item.comments)
                if item.evidence:
                    st.markdown("**Log evidence**")
                    st.dataframe(
                        pd.DataFrame([e.model_dump() for e in item.evidence]),
                        hide_index=True,
                        use_container_width=True,
                    )
                if item.assessment:
                    assessment = item.assessment
                    st.markdown("### TinyFish-grounded evaluation")
                    st.caption(
                        f"Review priority: **{assessment.priority_band} "
                        f"({assessment.priority_score}/100)** — {assessment.priority_basis} "
                        "This is a triage heuristic, not a probability that an attack "
                        "succeeded or a measured detection rate."
                    )
                    # Show pipeline stage checklist for this finding
                    _stage_icons = {
                        "ok": "✅",
                        "failed": "❌",
                        "skipped": "⏭️",
                        "pending": "⏳",
                    }
                    stage_cols = st.columns(3)
                    stage_cols[0].caption(
                        f"{_stage_icons.get(item.stage_correlation, '⏳')} "
                        f"Correlation: **{item.stage_correlation}**"
                    )
                    stage_cols[1].caption(
                        f"{_stage_icons.get(item.stage_agent, '⏳')} "
                        f"Agent/SIEM: **{item.stage_agent}**"
                    )
                    stage_cols[2].caption(
                        f"{_stage_icons.get(item.stage_references, '⏳')} "
                        f"Search/Fetch: **{item.stage_references}**"
                    )
                    st.info(assessment.web_research_summary)
                    if assessment.flaws_and_unknowns:
                        st.markdown("**Flaws, gaps, and unknowns**")
                        for note in assessment.flaws_and_unknowns:
                            st.markdown(f"- {note}")
                    red_column, blue_column = st.columns(2)
                    with red_column:
                        st.markdown("**Red Team — next steps**")
                        for action in assessment.red_team_actions:
                            st.markdown(f"- {action}")
                    with blue_column:
                        st.markdown("**Blue Team — next steps**")
                        for action in assessment.blue_team_actions:
                            st.markdown(f"- {action}")
                    if assessment.sources:
                        st.markdown("**TinyFish Search/Fetch sources**")
                        for source_index, source in enumerate(assessment.sources):
                            st.link_button(
                                f"{source.source}: {source.title}",
                                source.url,
                                key=f"assessment_source_{index}_{source_index}",
                            )
                            st.text(source.snippet)
                elif item.assessment_error:
                    _ec = getattr(
                        next(
                            (
                                e
                                for e in item.audit_events
                                if e.action == "public_reference_lookup_failed"
                            ),
                            None,
                        ),
                        "details",
                        item.assessment_error,
                    )
                    if "401" in item.assessment_error:
                        st.error(
                            "🔑 **TinyFish Search/Fetch: HTTP 401 — key invalid/expired.** "
                            "Local correlation succeeded. External grounding unavailable. "
                            "Generate a new key at https://agent.tinyfish.ai/api-keys "
                            "and update `TINYFISH_API_KEY` in `.env`."
                        )
                    elif (
                        "502" in item.assessment_error
                        or "503" in item.assessment_error
                        or "upstream" in item.assessment_error.lower()
                    ):
                        st.error(
                            "🌐 **TinyFish infrastructure temporarily unavailable.** "
                            "Local correlation succeeded. External grounding unavailable. "
                            "Try again later or check TinyFish status."
                        )
                    else:
                        st.error(
                            f"TinyFish-grounded assessment unavailable: {item.assessment_error}"
                        )
                if item.siem_before or item.siem_after:
                    bcol, acol = st.columns(2)
                    with bcol:
                        siem_mode = (item.siem_before or {}).get("mode", "")
                        mode_label = (
                            " (synthetic)" if siem_mode == "demo" else " (live)"
                        )
                        st.markdown(f"**TinyFish / SIEM before{mode_label}**")
                        if item.siem_before and item.siem_before.get("status"):
                            v_badge = item.siem_before["status"]
                            st.caption(
                                f"Status: **{v_badge}** (alert found: {item.siem_before.get('alert_found')})"
                            )
                        st.json(item.siem_before or {})
                    with acol:
                        after_mode = (item.siem_after or {}).get("mode", "")
                        after_label = (
                            " (synthetic)" if after_mode == "demo" else " (live)"
                        )
                        st.markdown(f"**TinyFish / SIEM after retest{after_label}**")
                        if item.siem_after and item.siem_after.get("status"):
                            a_badge = item.siem_after["status"]
                            st.caption(
                                f"Status: **{a_badge}** (alert found: {item.siem_after.get('alert_found')})"
                            )
                        st.json(item.siem_after or {})
                if item.siem_error:
                    if "401" in item.siem_error:
                        st.error(
                            "🔑 **TinyFish Agent: HTTP 401 — key invalid/expired.** "
                            "Local correlation is available. SIEM check failed. "
                            "Generate a new key at https://agent.tinyfish.ai/api-keys."
                        )
                    elif (
                        "upstream" in item.siem_error.lower()
                        or "502" in item.siem_error
                        or "ngrok" in item.siem_error.lower()
                    ):
                        st.error(
                            "🌐 **TinyFish Agent: Remote SIEM unreachable.** "
                            f"{item.siem_error} "
                            "Verify the remote service is listening or use direct local backend Mock SIEM."
                        )
                    elif (
                        "network" in item.siem_error.lower()
                        or "connect" in item.siem_error.lower()
                        or "timed out" in item.siem_error.lower()
                    ):
                        st.error(
                            f"📡 **TinyFish Agent: Network error.** {item.siem_error}"
                        )
                    else:
                        st.error(f"TinyFish before-check failed: {item.siem_error}")
                if item.llm_summary:
                    st.markdown("**Explanation**")
                    st.write(item.llm_summary)
                if item.llm_error:
                    st.warning(item.llm_error)
                st.markdown("**Remediation and retest**")
                if item.verification_status == "not_retested":
                    if not item.siem_before:
                        st.info(
                            "Run the TinyFish before-check before starting a retest."
                        )
                    elif settings.demo_mode:
                        if st.button(
                            "Simulate fix and retest synthetic SIEM",
                            key=f"simulate_retest_{index}",
                        ):
                            try:
                                retest_finding(
                                    item, settings, "simulated", actor="demo operator"
                                )
                            except (ReviewError, TinyFishError) as exc:
                                logger.warning("Synthetic retest failed: %s", exc)
                                st.error(f"Retest failed: {exc}")
                            else:
                                st.rerun()
                    elif settings.has_tinyfish:
                        if completed_retests >= settings.max_tinyfish_queries:
                            st.warning(
                                "TinyFish retest budget for this run is exhausted."
                            )
                        else:
                            confirmed = st.checkbox(
                                "I made the remediation outside PurpleSync; only verify it.",
                                key=f"confirm_live_fix_{index}",
                            )
                            if st.button(
                                "Run TinyFish after-retest",
                                key=f"live_retest_{index}",
                                disabled=not confirmed,
                            ):
                                try:
                                    retest_finding(
                                        item,
                                        settings,
                                        "operator_reported",
                                        actor="operator",
                                    )
                                except (ReviewError, TinyFishError) as exc:
                                    logger.warning("Live retest failed: %s", exc)
                                    st.error(f"TinyFish retest failed: {exc}")
                                else:
                                    st.rerun()
                    else:
                        st.warning(
                            "Live retest is unavailable. Configure TinyFish or enable "
                            "demo mode for the synthetic workflow."
                        )
                else:
                    st.info(
                        f"Retest: **{item.verification_status.replace('_', ' ').title()}** "
                        f"({item.remediation_mode.replace('_', ' ')})"
                    )

                if item.approved_at:
                    st.success(
                        f"Approved by {item.reviewer} at {item.approved_at}. "
                        f"{item.approval_note or ''}"
                    )
                else:
                    with st.form(f"approve_finding_{index}"):
                        reviewer = st.text_input(
                            "Reviewer name", key=f"reviewer_{index}"
                        )
                        note = st.text_area(
                            "Review note (optional)", key=f"review_note_{index}"
                        )
                        submitted = st.form_submit_button("Approve finding")
                        if submitted:
                            try:
                                approve_finding(item, reviewer, note)
                                st.rerun()
                            except ReviewError as exc:
                                st.error(str(exc))

                if item.audit_events:
                    st.markdown("**Session audit timeline**")
                    st.dataframe(
                        pd.DataFrame(
                            [event.model_dump() for event in item.audit_events]
                        ),
                        use_container_width=True,
                        hide_index=True,
                    )

        if approved:
            st.download_button(
                "Download human-reviewed CSV report",
                data=results_to_csv(approved),
                file_name="purplesync_reviewed_report.csv",
                mime="text/csv",
            )
        else:
            st.info("Approve eligible findings to enable the reviewed report export.")

with tabs[2]:
    st.markdown(
        """
### Architecture
- **Ingestion** parses UTF-8 JSON/CSV Red Team tests and Blue Team logs,
  with size limits and formula-injection stripping.
- **Correlation** deterministically matches alert text, keywords, ATT&CK techniques,
  asset IDs, and a configurable event-time window. Missing context is not guessed.
- **ATT&CK** matching uses a curated local subset. TinyFish Search/Fetch automatically
  searches public ATT&CK/Sigma guidance for mapped findings, or NIST guidance when
  technique mapping is unavailable.
- **TinyFish-grounded evaluation** combines local evidence with retrieved public
  guidance, lists input flaws/unknowns, estimates a transparent review-priority score,
  and gives separate safe next steps to the Red and Blue Teams. The score is a triage
  heuristic, not a probability or a detection-rate estimate.
- **TinyFish Agent API** checks only an HTTPS SIEM URL whose exact hostname is
  allowlisted. PurpleSync sends the redacted alert query, not uploaded log contents.
  The agent is read-only; live remediation is performed outside PurpleSync by an operator.
- **Retest** runs only after a demo simulation or explicit operator confirmation.
  The demo's before/after snapshots are synthetic and pre-authored.
- **Human gate** records reviewer, note, retest status, and a per-session audit timeline.
  Session state is in memory and is not tamper-proof or durable.
- **LLM** is optional and disabled for external transmission unless the user opts in;
  common emails, IPv4 addresses, and credential-like values are redacted first.
- Live mode is the default. Offline snapshots are used only when **Offline synthetic
  demo** is explicitly selected.

### CIA triad (prototype)
| Goal | How PurpleSync approaches it |
| --- | --- |
| Confidentiality | Env/Streamlit secrets, HTTPS, host allowlist, minimal TinyFish query, redacted LLM opt-in. |
| Integrity | Pydantic, asset/time scope, response validation, human approval, CI tests. |
| Availability | Offline demo, finite timeouts, API budgets, visible failures. |

Uploaded data stays in app-session memory. Search/Fetch sends only technique IDs or a
generic NIST query; the SIEM Agent receives only the redacted expected-alert query.
The audit timeline is not tamper-evident.

### OWASP notes
- Live target URLs must use HTTPS and an exact configured hostname; credentials in URLs are rejected.
- Upload sizes and row counts are capped; CSV formula-leading text is neutralized.
- TinyFish page content and alert text are treated as untrusted; credentials are not inserted into prompts.
- This is a showcase prototype: no real rule writes, durable audit store, accounts, or
  comprehensive PII classifier.
        """
    )

with tabs[3]:
    st.markdown(
        """
1. Copy `.env.template` to `.env` and set your TinyFish API key. Live mode is the default.
2. `python -m venv .venv` then `pip install -r requirements.txt`.
3. `streamlit run app.py`.
4. Configure an HTTPS mock SIEM URL whose exact hostname is in `ALLOWED_SIEM_HOSTS`.
5. Keep sample files selected and click **Run TinyFish-assisted analysis**. Each result
   gets a live Agent API before-check and a TinyFish Search/Fetch-based assessment.
6. Review evidence, the heuristic priority estimate, public sources, and separate Red
   and Blue Team next steps.
7. After making a fix in the mock SIEM, confirm it and run TinyFish after-retest.
8. Approve verified or already-detected findings with a reviewer name. Only approved
   findings can be exported as a reviewed CSV.
9. For an offline presentation, select **Offline synthetic demo**; its preset results are
   synthetic and do not call TinyFish.
10. RT-002 and RT-004 are initially detected; RT-003 remains a detection gap and RT-005
   has insufficient matching evidence.

### Live TinyFish
Set `PURPLESYNC_DEMO_MODE=false`, configure `TINYFISH_API_KEY`, and set `SIEM_URL` to
an HTTPS mock SIEM host included in `ALLOWED_SIEM_HOSTS`. Apply any real remediation
outside PurpleSync, then explicitly confirm it before the live after-check. The API agent
does not write rules, and a matching post-check is evidence—not proof of production safety.
        """
    )
    st.code(SAMPLE_RED.read_text(encoding="utf-8")[:700] + "\n…", language="json")
