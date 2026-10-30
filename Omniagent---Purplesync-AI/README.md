# PurpleSync AI

PurpleSync is a defensive Purple Team showcase prototype. It ingests Red Team test
definitions and Blue Team telemetry, correlates them deterministically by alert content,
ATT&CK technique, asset, and event time, and presents evidence and likely detection gaps.
Live mode uses TinyFish Agent to inspect an HTTPS, allowlisted mock SIEM and TinyFish
Search/Fetch to ground a per-finding evaluation, review-priority estimate, missing
evidence, and distinct safe next steps for both teams. Offline synthetic mode is available
only as an explicit presentation fallback.

PurpleSync does not generate exploits or modify a real SIEM.

## Architecture

```
Red Team CSV/JSON ─┐
                   ├─► validated input ─► asset/time-aware correlation ─► review
Blue Team logs ────┘                              │                         │
                                                  └─ TinyFish before/retest ┘
                                                            │
                                           redacted optional explanation + CSV
```

| Module | Role |
| --- | --- |
| `app.py` | Streamlit UI (input, results, security notes, demo) |
| `purplesync/parsers.py` | JSON/CSV ingestion and sanitization |
| `purplesync/correlator.py` | Deterministic matching and asset/time scope |
| `purplesync/mitre.py` | Curated local ATT&CK technique subset |
| `purplesync/tinyfish_agent.py` | Read-only TinyFish Agent API and offline snapshots |
| `purplesync/tinyfish_references.py` | TinyFish Search/Fetch for public ATT&CK, Sigma, or NIST guidance |
| `purplesync/assessment.py` | Transparent priority heuristic, flaws, and team-specific actions |
| `purplesync/workflow.py` | Explicit retest and human-approval gates |
| `purplesync/privacy.py` | Redaction of common identifiers before external calls |
| `purplesync/llm_helper.py` | Local explanation or opt-in OpenAI summary |
| `purplesync/pipeline.py` | Correlation and before-check orchestration |

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.template .env   # or: cp .env.template .env
streamlit run app.py
```

The default SIEM URL and allowlist are configured for
`https://release-enviable-supply.ngrok-free.dev/`. Keep the ngrok tunnel running and
ensure its upstream service is reachable. Open the app, configure your TinyFish key,
use the sample Red/Blue data, and click **Run TinyFish-assisted analysis**. TinyFish Agent checks the
SIEM, while TinyFish Search/Fetch retrieves relevant public guidance for every finding.
The evaluation reports a heuristic review-priority score, evidence gaps, cited sources,
and separate Red/Blue Team actions. After manually changing the mock SIEM, confirm the
change and run the live after-retest. Approve eligible findings to enable the reviewed
CSV export.

Live mode is the default (`PURPLESYNC_DEMO_MODE=false`). For a presentation without
network access or a public mock SIEM, explicitly choose **Offline synthetic demo** in
the app. It uses pre-authored snapshots in `sample_data/siem_snapshots.json`; simulated
results are not live TinyFish output and must be identified as synthetic.

## Secrets

Never commit API keys.

1. Copy `.env.template` to `.env` (gitignored).
2. Put your newly generated `TINYFISH_API_KEY` in `.env`; do not commit it.
3. The template uses `https://release-enviable-supply.ngrok-free.dev/`; keep
   `ALLOWED_SIEM_HOSTS` exactly `release-enviable-supply.ngrok-free.dev` unless you
   change the SIEM URL.
4. Optionally set `OPENAI_API_KEY`; external summaries require a separate explicit opt-in in the UI.
5. Streamlit Cloud: paste the same settings into **Secrets** (see `.streamlit/secrets.toml.template`).
6. GitHub Actions: add repository secret `TINYFISH_KEY`. CI tests mock external HTTP.

## TinyFish

Live path: `POST https://agent.tinyfish.ai/v1/automation/run` with `X-API-Key`.
The app validates HTTPS and an exact `ALLOWED_SIEM_HOSTS` hostname before sending the
target URL. TinyFish receives the expected alert query—not the uploaded log records.
Credentials are not added to the agent prompt. Start with a synthetic, unauthenticated
mock SIEM; never point the agent at production or arbitrary websites.

The Agent API is read-only in this application. For live retesting, an operator applies
the change outside PurpleSync and confirms that action before the after-check. A positive
check is verification evidence, not proof that a production control is safe.

TinyFish **Search/Fetch is part of every live analysis**, not an optional add-on. For
mapped findings it searches public ATT&CK and Sigma guidance using the technique ID
with generic detection-search terms; for unmapped findings it searches general NIST
incident-response guidance. Retrieved
URLs are restricted to official ATT&CK, SigmaHQ, and NIST hosts. It does not send
uploaded log rows, asset IDs, usernames, or raw messages to Search/Fetch.

The review-priority score is an explicitly labeled heuristic from local finding status
and matched evidence severity. It is **not** a probability of attack success, a
confidence in the public sources, or a measured detection rate. Public pages guide human
review and do not prove that the local SIEM emitted an alert. If Search/Fetch fails, the
app displays that error alongside the local assessment instead of claiming external
grounding.

The workspace `.mcp.json` configures the TinyFish MCP server for compatible VS Code
agent sessions; the MCP server authenticates through TinyFish's browser-based OAuth.
The Streamlit app calls the Agent and Search/Fetch REST APIs and uses `TINYFISH_API_KEY`.
The MCP OAuth session does not automatically provide that REST API key to the app.

## Sample outcome

| Test | MITRE | Expected | Sample result |
| --- | --- | --- | --- |
| RT-001 malicious HTTP | T1071.001 | IDS rule Y | Gap, then synthetic after-snapshot verifies when user retests |
| RT-002 phishing | T1566 | Phishing email detected | Detected |
| RT-003 valid accounts | T1078 | Impossible travel login | Gap (login telemetry only) |
| RT-004 PowerShell | T1059.001 | Encoded PowerShell | Detected |
| RT-005 port scan | T1046 | Network scan detected | Insufficient Data |

## Tests and CI

```bash
pytest
black --check .
flake8 purplesync app.py tests --max-line-length=120
bandit -q -r purplesync app.py
```

`.github/workflows/ci.yml` runs those checks on push/PR and CodeQL for Python.

## Security boundaries and CIA

- **Confidentiality:** secrets in env/Streamlit secrets, HTTPS, exact host allowlist,
  redaction of common email/IP/credential-like values, and explicit opt-in before
  sending redacted finding context to an external LLM. Use synthetic data for demos.
- **Integrity:** Pydantic validation, deterministic matching, strict asset/time context,
  bounded uploads, evidence display, reviewer approval, and CI checks.
- **Availability:** offline demo snapshots, finite request timeouts, a TinyFish query
  budget, and explicit errors when external checks fail.

This is a prototype: its audit timeline and approvals are in-memory session state,
not tamper-evident or durable. It has no production identity system, RBAC, backup,
or real remediation connector. See `demo.md` and the **Architecture** tab.

## License / data

MITRE ATT&CK names and IDs are used as a public knowledge mapping. Sample logs are synthetic.
