# PurpleSync AI demo

## Live TinyFish hackathon walkthrough

Show TinyFish Agent checking an allowlisted mock SIEM and TinyFish Search/Fetch
researching each finding. PurpleSync combines those public sources with its local
evidence match to produce flaws, a transparent triage estimate, and separate Red/Blue
Team actions. The operator applies any mock rule change; PurpleSync only verifies it.

## Steps

1. Copy `.env.template` to `.env` and add a newly generated TinyFish REST API key.
2. The template points to `https://release-enviable-supply.ngrok-free.dev/` and
   allowlists its exact hostname. Keep the ngrok tunnel and its upstream service running.
3. Run `streamlit run app.py`.
4. On **Ingest**, keep sample Red Team and Blue Team files selected.
5. Keep **Offline synthetic demo** unchecked. Click **Run TinyFish-assisted analysis**.
6. Open **Verify & review**.
   - RT-002 and RT-004 are **Detected**.
   - RT-001 and RT-003 are **Gap – missing evidence**.
   - RT-005 is **Insufficient Data**.
7. Expand a finding to show its asset/time evidence, TinyFish search sources, priority
   heuristic, flaws/unknowns, and distinct recommendations for both teams.
8. Apply a safe test change on the mock SIEM yourself, confirm the operator prompt, and
   run the TinyFish after-retest.
9. Enter a reviewer name and approve eligible findings. The export includes citations,
   recommendations, review priority, and session audit history.

## Offline synthetic presentation fallback

Select **Offline synthetic demo** in the sidebar. It uses pre-authored snapshots and
local guidance only; clearly identify this mode as synthetic rather than a live TinyFish
result. It does not need a TinyFish key or live SIEM host.

## What not to do

- Do not commit `.env` or `.streamlit/secrets.toml`.
- Do not paste production SIEM passwords into chat or screenshots.
- Do not use production logs, production credentials, or unrestricted websites in the demo.
- PurpleSync does not apply real remediation; the human operator owns any external change.
