# Five-minute demonstration

## Before presenting

Install dependencies in a Python 3.12 virtual environment. Rehearse both samples offline. Optionally configure your own Groq key and test the chosen model before the event; do not rely on a fresh API quota on stage. Keep keys hidden in `.env`. Use a clean demo database by choosing a new `AEGIS_DB_PATH`; do not delete anyone else's data.

## 0:00–0:40 — Problem

“Security analysts spend time correlating repeated alerts and writing response plans. AegisFlow automates evidence gathering and explains a controlled response, while leaving containment to a human decision.”

Explain that this demonstration uses synthetic logs and local simulated actions. The two AI agents are advisory.

## 0:40–1:40 — Investigation

Choose **Phishing campaign demo** and investigate. Show the three affected accounts, source-traceable evidence IDs, timestamps, hashes, and the excluded unrelated message. Explain that the risk score is a heuristic and that the reputation feed is synthetic.

If presenting AI mode, enable it before investigation and show the `groq` label and recorded request count. If the API is unavailable, identify the `offline-fallback` label; the local pipeline still works.

## 1:40–2:40 — Response and control

Open **Response & approval**. Show the fixed five-action plan. Point out that only one observed suspicious session can be revoked and the AI cannot add execution targets. Enter a name and note. Click approval once without checking the box to show that the dashboard rejects it, then review and check it.

## 2:40–3:40 — Execute and report

Approve the simulated actions. Show the final state and five recorded effects. Explain that approval, action effects, and audit entries are one database transaction. Show that the final incident has no execute button. Download the JSON and Markdown reports.

## 3:40–4:30 — Benign case

Investigate the benign email. Explain low heuristic risk, zero containment actions, and inconclusive unknown reputation behavior. Dismiss after reviewing. This shows that every alert does not trigger blocking.

## 4:30–5:00 — Engineering and team

Show the separate agent modules, JSON schemas, fixed policy, and tests. Highlight the normal two-call AI path, hard call budget, and cached incidents. Each teammate names one module they own. Explain that future live security integrations would require authenticated roles and independently verified intelligence.

Do not claim production deployment, real threat detection accuracy, live reputation validation, authenticated analyst identity, or compliance with undisclosed hackathon rules.
