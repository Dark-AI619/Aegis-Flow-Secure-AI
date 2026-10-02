# AegisFlow working concept

## Objective

Demonstrate a complete, explainable incident-response loop for a single phishing campaign, while separating advisory AI from policy and execution. The artifact is a running application rather than a set of prompts: input JSON → source-traceable evidence → bounded AI explanation → a fixed action plan → explicit analyst decision → persistent simulated effects → exported reports.

## Walkthrough

1. The analyst selects a synthetic case or supplies a strict JSON bundle. Every event has an ID, source, account, and timestamp with a timezone.
2. The application extracts sender and URL hosts from the selected alert. It parses URLs instead of relying on visual text; for example, `https://secure-payroll.test@innocent.example/` has host `innocent.example`.
3. Correlation finds events sharing an **exact normalized host** with the alert, including clicks and supplied sign-in logs. Unrelated events are excluded. The alert itself is retained even if it has no extractable hosts.
4. Each observation gets an evidence ID, original event ID, source label, event timestamp, indicator, explanation, and SHA-256 hash of the normalized event. A canonical hash of the whole input bundle identifies the input.
5. The local synthetic feed is checked. Unknown hosts stay unknown. If explicitly enabled, Serper provides up to two public-domain searches; reserved demonstration domains and IPs are not submitted. Search context never changes risk or executable actions.
6. Python computes a reproducible heuristic score and chooses the fixed phishing playbook. Evidence IDs bind every action to its source observations.
7. If Groq is enabled, two sequential CrewAI agents explain the evidence and the fixed plan. Only text JSON crosses the provider interface. There is no manager, execution tool, browsing loop, or embedding call.
8. JSON responses are validated. Unknown evidence IDs or malformed output discard the AI explanations and produce a clearly labeled local fallback. The fixed plan survives provider failure.
9. The analyst sees all proposed targets, enters a name and reason, and explicitly approves or dismisses the case. The dashboard also requires an approval checkbox. The CLI `--approve` flag is the equivalent explicit authorization.
10. The database transaction verifies the reviewed plan digest and the case state. Approval records each simulated effect and the analyst event together. Failure rolls back the entire decision. A case cannot execute twice.
11. JSON and Markdown exports include the evidence, plan, model usage, metadata, analyst decision, full timeline, and effects.

## Scoring policy

| Signal present anywhere in correlated evidence | Added score | Meaning |
|---|---:|---|
| Alert host in the synthetic malicious fixture | 60 | Demonstration reputation only |
| SPF or DKIM failure | 15 | Suspicious authentication, not proof |
| Urgency or credential-request language | 10 | Weak content heuristic |
| Shared alert host across multiple accounts | 10 | Possible campaign spread |
| Successful session marked suspicious in correlated logs | 15 | Supplied observation, not inferred compromise |

Each signal is counted once per incident, and the sum is capped at 100. Scores below 20 are low; 20–59 medium; 60–100 high. These are heuristic categories, **not calibrated probabilities**.

The included playbook proposes containment only at score ≥60 and only for alert hosts marked malicious in the local fixture. A high score without a locally identified malicious domain can still produce **no containment targets**. This conservative policy avoids pretending that text patterns or search snippets prove a domain is malicious.

## Fixed actions

| Action | Required evidence | Local simulated effect |
|---|---|---|
| `block_domain` | Exact alert host matching the synthetic malicious feed | Insert a blocklist effect row |
| `quarantine_email` | Observed email sharing a matching malicious host | Insert a message quarantine effect row |
| `revoke_session` | Observed successful, suspicious sign-in with matching host and a session ID | Insert a session revocation effect row |

No action executes an OS command, sends an email, changes an external security service, or calls a remediation API. Model explanations cannot introduce executable targets.

## State and caching

`review_required` transitions once to `contained` after approval or `dismissed` after dismissal. Low-risk cases remain reviewable and can be dismissed; no-action cases cannot be contained. Only the deterministic service creates action plans. Approval validates action kinds and evidence references against the stored plan.

Incident IDs are derived from the canonical input, selected AI/search mode, model, and policy version. Re-investigating the same configuration reuses its stored outcome, including final decisions or provider fallbacks. Offline and AI cases have separate identities. Settings such as the number of allowed model calls are not part of the cache key; changing those alone does not force a new run.

The two agents share one Groq adapter. The default two-attempt ceiling counts failures and blocks framework repair/retry calls. Groq SDK retries are disabled. Output is capped per request; token usage is captured when the provider returns it. If a network failure returns no usage, input-token billing cannot be inferred from the record.

## Metadata

The incident stores input SHA-256, creation time, schema and application versions, policy/playbook ID, static MITRE mapping, total and correlated event counts, AI-view limits, search opt-in, simulation flag, advisory-only flag, provider mode, request counts, token usage, and warnings. Evidence stores per-event SHA-256, source, observed timestamp, event ID, indicator, and evidence ID. Search records carry collection timestamps and source URLs when available. Approval events record analyst attribution, note, reviewed plan SHA-256, and execution results.

The original raw bundle is not retained in the database. Keep an authorized source copy if forensic reproduction is needed. SHA-256 establishes a stable reference; it does not authenticate the source or make SQLite tamper-proof.

## Trust boundaries

Input JSON, source labels, and search snippets are untrusted. Validation limits their shape and size, but does not prove accuracy. AI receives a bounded normalized evidence view rather than email bodies. Account identifiers can still be present. Prompt instructions tell both agents to treat evidence as data, while the execution boundary provides the stronger guarantee: models have no execution privileges.

This project is a hackathon prototype, not a complete SIEM or a production security control. Real integrations and authenticated approvals are deliberate follow-up work.
