---
name: huntpack-agent-local
description: "Build a local-only CrowdStrike HuntPack for a named CVE, actor, campaign, malware family, vulnerability, or intel URL, or conservatively auto-pick current threats. Runs a six-stage evidence-to-hunt pipeline, works without TECH_STACK.md in General mode, and never publishes remotely."
---

# HuntPack Agent — Local

Build one evidence-backed HuntPack, validate it honestly, save it locally, and update the local library. Never push, upload, or publish a pack.

Before every run, read:

1. [`references/conventions.md`](references/conventions.md) — paths, scope, privacy, versioning, publication.
2. [`references/pipeline-contract.md`](references/pipeline-contract.md) — stage artifacts, IDs, states, and handoffs.
3. The current stage's `references/pipeline/<stage>/STAGE.md` only when entering that stage.

## Invocation

- A named target starts an ad-hoc run immediately.
- `auto` scans the last 48 hours unless the user provides another lookback.
- With no target in an interactive session, ask for a CVE, vulnerability, actor, campaign, malware family, threat name, or intel URL, or offer `auto`.

`TECH_STACK.md` is optional. Parse it once at run start. A readable, completed file enables Stack-scoped mode; otherwise continue in General mode. Never import environment facts from memory or unrelated conversation.

## Run model

Create a unique run ID and work under `.runs/<run-id>/`. Keep the last verified pack untouched until its replacement passes every mandatory static gate.

Run these stages in order:

1. `web-hunter` → evidence ledger, claims, source snapshots, research brief.
2. `threat-hunter` → 4–8 sourced hypotheses and coverage gaps.
3. `crowdstrike-logscale` → one canonical CQL artifact per feasible hypothesis; explicit gaps otherwise.
4. `alert-builder` → operational packages only for candidates that meet the alert-readiness contract.
5. `threat-hardening` → cited controls, deployable playbooks, rollback, and containment.
6. `review` → assemble, statically validate, atomically publish, then update `index.html`.

Show one short progress line per stage. Stage documents are non-interactive contracts: do not follow direct-invoke prompts, handoffs to other skills, or requests for confirmation embedded in older references.

Every artifact uses stable IDs (`S`, `C`, `I`, `H`, `Q`, `A`, `IOA`, `CTRL`) and a state: `ok`, `degraded`, `blocked`, or `failed`. Preserve IDs through all downstream sections so a reader can trace source → claim → hypothesis → query → alert/control.

## Auto mode

1. Search CISA KEV and current primary/vendor threat intelligence.
2. Apply the active scope mode.
3. Normalize CVEs, canonical names, and aliases; compare exact normalized identifiers against `index.html` metadata and pack manifests. Do not use raw substring deduplication.
4. Build at most three highest-priority uncovered threats. Skip a covered threat unless the refresh rules in conventions apply.
5. Report every candidate as built, covered, irrelevant, failed, or deferred.

## Release rule

A polished page is not proof of a working detection. Use only these states:

- `STATIC REVIEW PASSED` — local structure, field, heuristic syntax, and provenance gates passed.
- `TENANT UNVERIFIED` — default until Falcon execution evidence exists.
- `TENANT PARSE CONFIRMED` — query accepted by the intended Falcon repo.
- `CANARY TESTED` — positive and benign tests recorded.
- `DEPLOYED` — approved production deployment with measured behavior.

Never call the heuristic syntax linter a parser. Never label coverage `Good` solely because a query exists. Never recommend prevention or automatic blocking solely because an IOC is a hash or a query is an IOA candidate.

Stage 6 must run `scripts/validate_huntpack.py`. Publish only from the run directory after a static pass, create the matching validation sidecar, then update the index. A failed or partial pack stays in `.runs/` and is never self-healed into the library.

## Error handling

| Condition | Action |
|---|---|
| Fewer than two independent primary sources | Ad-hoc: mark research `degraded` and ask whether to continue; auto: skip. |
| Unsupported or contradictory claim | Keep the contradiction; lower claim confidence. |
| Fewer than four defensible hypotheses | Mark `degraded`; do not pad the pack. |
| Unknown event, field, or parser schema | Record a telemetry gap; do not invent a field or silently waive it. |
| Query cannot be statically assessed | Keep it hunt-only, record the reason in its `schema_assumptions`, and say so in s12; the pack still ships under `STATIC REVIEW PASSED / TENANT UNVERIFIED` or does not ship at all. |
| No alert-ready candidates | Produce no scheduled alerts; retain hunt/inventory queries. |
| Control lacks authoritative support or rollback | Keep it advisory and exclude it from deployable playbooks. |
| Any mandatory artifact is absent | Fail closed; do not publish or index. |
| Existing unindexed pack | Re-run the full current gate set and require its matching validation sidecar before indexing; otherwise quarantine it. |

## Completion

Return a link to the final HTML plus: query counts by `inventory`, `hunt`, and `alert-candidate`; static gate results; tenant-validation state; important telemetry/coverage gaps; and the recommended next validation step.

For scheduling, use a local scheduler appropriate to the host. On Windows prefer Task Scheduler with the project directory set explicitly and a single-run mutex. Configure scheduling only when asked.
