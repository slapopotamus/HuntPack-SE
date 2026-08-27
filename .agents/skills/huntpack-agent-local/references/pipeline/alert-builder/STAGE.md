# Stage 4 — Operationalization and Alert Packages

**Input:** Stage 3 `QuerySet` and IOA candidates.  
**Output:** `OperationalizationSet` with an explicit decision for every query.  
**State:** `ok|degraded|failed`.

This stage decides whether and how a query can operate. It does not infer a triggering host, ask for incident values, or treat IOA candidacy as alert readiness.

## Readiness decision

Default each query to `hunt-only`. Promote to `alert-package` only when all are defined:

- intended repo and required telemetry are documented;
- stable result entity and dedupe key;
- meaningful positive test and benign baseline plan;
- query window, cadence, late-data overlap, and threshold;
- grouping, deduplication, suppression, and re-notification behavior;
- notification route, owner, SLA, and failure monitoring;
- triage fields survive query aggregation;
- rollback/disable procedure.

`CONF high` and `FP medium` are not sufficient. Inventory queries are never alert packages by default. If tenant evidence is absent, keep the package `DESIGN ONLY` and do not call it ready to deploy.

## Scheduled-search schema

```yaml
- alert_id: A01
  query_id: Q01
  decision: hunt-only|alert-package
  readiness: design-only|tenant-parsed|canary-tested|deployed
  rationale: <why>
  search:
    name: <TTP-based, no victim/company names>
    repo: <repo>
    query_id: Q01
    lookback: 30m
    cadence: 15m
    overlap: 15m
    threshold: <count/condition>
    group_by: []
    dedupe_key: []
    suppression: <duration and exceptions>
    renotify: <policy>
    route: <generic destination or availability-dependent>
    owner: <role>
    sla: <triage target>
    failure_monitor: <how a failed/late search is noticed>
    disable_rollback: <exact disable path>
  observed_baseline: unknown|<measured count and period>
  positive_test: {steps, expected_fields, expected_result, evidence_state}
  benign_test: {steps, expected_fields, expected_result, evidence_state}
  alert_message: {subject, summary, first_checks}
  triage_checklist: []
  pivots: []
```

Use placeholders only for incident-time values (`REPLACE_WITH_HOSTNAME`, timestamp, user, hash). Every pivot names required substitutions and remains syntactically separate from the scheduled query.

## Triage quality

- Do not equate `ProcessBlocked` with complete prevention without corroborating prevention/result fields.
- Start with event semantics, parent/lineage, user/context, target, and prevalence.
- Include host-scoped and environment-wide pivots when both are useful.
- Define isolation/escalation conditions; avoid generic “check for suspicious activity.”
- State when a query is aggregated and which event-level fields are no longer available.

## Custom IOA schema

Each `IOAxx` includes source query/hypothesis, platform, rule group/type, process/path/parent/command-line patterns, exclusions, positive and benign tests, detect-only pilot, success metrics, rollback, and approval owner. Never recommend straight-to-block from static design alone.

## Exit gate

Every query has a recorded decision. An alert package missing any operational field returns to `hunt-only`. No alert email is generated for inventory or unready queries. Stage state is `degraded` when potentially useful candidates remain blocked on tenant telemetry/testing.
