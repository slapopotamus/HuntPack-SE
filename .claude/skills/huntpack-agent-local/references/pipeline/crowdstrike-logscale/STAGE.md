# Stage 3 — CrowdStrike CQL Query Set

**Input:** Stage 2 `HuntScaffold`.  
**Output:** `QuerySet`, one primary query per feasible hypothesis and explicit gaps for the rest.  
**State:** `ok|degraded|failed`.

This stage writes CQL only. It does not repeat research, create scheduled alerts, or claim tenant validation.

## Load references selectively

- `references/falcon-events.md` for event/field candidates.
- `references/functions.md` for function shapes.
- `references/hunt-patterns.md` for correlation ideas.
- `references/best-practices.md` for cost discipline.

These local references are working aids, not a Falcon compiler. Where they conflict, prefer current official LogScale documentation and tenant evidence. Never claim that local lint proves parsing.

## Query construction

1. Start with the narrowest available repo/tag/event filter.
2. Preserve the hypothesis's platform and telemetry assumptions.
3. Correlate process relationships with `aid` plus process ID; never join on PID alone.
4. Treat direct-parent-only logic as partial when wrappers or grandchildren are plausible.
5. Put selective filters before joins/aggregation and cap high-cardinality functions.
6. End with triage-useful fields or aggregation.
7. Store lookback in both `// TIMEFRAME:` and the query card's `data-lookback`.
8. If the required schema is unknown, return a gap or tenant-specific skeleton, not fabricated fields.

## Canonical query artifact

```yaml
- query_id: Q01
  hypothesis_id: H01
  disposition: inventory|hunt|alert-candidate
  repo: <intended repo>
  lookback: 7d
  result_entity: host|user|process|domain|ip|other
  dedupe_key: <stable fields or unknown>
  static_state: unreviewed|static_pass|static_fail
  tenant_state: unverified|parsed|tested|deployed
  schema_assumptions: []
  cql: |
    // HUNT: ...
    // HYPOTHESIS: H01
    // USE: hunt
    // MITRE: ...
    // CONF: medium
    // FP: medium
    // COST: low
    // TIMEFRAME: 7d — ...
    // REQUIRES: ...
    // FALSE POSITIVES: ...
    // TUNING: ...
    // VALIDATION: STATIC-ONLY
    ...
```

Every query carries all canonical header lines. `MITRE: N/A — inventory` is correct for administrative inventory. Use specific ATT&CK IDs only when the query actually observes the mapped behavior.

## Query card copy

Every query ships with reader-facing copy, not just metadata. For each query
record two strings alongside the canonical artifact, and hand both to Stage 6:

```yaml
  card_title: "Q01 · wscript.exe executing a .js from a browser-download path"
  card_note: "Looks for: wscript.exe or cscript.exe running a .js from Downloads
    or Temp. Accomplishes: catches the loader at execution — the flagship signal,
    and the one stage that does not change between builds."
```

- `card_title` is `Qxx · <short behavioural description>`. Describe what the
  query catches, not the technique number and not the raw `// HUNT:` line.
- `card_note` is one `Looks for:` sentence and one `Accomplishes:` sentence in
  analyst voice. `Looks for` restates the query's logic in plain language;
  `Accomplishes` says which stage of the chain it catches and how durable that
  signal is. Aim for 25–45 words total.
- This is interpretation of your own query, so it asserts nothing about a source
  and needs no snapshot. Do not smuggle unevidenced claims about the threat into
  it — those belong in Stage 1 with a claim ID.
- Where several queries are unequal, say so in one sentence for the section
  intro callout: which are the strong keepers, which depend on intrusion-specific
  stages, and which need a same-host correlation before they mean anything.

## Ratings

- `CONF` describes how strongly a hit supports the threat behavior, not how likely the query is to return data.
- `FP` describes expected benign lookalikes in a typical environment.
- `COST` accounts for window, regex breadth, joins, and cardinality.
- FP medium/high requires a concrete in-query `// TUNING:` exclusion.

## IOA candidates

List behaviorally durable candidates separately with query/hypothesis ID, process/path/command-line logic, exclusions, platform, positive test, benign test, and why it is not merely an IOC. Do not select prevent mode.

## Static review

Run the local field and heuristic syntax checks during drafting. Their outcomes are `STATIC-ONLY`. An unknown event/field is a failure unless supported by explicit tenant-schema evidence recorded in the artifact.

## Exit gate

Every non-gap hypothesis maps to a unique query ID with full metadata. No empty query set, unresolved placeholder, PID-only correlation, unbounded group, or silent schema assumption proceeds to Stage 4.
