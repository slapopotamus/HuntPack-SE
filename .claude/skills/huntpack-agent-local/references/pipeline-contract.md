# HuntPack Pipeline Contract

The six stages exchange structured artifacts in conversation context. Stable IDs prevent evidence and operational decisions from becoming detached during rendering.

## Shared envelope

Every stage output begins with:

```yaml
run_id: <UTC timestamp + slug>
stage: <1..6>
state: ok|degraded|blocked|failed
scope_mode: stack|general
inputs: [artifact IDs]
warnings: []
```

`degraded` is usable with visible limitations. `blocked` needs external input. `failed` is unusable. A downstream stage may not silently convert `degraded` to `ok`.

## Stable IDs

| Prefix | Artifact |
|---|---|
| `S01` | Source snapshot/ledger entry |
| `C01` | Factual claim |
| `I01` | Atomic or host indicator |
| `H01` | Detection hypothesis |
| `Q01` | CQL query |
| `A01` | Scheduled-search/alert package |
| `IOA01` | Custom IOA candidate |
| `CTRL01` | Hardening or containment control |

## Stage artifacts

### Stage 1 — ResearchBrief

- subject, aliases, dates, affected surface, exploitation/patch state;
- source ledger and snapshot manifest;
- claim ledger: text, source IDs, direct/inferred, confidence, contradiction state;
- IOC ledger: type, value, source IDs, context, confidence, volatility, proposed action;
- ATT&CK assertions with source IDs or `analyst_inference`;
- observable behaviors and research gaps.

### Stage 2 — HuntScaffold

Produce 4–8 hypotheses when evidence permits. Each `Hxx` contains source claim IDs, behavior, platform, ATT&CK assertion, required event/fields/repo/license, expected positive evidence, benign lookalikes, lookback, fidelity, scope status, telemetry status, validation method, and disposition (`inventory|hunt|alert-candidate|gap`).

### Stage 3 — QuerySet

Each feasible hypothesis maps to exactly one primary `Qxx`; a gap maps to no invented query. Preserve the canonical metadata header, raw CQL, intended repo, lookback, result/entity semantics, cost controls, static review state, and unresolved schema assumptions. Optional broad/narrow variants keep the same hypothesis ID and distinct query IDs.

### Stage 4 — OperationalizationSet

For each query, record `hunt-only` or `alert-package`. Alert packages require complete scheduling and response fields. IOA candidates are separate artifacts and never inherit readiness from the scheduled-search decision.

### Stage 5 — DefensePlan

Controls map to claim/hypothesis/technique IDs and include versioned authority, applicability, prerequisites, exact change, pilot scope, blast radius, compatibility, verification plus expected result, rollback, owner, approval, and retained evidence. Containment adds triggers, decision authority, preservation order, exceptions, recovery, and closure gates.

### Stage 6 — PackManifest

Record every stage state, artifact counts, coverage states, static gate results, pack/source hashes, tenant-validation state, publication path, and index status. Missing mandatory artifacts fail closed.

## Handoff invariants

1. Claims and indicators retain their source IDs.
2. Every hypothesis cites claims; every query cites a hypothesis.
3. Alert and IOA decisions cite query IDs and evidence state.
4. Controls cite claims or hypotheses and an authority.
5. Validation plans are not validation evidence.
6. `STATIC REVIEW PASSED` never becomes `TENANT PARSE CONFIRMED` without recorded tenant evidence.
