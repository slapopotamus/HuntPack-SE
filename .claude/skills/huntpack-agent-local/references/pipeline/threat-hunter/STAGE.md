# Stage 2 — Hunt Scaffold

**Input:** Stage 1 `ResearchBrief` and scope profile.  
**Output:** `HuntScaffold` with 4–8 evidence-linked hypotheses when available.  
**State:** `ok|degraded|failed`.

This stage decides what to hunt. It does not research again, write CQL, create alert emails, recommend blocking, or manage an environment profile.

## Build hypotheses from evidence

For each meaningful attack-chain behavior:

1. cite its Stage 1 claim IDs;
2. state the attacker behavior and expected observable;
3. map ATT&CK only when the behavior supports it;
4. identify platform, Falcon event types, fields, repo/parser, and license assumptions;
5. state expected positive evidence and likely benign lookalikes;
6. choose a practical lookback and fidelity;
7. classify as `inventory`, `hunt`, `alert-candidate`, or `gap`.

Do not turn software inventory, a listener, a connection, or an administrative action into attacker ATT&CK behavior without evidence. Do not force every claim into a query.

## Scope and telemetry

- `scope_status` is `in_scope`, `general`, or `excluded`.
- `telemetry_status` is `documented`, `tenant_unverified`, `unavailable`, or `unknown`.
- Excluded hypotheses do not proceed.
- Unknown/unavailable telemetry becomes a visible gap, not an invented field.
- Consider wrapper/interpreter processes, two-generation lineage, service/container execution, IPv4/IPv6, proxy/DNS visibility, and platform variants where relevant.

## Output schema

```yaml
hunt_scaffold:
  attack_chain:
    - {order, claim_ids, behavior, platform, detection_goal}
  hypotheses:
    - hypothesis_id: H01
      claim_ids: [C01]
      statement: If <activity>, we should observe <evidence> in <telemetry>.
      behavior: <one behavior>
      platform: windows|linux|macos|identity|cloud|network|cross-platform
      attack: {technique_id, technique_name, basis, source_ids}
      telemetry:
        repo: <repo or tenant-specific>
        events: []
        fields: []
        license: <known requirement or unknown>
        status: documented|tenant_unverified|unavailable|unknown
      expected_positive: <specific result>
      benign_lookalikes: []
      lookback: <duration and reason>
      fidelity: high|medium|low
      scope_status: in_scope|general|excluded
      disposition: inventory|hunt|alert-candidate|gap
      validation_method: <safe positive + benign plan>
  coverage_gaps: []
```

## Classification rules

- **Inventory:** establishes presence or baseline only; no threat alert by default.
- **Hunt:** useful analyst-led correlation with context-dependent semantics.
- **Alert candidate:** discrete suspicious behavior with stable entity/result semantics and a plausible suppression strategy. This is only a candidate; Stage 4 can reject it.
- **Gap:** important behavior lacks reliable telemetry, fields, or a defensible query shape.

An IOA-shaped behavior is not automatically alert-ready. A named product, port, file extension, or direct parent match alone is usually inventory/hunt unless additional behavior raises fidelity.

## Exit gate

`ok` requires 4–8 non-duplicative hypotheses, stable IDs, claim linkage, scope and telemetry status, and at least one safe validation method per queryable hypothesis. Fewer than four defensible hypotheses is `degraded`; do not pad the count.
