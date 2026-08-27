# Stage 5 — Hardening, Playbooks, and Containment

**Input:** ResearchBrief, HuntScaffold, QuerySet, and OperationalizationSet.  
**Output:** `DefensePlan` for pack sections 10–11 (tiered hardening plus playbooks, then containment).  
**State:** `ok|degraded|failed`.

This is a complete pipeline contract. Do not switch to standalone-document modes, invoke another skill, ask which format the user wants, or stop mid-workflow.

## Select controls

Use the threat's evidenced behavior and active scope. Prefer 2–4 high-leverage controls per major behavior over long generic lists.

All three tiers ship. Each of `immediate`, `near-term`, and `strategic` carries at
least one control, or one explicit line naming why no safe control exists at that
tier for this threat. An empty tier with no explanation reads as an oversight and
fails the structure gate. Render each tier as a `.tier-blk` whose `.tier-lbl` names the tier *and* what it
buys — `Immediate — neuter the loader`, not a bare `Immediate`; the label is a
9.5px eyebrow and carries no information without the descriptor. Then
and each control as an `<li>` that opens with a `<strong>` lead-in and carries its
MITRE mitigation ID inline — `<strong>Constrain script hosts</strong> for standard
users (M1038)` — so the tier is scannable without reading every clause.

Authority order:

1. affected vendor advisory/fixed version for product-specific vulnerabilities;
2. current vendor security baseline or hardening guide;
3. versioned CIS/DISA/NIST/CISA guidance applicable to the platform;
4. MITRE mitigation for rationale, not as the sole implementation detail;
5. clearly labelled best practice when no stronger authority exists.

Record the exact benchmark/advisory edition and access date. Never cite a control number without its version and applicability.

## Control schema

```yaml
- control_id: CTRL01
  supports: [C01, H01]
  platform: <surface>
  tier: immediate|near-term|strategic
  title: <control>
  authority:
    source_id_or_url: <authority>
    document_version: <edition/date>
    control_id: <if applicable>
    basis: formal|vendor|best-practice
  applicability: <when it applies>
  prerequisites: []
  exact_change: <setting/command/configuration>
  pilot_scope: <small safe cohort>
  blast_radius: low|medium|high
  compatibility_risks: []
  service_continuity_stop_conditions: []
  verification:
    method: <read-only check>
    expected_result: <specific result>
    evidence_to_retain: <artifact>
  rollback: <exact reversal>
  owner: <role>
  approval: not-required|peer-review|change-control|executive
  readiness: advisory|deployable-design|canary-tested|deployed
```

A control lacking exact change, verification, expected result, rollback, or a defensible authority is `advisory` and must not appear as a deployable playbook.

## Playbooks

For deployable-design controls, provide ordered steps:

1. prerequisites and backups;
2. pre-change read-only state capture;
3. pilot change;
4. verification with expected result;
5. service/application health check;
6. expansion criteria;
7. rollback and rollback verification;
8. evidence and owner.

Commands are illustrative until tested on the named platform/version. Do not claim idempotence, dry-run safety, or fleet readiness without evidence.

## Containment runbook

Include:

- activation triggers and decision authority;
- preservation order: alert/query results, raw events, process tree, files/hashes, network/DNS, identity/session state, relevant configs, prompts/tool logs when applicable;
- isolation/credential/token/service actions with exceptions and business-continuity checks;
- owner and evidence for every phase;
- a runbook table with exactly these columns: Phase, Trigger, Authority, Owner, Evidence, Recovery;
- recovery prerequisites and rollback;
- closure gates and re-hunt timing.

Containment is threat-specific. Do not automatically rotate certificates, disable identity services, isolate infrastructure, or restart critical services without a decision gate and continuity plan.

## Exit gate

Stage 5 is `ok` only when every major evidenced behavior has a control or an explicit no-safe-control gap, at least one verifiable control exists, and containment has triggers, authority, owners, evidence, recovery, and closure. Missing rollback or versioned citations makes the stage `degraded`, not silently complete.
