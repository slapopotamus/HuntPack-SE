# HuntPack Quality Gates

## Mandatory local gates

Run the portable orchestrator from the active skill directory:

```text
python scripts/validate_huntpack.py --write-sidecar <candidate.html>
```

It runs:

1. `verify_huntpack.py` — HTML structure, safety, and content-shape checks.
2. `lint_cql_fields.py` — Falcon field/event heuristic checks.
3. `lint_cql_syntax.py` — CQL heuristic anti-pattern checks.
4. `check_ioc_provenance.py` — IOC/source-snapshot provenance checks.

These are static gates, not a Falcon parser or live detection test.

`verify_huntpack.py` is the strictest of the four and carries the content floors,
so read its failures literally rather than working around them. It enforces the
15 unique sections, the fixed left navigation and TOC toggle, the Falcon cloud
selector inside s7, all five cloud hosts, one card per CQL block with both
actions wired, the full canonical CQL header plus `data-lookback`, the published
class vocabulary, a `.qc-note` rationale on every card, all three hardening
tiers, a copyable hunt ticket, changelog entry markup, the Executive Summary
shape from Stage 6 §4a, no build-config wording anywhere reader-facing, and no
stub sections. Each script also runs standalone with `--self-test`; keep that
suite green when changing a gate rather than relaxing the check.

## Publication matrix

| Evidence | Allowed label | Publication behavior |
|---|---|---|
| Mandatory local gate fails | `STATIC REVIEW FAILED` | Do not publish or index |
| All local gates pass | `STATIC REVIEW PASSED / TENANT UNVERIFIED` | Publish as Draft |
| Intended Falcon repo accepts query | `TENANT PARSE CONFIRMED` | Record repo/time/result |
| Positive and benign tests recorded | `CANARY TESTED` | Eligible for canary scheduling |
| Approved and measured in production | `DEPLOYED` | Eligible for production wording |

## Semantic review checklist

Local scripts cannot prove these; Stage 6 must review them explicitly:

- each query detects the hypothesis rather than merely a product or port;
- wrapper processes, lineage depth, missing fields, IPv6, proxy/DNS, and platform variants were considered;
- ATT&CK describes attacker behavior, not administrative inventory;
- `CONF`, `FP`, and `COST` match real expected behavior;
- inventory and hunt queries are not promoted as alerts;
- every alert package has positive/benign tests and suppression design;
- every control has verification, rollback, blast-radius, and versioned authority;
- coverage is based on evidence state, not artifact existence.

## Required adversarial tests

The regression suite must reject: zero queries, a missing section, a stub section, a query card with no rationale, a prose-only hunt ticket, duplicate query IDs, incomplete metadata, one card missing an action button, unknown field/event without evidence, malformed delimiters, unresolved placeholders, injected HTML/JavaScript, an IOC absent from its current source snapshot, and a stale validation hash.
