# Stage 6 — Review, Assembly, Validation, and Publication

**Input:** every upstream artifact plus current-run source snapshots.  
**Output:** validated Draft HTML, validation sidecar, source directory, pack manifest, and an index row.  
**State:** `ok|failed` for publication.

Read [`../../quality-gates.md`](../../quality-gates.md) before assembling. This stage is the only publisher.

## 1. Fail-closed artifact review

Require:

- current-run source manifest with hashes;
- stable source/claim/hypothesis/query/control IDs;
- at least one CQL query and a decision for every query;
- full canonical metadata on every query;
- validation plans clearly separated from validation evidence;
- complete Stage 5 output;
- no unresolved mandatory placeholders.

Do not convert missing content into “populate later” text. A legitimate absence is specific, such as “No atomic IOCs were published by accessible primary sources as of YYYY-MM-DD.”

## 2. Semantic review

For every query verify:

- it supports its hypothesis and uses only evidenced ATT&CK mappings;
- inventory, hunt, and alert-candidate labels are honest;
- wrapper/lineage, platform, schema, IPv6/proxy/DNS, and cost limitations are visible;
- query metadata matches its operational package;
- a static-only query is not called parsed, tested, validated, deployable, or production-ready.

Coverage states are `Gap`, `Design`, `Static`, `Tenant`, `Canary`, or `Deployed`. Only `Canary` and `Deployed` render as `Good`.

## 3. Safe HTML assembly

Create one self-contained offline HTML file with inline CSS and the exact application JavaScript. Escape all source-derived text and attributes. Allow only `https://` source links and the five disclosed Falcon hosts. Reject unexpected scripts, external CSS/images, iframes, forms, event-handler attributes derived from data, and `javascript:` URLs.

The UI must provide:

- fixed left TOC plus working desktop/mobile toggle and scrollspy;
- filter/collapse controls for query categories;
- distinct CONF/FP/COST colors;
- Copy CQL with local-file fallback;
- Open in Falcon using each query block's `data-lookback`;
- per-query links to hypothesis and operationalization IDs;
- a `.qc-note` rationale on every query card (see conventions §6A);
- a visible `STATIC REVIEW PASSED / TENANT UNVERIFIED` banner unless stronger evidence exists.

Preserve canonical CQL comments byte-for-byte except HTML escaping. Do not collapse metadata into one line.

### 4a. Executive Summary shape

S1 is the only section most readers finish. Lead with the **threat**, not with this
pipeline. Aim for **1,800-2,600 characters** of visible text. Under 1,500 fails the
gate; the upper figure is editorial judgement, not a gate — past roughly 2,600 the
section stops being a summary, but no script will stop you.

Write it in this order:

1. **What happened and who reported it** - vendor and publication date, in one sentence.
2. **How the thing actually works**, technically and specifically. Name the loader, the
   transport, the encoding, the persistence, the registry key, the packet types, the
   filenames. Precision is the point: "smuggles its command channel inside ordinary DNS
   lookups, XORed with a single-byte key and chopped into 63-character chunks" beats
   "uses covert DNS-based C2" every time.
3. **Why detection has to live where it lives.** State the highest-value defensive angle
   and say what is *not* durable - rotating infrastructure, reassignable hostnames,
   filenames that change per build.
4. **Bold lead-ins** on at least two of those beats, so the section is skimmable. Use
   `<strong>` for the framing phrase, not for whole sentences.
5. A closing **`Defender priority:`** callout - one concrete instruction the reader can
   act on first, in a `.callout` element.
6. Then the summary table (Priority / Why now / Coverage delivered / Key limitation),
   **below the narrative**, as the scannable version for someone who already read it.

Never open with the generator's configuration. "General-mode draft. No TECH_STACK.md was
present" tells the reader nothing about the threat and burns the most valuable line in the
pack. Coverage limits belong in telemetry terms, in the Key limitation cell or in the
narrative's third beat - never as a statement about which mode the build ran in.


### 4b. Hunt ticket shape

S13 exists to be pasted into an ITSM tool, so it is a single copyable block, not
prose. Render `.ticket` wrapping a `<pre class="code" id="ticket-block">` plus a
`copyBlock('ticket-block', this)` button, with these labels:

```text
TITLE:        <threat> hunt — <pack version>
SEVERITY:     <critical|high|medium|low> — <one clause of justification>
SCOPE:        <platforms and telemetry the hunt assumes>
HYPOTHESIS:   <Hxx IDs and one line each>
QUERIES RUN:  <Qxx by use — inventory / hunt / alert-candidate>
DO FIRST:     <the single highest-value query and its window>
FINDINGS:     <blank for a fresh pack, or the recorded result>
GAPS:         <telemetry, schema, or validation gaps carried forward>
ACTIONS:      <next concrete step, owned>
OWNER:        <role>
VERSION:      <pack version and validation state>
```

## 4. Required sections

| ID | Section | Minimum content | Floor |
|---|---|---|---|
| s1 | Executive Summary | threat narrative first, then the summary table (see 4a) | 1,800–2,600 chars; under 1,500 fails |
| s2 | Source and Claim Review | source ledger, claim IDs, contradictions | one row per `Sxx` with tier and independence group |
| s3 | Hunt Brief and Attack Chain | attack chain, hypotheses, and an `<h4>` on affected surface and telemetry | chain table ≥4 ordered steps; every `Hxx` listed |
| s4 | Consolidated IOC Table | indicator/source IDs or explicit evidence-backed absence | one row per `Ixx`, or a specific dated absence statement |
| s5 | ATT&CK Mapping | behavior, basis, source IDs | one row per evidenced technique; inferred rows marked |
| s6 | Native / Non-CQL Hunts | a table of `Hunt \| Log source \| Logic \| Response`, naming concrete event IDs or console paths | ≥2 rows, or a stated telemetry gap explaining why not |
| s7 | CQL Hunt Queries | categorized cards, per-query lookback, per-card rationale | one card per `Qxx`; every card carries `.qc-note` |
| s8 | Operationalization and IOA Candidates | scheduled searches plus separately gated IOA candidates | one row per `Qxx` decision |
| s9 | Machine-Readable IOC Appendix | source-tagged CSV and practical copy blocks | ≥3 `.ioc-grab` blocks, or a dated absence statement |
| s10 | Hardening — Tiered and Deployable | control IDs, readiness, then the deployable playbooks | all three tiers populated or explicitly excused; each `.tier-lbl` reads `Immediate — <what it neuters>`; ≥1 playbook |
| s11 | Containment Runbook | phase, trigger, authority, owner, evidence, recovery | ≥5 phases, all six columns present |
| s12 | Detection Coverage and Validation Evidence | evidence-based state, then plans, recorded evidence, and gaps | one row per technique in s5; never artifact-only “Good” |
| s13 | Hunt Summary Ticket | paste-ready block (see 4b) | `.ticket` + `<pre>` + copy action |
| s14 | Changelog | version/date/material changes | ≥1 `.chg-entry` per shipped version; no `next`/`planned` rows |
| s15 | References | source/authority IDs, URL, version, access date, use | one row per `Sxx` and per cited authority |

A floor is a floor, not padding permission. Where the evidence genuinely does not
support the floor, write the specific dated reason in the section — “No atomic
IOCs were published by accessible primary sources as of 2026-08-24” — rather than
inventing rows. Stub bodies fail the structure gate: every section needs real
content or a real explanation of its absence.

## 5. Static gates

From the active skill directory run:

```text
python scripts/validate_huntpack.py --write-sidecar <run-candidate.html>
```

The orchestrator resolves sibling scripts and uses the active tree; never hardcode `.agents` or `.claude`. It runs structural/safety, field/event heuristic, CQL heuristic, and provenance gates. These do not contact Falcon.

After any fix, rerun the full gate set. `PROVENANCE N/A` is acceptable only when the pack truly ships no atomic IOCs and the pack says so; it is not verified provenance.

## 6. Atomic publication

1. Confirm the sidecar says `static_pass: true` and its pack SHA-256 matches.
2. Move the HTML, exact-stem source directory, and sidecar from `.runs/<run-id>/` into `packs/<YYYY-MM>/` as one release set.
3. Create the pack manifest with stage states, artifact counts, hashes, validation state, and final paths.
4. Acquire the project index lock, write a temporary index, validate its HTML/targets, and atomically replace `index.html`.
5. Release the lock.

If any step fails before the final index replace, do not add the row. Self-heal reruns current gates and verifies the sidecar/hash; file existence alone is never sufficient.

## 7. Completion report

Report counts by query use, each static gate result, provenance `OK|N/A`, tenant state, thin/gap sections, publication path, and the next concrete tenant/benign/positive validation step.
