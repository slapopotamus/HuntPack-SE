# CQL Pipeline Discipline & Best Practices

How to *compose* a CQL query so it runs fast, returns the right result set, and is readable when someone re-opens it in three months. Lessons distilled from the LogScale community (notably `straw-hat-kjones/cql-best-practices`) and from live-fire hunt-pack work in a production NG-SIEM tenant.

The function reference (`functions.md`), the syntax rules (`SKILL.md` §Core Syntax), and the anti-patterns sections (`SKILL.md` lines 526–672, `functions.md` lines 185–211) tell you what each piece *does*. This file tells you how to **arrange them**.

---

## 1. Canonical pipeline order

Every well-formed CQL query follows the same nine-step sequence. Build queries by going down this list — never skip ahead and never re-order.

```
1. Tag filters (# prefix)     // indexed, ~free
2. Timeframe restriction      // explicit query-time guard when needed
3. Field filters (exact)      // exact before wildcard
4. Cardinality assessment     // peek before aggregating
5. Negative filters (!=, !in) // subtract known-benign
6. Regex                      // only on unparsed/freeform fields
7. Data transformation        // :=, math, parsing, per-row work
8. Aggregation                // groupBy, stats, top
9. Post-processing            // sort, table, limit, display
```

**Why the order matters.** Stages 1–3 are cheap and reduce the row count. Stages 6–9 are expensive *per row*. Putting an expensive operation before a cheap one multiplies cost by the un-filtered row count. The whole game is to push every row reduction as far left as possible.

A worked example, with annotations:

```
// Hunt: suspicious PowerShell encoded commands, last 24h
#event_simpleName = ProcessRollup2                  // 1. tag filter (indexed)
| test(@timestamp >= now() - 86400000)              // 2. timeframe
| ImageFileName = /\\powershell\.exe$/i       // 3. field filter (exact-ish)
| ParentBaseFileName != "explorer.exe"        // 5. negative — drop interactive launches
| CommandLine = /-e[nc]?\s|FromBase64/i       // 6. regex — only after volume is small
| DecodedLen := length(CommandLine)           // 7. transform
| DecodedLen > 200
| groupBy([ComputerName, UserName],           // 8. aggregate
    function=[count(as=Hits),
              selectFromMax(field=@timestamp,
                            include=[CommandLine])],
    limit=500)
| sort(Hits, order=desc, limit=100)           // 9. post-process
```

---

## 2. Cardinality management

Cardinality kills queries more reliably than bad regex. Every aggregation has the potential to explode the result set; cap it explicitly.

### Always set `limit=` on `groupBy` and `top`
LogScale will silently truncate at internal `StateRowLimit` if you don't. Make the cap visible in the query so future-you knows what was intentional.

```
// BAD — unbounded groupBy on a high-cardinality field
| groupBy(RemoteAddressIP4, function=count())

// GOOD — explicit cap, sorted, then narrowed
| groupBy(RemoteAddressIP4, function=count(as=Hits), limit=500)
| sort(Hits, order=desc)
| head(20)
```

### Sample during development
For long time-windows or noisy repos, prototype against a fraction of events:

```
| sample(percentage=10)    // 10% sample — verify shape before full run
```

Drop the `sample()` line before shipping. Don't ship sampled queries.

### `tail(200)` is the hidden default
Without an aggregation, LogScale auto-applies `tail(200)` so the UI doesn't crash. If you need more raw events, ask for them explicitly:

```
| tail(max)        // or tail(10000) etc. — caps at StateRowLimit
```

### Work vs. wall-clock
LogScale reports a **Work** metric per query (visible in the query inspector / Work tab). Wall-clock time depends on cluster load; Work is the actual compute cost and is the right metric for comparing two versions of the same hunt. Reduce Work, not seconds.

### Cardinality peek before committing
If you're about to `groupBy` a field you don't know the spread of, peek first:

```
// Step 1 — peek the cardinality
| #event_simpleName = ProcessRollup2 | ImageFileName = /powershell/i
| count(CommandLine, distinct=true, as=DistinctCmdLines)

// Step 2 — only then commit to aggregating
| groupBy(CommandLine, function=count(), limit=...)
```

---

## 3. Filter early, format late — the three most expensive mistakes

### 3a. `groupBy` before filter

```
// BAD — aggregates everything, then narrows
#event_simpleName = ProcessRollup2
| groupBy(CommandLine, function=count())
| CommandLine = /powershell/i

// GOOD — narrow first, then aggregate the small set
#event_simpleName = ProcessRollup2
| CommandLine = /powershell/i
| groupBy(CommandLine, function=count(as=Hits), limit=500)
```

### 3b. `format()` / `table()` / per-row work before filter

Formatting runs *per row*. Format 10 million events and you'll burn through Work budget before the first chart loads.

```
// BAD — every event gets formatted, even the ones you throw away
#event_simpleName = ProcessRollup2
| When := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
| Path := concat([ImageFileName, " ", CommandLine])
| ImageFileName = /\\malware\.exe$/

// GOOD — filter to the few rows that matter, then format them
#event_simpleName = ProcessRollup2
| ImageFileName = /\\malware\.exe$/
| When := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
| Path := concat([ImageFileName, " ", CommandLine])
```

### 3c. Unlimited `groupBy` on high-cardinality fields

`RemoteAddressIP4`, `CommandLine`, `URI`, `@timestamp` (without a bucket), `SHA256HashData` — all of these will produce millions of groups in a busy tenant. Always cap:

```
// BAD
| groupBy(SHA256HashData, function=count())

// GOOD
| groupBy(SHA256HashData, function=count(as=Hits), limit=1000)
| sort(Hits, order=desc)
```

---

## 4. Field type hierarchy (cost model)

Knowing which fields are cheap vs. expensive to filter on is the difference between a 2-second query and a 2-minute one.

| Type | Syntax | Indexed? | Cost | When to use |
|---|---|---|---|---|
| **Tag fields** | `#event_simpleName`, `#repo`, `#parser` | Yes | Lowest | **Always filter first**, before anything else |
| **Metadata fields** | `@timestamp`, `@id`, `@ingesttimestamp`, `@host` | Yes | Very low | Timeframe, dedup, host scoping |
| **User fields (exact)** | `UserName = "alice"`, `Port = 443` | Partial | Low | Once tag-narrowed, prefer exact match |
| **User fields (wildcard)** | `CommandLine = *mimikatz*` | No | Medium | Use after a tag filter has reduced volume |
| **User fields (regex)** | `CommandLine = /regex/i` | No | Medium | Same — only after volume is small |
| **Assigned fields** | `X := expr` then `X = "y"` | No | Free at filter time, but compounds | Computed values, joins keys |
| **Free-text** | `"mimikatz"`, `/pattern/` | No | Highest — scans every field | Exploration only, never in shipped queries |

The single most important rule: **`#`-prefixed tag filters always go first.** They are the only thing LogScale's indexer can use to skip whole segments of the dataset.

---

## 5. AID filtering — the IR / triage perf lever

When you're hunting on one host (incident response, post-detection triage), filter by Agent ID (`aid`) as your second filter after `#event_simpleName`. It cuts cardinality by orders of magnitude.

```
#event_simpleName = ProcessRollup2
| aid = "abc123def456..."        // one host only
| ... rest of the hunt
```

Pattern: use this when you have a target host. Don't use it for fleet-wide hunts — that's what tag filters and time windows are for.

---

## 6. Parameterized queries — make detections reusable

LogScale's `?paramname` syntax prompts the user (or scheduled-search runtime) for a value. Use it any time you'd otherwise copy-paste a detection with one value changed.

```
// Stored detection: PowerShell hunts on a single host, configurable lookback
#event_simpleName = ProcessRollup2
| test(@timestamp >= now() - ?lookback_ms)
| aid = ?aid
| ImageFileName = /\\powershell\.exe$/i
| CommandLine = /?suspect_pattern/i
| table([@timestamp, ComputerName, UserName, CommandLine])
| sort(@timestamp, order=desc)
```

Three rules:
1. Name parameters by what they *are*, not what they're *for* (`?lookback_ms`, not `?p1`).
2. Document defaults in a `// ?lookback_ms default: 86400000 (24h)` comment above the query.
3. Don't parameterize tag filters — they should be hard-coded so the query plan is stable.

---

## 7. Readability conventions

A query that works once is worth less than a query someone else can read in six months.

### One operation per line, break on `|`

```
// BAD — runs fine, unreadable
#event_simpleName=ProcessRollup2 | ImageFileName=/powershell/i | CommandLine=/-enc/i | groupBy(ComputerName, function=count(as=Hits)) | sort(Hits, order=desc)

// GOOD — same query, scannable
#event_simpleName = ProcessRollup2
| ImageFileName = /powershell/i
| CommandLine = /-enc/i
| groupBy(ComputerName, function=count(as=Hits))
| sort(Hits, order=desc)
```

In the LogScale UI, `Shift+Enter` inserts a real newline (Enter alone submits the query).

### Comments are mandatory on shipped queries

```
// MITRE T1059.001 — Encoded PowerShell
// Triage:
//   1. Confirm CommandLine actually decodes to something suspicious (base64 → script)
//   2. Check parent process (legit launcher vs. browser/Office)
//   3. Pivot to NetworkConnect for the same falconPID

#event_simpleName = ProcessRollup2
| ImageFileName = /\\powershell\.exe$/i
| CommandLine = /(-enc|-encodedcommand|-e\s+[A-Za-z0-9+\/=]{20,})/i   // base64-ish args
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc)
```

Inline `//` comments at the end of a filter line are the highest-ROI place to leave context (*why* this filter is here, not what it does syntactically).

### Block comments for multi-line context

```
/*
  Hunt: T1078.004 — Cloud account abuse via Salesforce Connected App
  Owner: hunt-pack/unc6395
  Caveat: SaaS field names may be parser-prefixed in some tenants
          (e.g. salesforce.event_type vs EVENT_TYPE).
          Validate one row before fleet-deploying.
*/
```

---

## 8. The `in()` performance idiom

For indexed fields with a small set of allowed values, `in()` is materially faster than regex alternation. Always prefer it when the field is one of: `#event_simpleName`, `EVENT_TYPE`, `ENTITY_NAME`, `METHOD_NAME`, `eventType`, `Operation`, `eventCategory`.

```
// SLOW (regex over indexed field, scans literal patterns)
| #event_simpleName = /^(ProcessRollup2|NetworkConnectIP4|DnsRequest)$/

// FAST
| in(#event_simpleName, values=["ProcessRollup2", "NetworkConnectIP4", "DnsRequest"])
```

**Caveat — context matters.** `in()` is only valid as a **top-level pipeline filter** (`| in(...)`), not inside an `OR` group, `case` condition, or `if()` predicate. See SKILL.md "Function calls are not supported in filter expressions" (line 530) for the substitution playbook when you need an OR.

---

## 9. Anti-pattern quick reference

A condensed scorecard. Each row links back to the full BAD/GOOD treatment in `SKILL.md` or `functions.md`.

| Anti-pattern | One-line fix | Full treatment |
|---|---|---|
| `groupBy` before filter | Move filter above groupBy | §3a above |
| Format before filter | Move transformation below filter | §3b above |
| Unbounded `groupBy` | Add `limit=N`, sort, head | §3c above |
| Free-text / `/regex/` first | Add tag filter, then field filter, then regex | §1 + §4 |
| `in()` inside `OR` group | Rewrite as `field = /^(a\|b)$/` | SKILL.md L530 |
| `collect(X, as=Y)` | `collect(X)` + `rename(field=X, as=Y)` | SKILL.md L586 |
| `default(value=X, field=Y)` | `Y := if(Y != "", then=Y, else=X)` | SKILL.md L597 |
| `Y := if(..., as=Y)` | Drop one — `:=` and `as=` are both assignment | SKILL.md L607 |
| `(f1 OR f2) = /re/` | `X := coalesce([f1,f2])` then `X = /re/` | SKILL.md L620 |
| `coalesce([f1,f2], 0)` | `coalesce()` is list-only; chain `if()` for default | SKILL.md L631 |
| `eventStats(series=)` / `bucket(series=)` | Use `groupBy + join` or arithmetic bucket | SKILL.md L642 |
| `regex(format(...), field=Y)` | Lookup file + `match(file=...)` | SKILL.md L660 |
| `now() - 7d` literal | Epoch ms: `now() - 604800000` | SKILL.md L673 |
| Uppercase `OR` / `AND` | Lowercase | SKILL.md L655 |
| `stddev`, `formattime` | `stdDev`, `formatTime` (case-sensitive) | SKILL.md L656 |
| Hyphen at end of char class | Move to start: `[-A-Za-z]` | SKILL.md L658 |

---

## 10. Detection engineering workflow

How to go from "I read about an attack" to "a shipped, tuned detection." Each step is a checkpoint; don't skip ahead.

### Step 1 — Start narrow
Pick one tag filter (`#event_simpleName`) and one obvious field condition (the most specific thing in your threat-intel). Add a 1-hour window and `head(100)`. Run it. You're confirming the data is there at all.

### Step 2 — Expand selectivity, not scope
If step 1 returned hits, *don't* widen the time window yet. Instead, add the next-most-specific filter (parent process, user, command-line keyword) and check that the result count drops. If it doesn't drop, your filter isn't selective — pick a different one.

### Step 3 — Validate field names
Especially for SaaS/IdP data: `EVENT_TYPE` vs `salesforce.event_type` vs `event.type` — these all exist in the wild depending on the parser. Run `| groupBy(YourField)` against a known-good row to confirm the field is populated before relying on it in a hunt. Endpoint fields are stable; SaaS fields are not.

### Step 4 — Stretch the window, watch cardinality
Now expand to your real time window (24h, 7d, 30d). Watch the Work metric. If it grows faster than linearly with the window, you have an un-tag-filtered stage somewhere — go back and check §1.

### Step 5 — Confidence variants
A single hunt usually produces three useful detections at different confidence levels:

- **High-confidence (alert):** strict filters, narrow scope, low false-positive rate. Pages someone.
- **Medium-confidence (review):** looser filters, broader scope. Lands in a daily review queue.
- **Low-confidence (hunt):** the broadest version, used for proactive hunting and baselining.

Build all three from the same base query by gating with parameters or by saving three versions. Document the false-positive sources in a comment block above each.

### Step 6 — Document
Above the query, in a block comment, capture:
- The hunt question in one sentence
- MITRE technique (if applicable)
- Known false positives (named software, known users, environments)
- Pivot queries: what to run next if a row fires
- Owner (you) + date

See `references/hunt-patterns.md` for reusable pattern shapes that often serve as the starting point for steps 1–2.

---

## 11. Query review checklist

Before shipping any hunt, scheduled search, or dashboard panel:

- [ ] Tag filter (`#`) is the first or second line
- [ ] Time window is explicit (epoch-ms form, not `7d` literal)
- [ ] Every `groupBy` / `top` has an explicit `limit=`
- [ ] No `format()`, `concat()`, `parseJson()`, or other per-row work above a filter
- [ ] No `in()` / `cidr()` / `isempty()` inside an `OR` group or `case`/`if` condition
- [ ] No `collect(X, as=Y)` — use follow-on `rename()`
- [ ] No `default(value=, field=)` — use `if()`
- [ ] No `:=` combined with `as=` on the same expression
- [ ] Has a header comment naming the hunt, owner, and (if MITRE-mapped) ATT&CK ID
- [ ] Multi-line — broken on `|`, not collapsed onto one line
- [ ] If parameterized, defaults documented in a comment
