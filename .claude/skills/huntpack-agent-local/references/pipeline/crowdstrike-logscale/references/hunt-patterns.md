# CQL Hunt Pattern Shapes

Reusable *templates* for common threat-hunting questions. Each pattern shows the **shape** of the query — the join structure, the bucket math, the aggregation — not a tenant-ready detection. Replace the placeholder fields and thresholds, validate against a real sample row, then ship.

> **Validate before deploying.** SaaS/IdP field names are parser-prefixed in many tenants (`salesforce.event_type` vs `EVENT_TYPE`). Endpoint field names are stable. When in doubt, run the query against a 1-hour window with a hard `head(10)` first to confirm shape.

Cross-references:
- Composition rules — [`best-practices.md`](best-practices.md)
- Function signatures — [`functions.md`](functions.md)
- Live-tested detections — [`detections.md`](detections.md)

---

## Pattern A — Beaconing detection (periodic C2)

**Question:** Which host/IP pairs talk to each other on a regular cadence (e.g., every 5 minutes for an hour)?

**Shape:** Bucket time → groupBy(host, dest, bucket) → re-aggregate to count how many buckets each pair appeared in → filter for pairs active in N+ buckets.

```
#event_simpleName = NetworkConnectIP4
| test(@timestamp >= now() - 86400000)                     // 24h window
| !cidr(RemoteAddressIP4, subnet="10.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="172.16.0.0/12")
| !cidr(RemoteAddressIP4, subnet="192.168.0.0/16")
| Bucket5m := @timestamp - (@timestamp % 300000)       // 5-min bucket (epoch-ms math)
| groupBy([ComputerName, RemoteAddressIP4, Bucket5m],
    function=count(as=ConnsInBucket), limit=20000)
| groupBy([ComputerName, RemoteAddressIP4],
    function=[
      count(as=BucketsActive),
      avg(ConnsInBucket, as=AvgConnsPerBucket),
      min(Bucket5m, as=FirstBucket),
      max(Bucket5m, as=LastBucket)
    ],
    limit=5000)
| BucketsActive > 12                                    // >1h of 5-min cadence
| AvgConnsPerBucket < 5                                 // exclude chatty apps
| sort(BucketsActive, order=desc)
```

**Knobs:** bucket width (300000 = 5min, 60000 = 1min), `BucketsActive` threshold (cadence × duration), `AvgConnsPerBucket` ceiling (to drop legitimate high-volume services).

**Why epoch-ms math:** `bucket(span=5m)` works in some contexts but the explicit arithmetic form is portable across LogScale builds and never breaks under `groupBy` chains. See [`best-practices.md`](best-practices.md) §Time arithmetic.

---

## Pattern B — Rare-entity hunting (low-prevalence anything)

**Question:** Which domains/binaries/processes/IPs are seen by very few hosts (likely targeted)?

**Shape:** groupBy(entity) → count distinct hosts → filter for low-host-count + multi-event (excludes one-offs).

```
#event_simpleName = DnsRequest
| test(@timestamp >= now() - 604800000)                    // 7d window
| !DomainName = /\.(microsoft|google|amazon|apple|cloudflare)\.com$/i
| groupBy(DomainName,
    function=[
      count(as=TotalQueries),
      count(aid, distinct=true, as=DistinctHosts),
      collect(ComputerName, limit=20),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ],
    limit=20000)
| DistinctHosts <= 3                                    // rare across fleet
| TotalQueries >= 5                                     // but not a single typo
| sort(DistinctHosts, order=asc)
```

**Knobs:** time window (longer = more confidence in "rare"), `DistinctHosts <=` threshold, `TotalQueries >=` floor.

**Reuse across event types:** swap the tag filter and the entity field — `DomainName` → `SHA256HashData`, `ImageFileName`, `RemoteAddressIP4`, `CONNECTED_APP_NAME`, etc.

---

## Pattern C — Frequency baseline (rare-vs-recent)

**Question:** Has a process/IP/user appeared *recently* that wasn't in the historical baseline?

**Shape:** Two groupBys joined: recent window → left-join against a prior-window baseline → filter where baseline is empty or count diverges. See [`SKILL.md`](../SKILL.md) §"Baseline-vs-recent comparison" for the z-score variant.

```
// Recent: things seen in last 24h
#event_simpleName = ProcessRollup2
| test(@timestamp >= now() - 86400000)
| groupBy([SHA256HashData, ImageFileName],
    function=[
      count(as=RecentHits),
      count(aid, distinct=true, as=RecentHosts)
    ],
    limit=10000)
| join(query={
    // Baseline: same shape over the prior 30 days, excluding the last 24h
    #event_simpleName = ProcessRollup2
    | test(@timestamp < now() - 86400000)
    | test(@timestamp >= now() - 2592000000)
    | groupBy([SHA256HashData],
        function=count(as=BaselineHits),
        limit=50000)
  }, field=SHA256HashData, include=[BaselineHits], mode=left)
| BaselineHits := if(BaselineHits != "", then=BaselineHits, else=0)
| BaselineHits = 0                                      // never seen before
| sort(RecentHits, order=desc)
```

**Knobs:** baseline-vs-recent window split, `mode=left` (keep new) vs `mode=inner` (only matching), threshold logic in the final filter.

**Why follow-on `if()`:** `default(value=0, field=BaselineHits)` is rejected in LogScale v1.237+ — see [`SKILL.md`](../SKILL.md) line 597.

---

## Pattern D — Per-host timeline reconstruction

**Question:** What happened on host X around time T? (Incident response triage.)

**Shape:** Union multiple event types via regex tag filter → label each row with a category → sort by timestamp → display.

```
@timestamp >= (?start_ms)
@timestamp <= (?end_ms)
aid = ?target_aid                                       // see best-practices.md §AID filtering
| in(#event_simpleName, values=[
    "ProcessRollup2",
    "NetworkConnectIP4",
    "DnsRequest",
    "NewExecutableWritten",
    "UserLogon",
    "ScheduledTaskRegistered"
  ])
| case {
    #event_simpleName = ProcessRollup2          | Category := "process";
    #event_simpleName = NetworkConnectIP4       | Category := "network";
    #event_simpleName = DnsRequest              | Category := "dns";
    #event_simpleName = NewExecutableWritten    | Category := "file";
    #event_simpleName = UserLogon               | Category := "auth";
    #event_simpleName = ScheduledTaskRegistered | Category := "persist";
    *                                           | Category := "other";
  }
| Detail := coalesce([CommandLine, RemoteAddressIP4, DomainName, TargetFileName, UserName])
| table([@timestamp, Category, ComputerName, Detail])
| sort(@timestamp, order=asc, limit=10000)
```

**Knobs:** event list (add/remove tags by what's relevant to the incident), `Detail` field list (coalesce more fields if some are blank), time window from your IR scoping.

**Why `in()` not regex alternation:** `#event_simpleName` is indexed; `in()` hits the index, regex doesn't. See [`best-practices.md`](best-practices.md) §8.

---

## Pattern E — Parent-child anomaly (Office spawning shells, services spawning cmd, etc.)

**Question:** Did a process that *shouldn't* spawn shells/scripts/network tools do so?

**Shape:** Tag on `ProcessRollup2` → filter ParentBaseFileName to the suspicious-parent set → filter ImageFileName to the suspicious-child set → display.

```
#event_simpleName = ProcessRollup2
| in(ParentBaseFileName, values=[
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe",
    "acrord32.exe","acrobat.exe"
  ], ignoreCase=true)
| in(FileName, values=[
    "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
    "mshta.exe","certutil.exe","bitsadmin.exe","rundll32.exe","regsvr32.exe"
  ], ignoreCase=true)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=500)
```

**Variants:** swap parent-set / child-set to express other invariants — `services.exe` spawning `cmd.exe` (legitimate but worth surfacing); `WmiPrvSE.exe` spawning anything not in the standard-WMI-children list; `lsass.exe` spawning anything at all.

---

## Pattern F — External-only network filter (kill the private-CIDR noise)

**Question:** Which connections actually left the perimeter?

**Shape:** Drop RFC1918 + loopback before anything else, then aggregate.

```
#event_simpleName = NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet="10.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="172.16.0.0/12")
| !cidr(RemoteAddressIP4, subnet="192.168.0.0/16")
| !cidr(RemoteAddressIP4, subnet="127.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="169.254.0.0/16")     // link-local
| ...                                                   // your hunt logic here
```

**Why all five subnets:** RFC1918 + loopback + link-local + (if applicable) your own corporate-internet egress range. Each `!cidr` call must be a top-level pipeline filter — see [`SKILL.md`](../SKILL.md) line 530 (function calls in OR groups are illegal).

**For IPv6:** add `!cidr(RemoteAddressIP6, subnet="fc00::/7")` (ULA) and `!cidr(RemoteAddressIP6, subnet="fe80::/10")` (link-local).

---

## Pattern G — High-volume egress

**Question:** Which hosts pushed unusually large amounts of data out?

**Shape:** External-only filter → groupBy(host, dest) summing BytesOut → filter for high-volume pairs.

```
#event_simpleName = NetworkConnectIP4
| test(@timestamp >= now() - 86400000)
| !cidr(RemoteAddressIP4, subnet="10.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="172.16.0.0/12")
| !cidr(RemoteAddressIP4, subnet="192.168.0.0/16")
| BytesOut > 0
| groupBy([ComputerName, RemoteAddressIP4],
    function=[
      sum(BytesOut, as=TotalOut),
      count(as=Conns),
      selectFromMax(field=@timestamp, include=[ContextBaseFileName])
    ],
    limit=5000)
| TotalOut > 104857600                                  // 100 MB
| sort(TotalOut, order=desc)
```

**Knobs:** `TotalOut >` threshold (start high, lower until signal-to-noise breaks), time window.

---

## Pattern H — Lookup-file enrichment

**Question:** Are any of my recent events touching a known-bad indicator?

**Shape:** Hunt query → `match(file=...)` against an uploaded watchlist → keep only hits (`strict=true`) or enrich and keep all (`strict=false` + `include=[...]`).

```
// Strict: drop everything that doesn't match the watchlist
#event_simpleName = NetworkConnectIP4
| match(file="ti_known_bad_ips.csv",
        field=RemoteAddressIP4,
        column=indicator,
        strict=true)
| table([@timestamp, ComputerName, RemoteAddressIP4, ContextBaseFileName])

// Enriching: keep everything, attach intel where it exists
#event_simpleName = NetworkConnectIP4
| match(file="ti_known_bad_ips.csv",
        field=RemoteAddressIP4,
        column=indicator,
        include=[source, confidence, first_seen],
        strict=false)
| ThreatHit := if(source != "", then="yes", else="no")
```

**Operational note:** lookup files are uploaded in **Falcon → NG-SIEM → Lookup files**. Each file is per-search-head; if you have multi-region tenants, upload separately.

---

## Pattern templates — when to use which

| Hunt question | Pattern | Pivot to |
|---|---|---|
| "Is anything beaconing?" | A | D for the host that fired |
| "Is anything new in the fleet?" | B or C | A or G to characterize |
| "What did this host do during the incident?" | D | E, F, G as appropriate |
| "Did Office spawn a shell?" | E | D on the affected host |
| "Did anything talk to the internet weirdly?" | F + (A or G) | E for the parent |
| "Did we touch known-bad IOCs?" | H | D on the affected host |
