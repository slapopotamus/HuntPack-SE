# CQL Function Reference

Complete reference of CrowdStrike Query Language functions organized by category.

> **v3 correctness note.** Tables below are the *verified* signatures. Spellings that look right but break in
> LogScale are collected in **"Common errors & anti-patterns"** at the bottom — read that section first if a
> query won't parse. The biggest repeat offenders are malformed `format()` arguments, `collect(as=)`, and
> function calls (`in()`/`cidr()`/`regex()`) that are combined inside unsupported Boolean filter groups. `eval()`,
> `setField()`, `default()`, quoted wildcard patterns, and uppercase Boolean operators are valid documented CQL;
> prefer `:=` where it is clearer, but do not rewrite valid syntax merely to satisfy style.

## Aggregate Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `avg()` | `avg(field, as=name)` | Calculate average |
| `count()` | `count(field, distinct=true)` | Count events/values |
| `collect()` | `collect(field, limit=100, separator=",")` — **does NOT accept `as=`**; rename via follow-on `rename()` | Collect values into list |
| `max()` | `max(field, as=name)` | Maximum value |
| `min()` | `min(field, as=name)` | Minimum value |
| `percentile()` | `percentile(field, percentiles=[50,95,99])` | Calculate percentiles |
| `range()` | `range(field)` | Difference between max and min |
| `stdDev()` | `stdDev(field)` — **case-sensitive** (not `stddev`) | Standard deviation |
| `sum()` | `sum(field, as=name)` | Sum values |
| `variance()` | `variance(field)` | Statistical variance |
| `selectFromMin()` | `selectFromMin(field=@timestamp, include=[f1, f2])` | Fields from the row with the lowest `field` per group |
| `selectFromMax()` | `selectFromMax(field=@timestamp, include=[f1, f2])` | Fields from the row with the highest `field` per group (most-recent representative row) |
| `selectLast()` | `selectLast([f1, f2])` | Last value(s) seen per group |

## Grouping Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `bucket()` | `bucket(field=@timestamp, span=1h, function=...)` — for portable buckets under `groupBy`, prefer arithmetic: `B := @timestamp - (@timestamp % 3600000)` | Create time buckets |
| `groupBy()` | `groupBy([fields], function=[funcs], limit=N)` — **always set `limit=`** | Group and aggregate |
| `timeChart()` | `timeChart(series=field, span=5m, function=count())` — `series=` may also be given positionally (`timeChart(field, …)`); both work | Time-series aggregation |
| `top()` | `top(field, limit=10)` | Top N values by count |
| `window()` | `window(function, span=3)` | Sliding window calculation |

## String Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `concat()` | `concat([f1, f2], as=result)` | Join field values |
| `format()` | `format("%s: %d", field=[f1, f2], as=result)` — fields go in `field=` (a single field or `[...]` array); the format string may be positional or `format=`. **Invalid:** passing data fields positionally (`format("%s", a, b)`). | Format string |
| `length()` | `length(field, as=len)` | String length |
| `lower()` | `lower(field, as=name)` | Lowercase |
| `upper()` | `upper(field, as=name)` | Uppercase |
| `replace()` | `replace("regexString", with="new", field=f, as=out)` — regex is the **first positional string** arg | Find and replace |
| `splitString()` | `splitString(field, by=":", index=0, as=part)` | Split a string; `index=` picks one segment |
| `strip()` | `strip(field)` | Remove whitespace |
| `substring()` | `substring(field, start=0, end=10)` | Extract substring |

> `split(field)` is **not** a string splitter — it explodes an array-valued field into multiple events. To cut a
> string, use `splitString()`.

## Filtering Functions

> **Filter-context rule:** `and`/`or` do not combine with function calls. `in()`, `cidr()`, `regex()`, `test()`
> work as a **top-level stage** (`| in(...)`) or as a *single* `case`/`match` branch condition — but not inside an
> `and`/`or` boolean group (`FunctionCallsNotSupportedInFilterExpressions`). Split into `|` stages. See below.

| Function | Syntax | Description |
|----------|--------|-------------|
| `cidr()` | `cidr(field, subnet="10.0.0.0/8")`; multiple ranges in one call: `!cidr(field, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])` | IP in CIDR range — use for IP ranges, never quoted wildcards |
| `head()` | `head(n)` | First n events |
| `in()` | `in(field, values=[v1, v2])` / `!in(...)` | Match any value |
| `regex()` | `regex("pattern", field=f)` | Regex extraction (pattern is compile-time, not runtime) |
| `sample()` | `sample(percentage=10)` | Sample events |
| `tail()` | `tail(n)` | Last n events |
| `test()` | `test(condition)` | Boolean filter on an expression |

## Data Manipulation

| Function | Syntax | Description |
|----------|--------|-------------|
| `default()` | `default(value=Y, field=X, replaceEmpty=true)`; `X := if(X != "", then=X, else=Y)` is an explicit alternative. | Set a default value |
| `drop()` | `drop([f1, f2])` | Remove fields |
| `dropEvent()` | `dropEvent()` | Remove event |
| `rename()` | `rename(field=old, as=new)` — multi: `rename([[old1,new1],[old2,new2]])` | Rename field |
| `select()` | `select([f1, f2])` | Keep only fields |
| `table()` | `table([f1, f2])` | Display as table |
| `coalesce()` | `coalesce([f1, f2])` — **list only, no default-value arg**; chain `if()` for a default | First non-null |

> **Assignment is `:=`, conditional is `if()`.** CORRECTED 2026-07-24: CQL **does** have `eval()` and `setField()` — both documented, and `:=` is shorthand *for* eval. Prefer `:=` for readability, but neither is an error. Inside `eval()` only `== != + - * / %` and parens are allowed (no function calls), and bare identifiers are field names, so quote string literals.
> Write `NewField := expression` or `if(cond, then=A, else=B, as=NewField)`.

## Time Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `formatTime()` | `formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, as=out)` | Format/extract from timestamp |
| `now()` | `now()` | Current time (epoch ms) |
| `parseTimestamp()` | `parseTimestamp("format", field=f)` | Parse time string |
| `start()` / `end()` | `start()` / `end()` | Query window start / end |

> **Hour / day-of-week extraction:** use `formatTime("%H", field=@timestamp, as=Hour)` (zero-padded string) and
> `formatTime("%u", field=@timestamp, as=DoW)`. The namespaced `time:hour()` / `time:dayOfWeek()` forms are not
> reliable across builds — verify in your tenant before relying on them, or just use `formatTime()`.
> For time math use **epoch milliseconds**: `test(@timestamp >= now() - 604800000)` (7d). `now() - 7d` literals are
> not accepted in all contexts.

## Parsing Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `base64Decode()` | `base64Decode(field, as=out)` | Decode base64 |
| `base64Encode()` | `base64Encode(field)` | Encode base64 |
| `kvParse()` | `kvParse()` | Parse key=value |
| `parseCEF()` | `parseCEF(field)` | Parse CEF format |
| `parseCsv()` | `parseCsv(field, columns=[...])` | Parse CSV |
| `parseJson()` | `parseJson(field)` | Parse JSON |
| `parseLEEF()` | `parseLEEF(field)` | Parse LEEF format |
| `parseUrl()` | `parseUrl(field)` | Parse URL components |
| `parseXml()` | `parseXml(field)` | Parse XML |
| `parseInt()` | `parseInt(field, as=out, radix=16)` | Parse integer (e.g. hex RID) |

## Hash Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `crypto:md5()` | `crypto:md5(field, as=hash)` | MD5 hash |
| `crypto:sha1()` | `crypto:sha1(field)` | SHA1 hash |
| `crypto:sha256()` | `crypto:sha256(field)` | SHA256 hash |
| `hashMatch()` | `hashMatch(field, hash="...")` | Match hash value |

## Network Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `asn()` | `asn(ip, as=asn_info)` | Get ASN info |
| `communityId()` | `communityId(...)` | Calculate Community ID |
| `ipLocation()` | `ipLocation(field)` | GeoIP lookup |
| `rdns()` | `rdns(ip)` | Reverse DNS |

## Math Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `math:abs()` | `math:abs(field)` | Absolute value |
| `math:ceil()` | `math:ceil(field)` | Round up |
| `math:floor()` | `math:floor(field)` | Round down |
| `math:log()` | `math:log(field)` | Natural log |
| `math:log10()` | `math:log10(field)` | Log base 10 |
| `math:pow()` | `math:pow(base, exp)` | Power |
| `math:sqrt()` | `math:sqrt(field)` | Square root |
| `round()` | `round(field, decimals=2)` | Round |

## Array Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `array:append()` | `array:append(arr[], value)` | Add to array |
| `array:contains()` | `array:contains(arr[], value="x")` | Check membership |
| `array:filter()` | `array:filter(arr[], var=x, function={test(x > 10)})` | Filter array |
| `array:length()` | `array:length(arr[])` | Array size |
| `array:sort()` | `array:sort(arr[], order=asc)` | Sort array |
| `concatArray()` | `concatArray(arr[], sep=",")` | Join to string |

## Security Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `ioc:lookup()` | `ioc:lookup(type="ip", field=ip)` | IOC matching |
| `shannonEntropy()` | `shannonEntropy(field, as=entropy)` | Calculate entropy |

## Join / Lookup Functions

| Function | Syntax | Description |
|----------|--------|-------------|
| `join()` | `join(query={subquery}, field=f, key=k, include=[...], mode=left)` — use `query=` and `mode=` explicitly | Cross-query join |
| `defineTable()` | `defineTable(query={…}, name="t", include=[cols])` then `\| match(table="t", field=f, column=c)` — **preferred over `join()`** for complex / multi-cluster joins | Define an in-query lookup table |
| `match()` | `match(file="lookup.csv", field=f, column=c, strict=true)` (CSV) **or** `match(table="t", field=f, column=c)` (a `defineTable`) | Lookup-file / table match |
| `readFile()` | `readFile("file.csv")` | Read lookup file |
| `selfJoin()` | `selfJoin(field=[f], where=[{...},{...}])` | Self join |
| `selfJoinFilter()` | `selfJoinFilter(field=[f], where=[{...},{...}])` | Filtered self join |

## Conditional

| Construct | Syntax | Notes |
|-----------|--------|-------|
| `if()` | `if(condition, then=A, else=B, as=field)` | **Do NOT** combine LHS `:=` with `as=` (DuplicatedFunctionArgument). Pick one. |
| `case` | `case { cond \| field := value; * \| field := default; }` | Multi-branch; each branch is `condition \| assignment;`, default `* \| …`. A single filtering function (`in(values=[…])`) is OK as a condition, but you can't combine it with `and`/`or` there. |
| `match` (switch) | `FIELD match { value => assign; /regex/ => assign; * => assign }` — field **before** the keyword, `=>` arrows, `;` separators, `*` default | **Valid** (confirmed in LogScale docs); a branch may be a value, `/regex/`, or `in(values=[…])`. Faster than `case` when the field is known to exist. The old `match(field){…}` parenthesized form is wrong. `match(file=...)` is the unrelated lookup function. |

## Widget Functions (Visualization)

| Function | Syntax | Description |
|----------|--------|-------------|
| `sankey()` | `sankey(source=, target=, weight=)` | Sankey diagram |
| `worldMap()` | `worldMap(lat=, lon=)` | Map visualization |

---

# Common errors & anti-patterns (live-tested against LogScale v1.237+)

## Functions / syntax that look valid but aren't

| Anti-pattern | Why it fails | Use instead |
|--------------|--------------|-------------|
| `eval(X = expr)` | Valid CQL, but `:=` is usually clearer for one assignment | `X := expr` when readability improves |
| `setField(X, value)` | Valid CQL; use its documented signature | `X := value` is a concise alternative |
| `format("%s", a, b)` | data **fields** passed positionally | `format("%s", field=[a, b], as=out)` (format string may stay positional; fields must be `field=`) |
| `split(field, by=",")` | `split()` explodes arrays, not strings | `splitString(field, by=",")` |
| `collect(X, as=Y)` | `collect()` rejects `as=` | `collect(X)` then `rename(field=X, as=Y)` |
| `default(value=0, field=X)` | Valid documented CQL | `X := if(X != "", then=X, else=0)` is an explicit alternative |
| `X := if(..., as=X)` | `:=` and `as=` both assign | drop one |
| `(f1 OR f2) = /regex/` | `OR` invalid on LHS of `=` | `X := coalesce([f1, f2])` then `X = /regex/` |
| `coalesce([f1, f2], 0)` | takes a list only | `X := coalesce([f1, f2])` then `X := if(X != "", then=X, else=0)` |
| `in(field=X, ...)` inside an `OR`/`case`/`if` | function calls illegal in filter expressions | top-level `\| in(...)`, or `X = /^(a\|b\|c)$/` |
| `cidr(...)` inside an `OR` group | same | top-level `\| !cidr(...)`, or pre-tag via `case` then filter derived field |
| `RemoteAddressIP4 = "10.*"` | CORRECTED 2026-07-24: this is VALID — quoting does not disable the wildcard. For IP *ranges* prefer `cidr()`, but as a quality choice, not a syntax fix. |
| `EVENT_TYPE = /^(A\|B\|C)$/` on indexed field | slow regex alternation | `in(EVENT_TYPE, values=["A","B","C"])` |
| `eventStats(... series=[])` | not a CQL function | `groupBy` + `join` against a baseline subquery |
| `bucket(... series=[])` | `series=` isn't a `bucket()` arg | arithmetic bucket: `B := @timestamp - (@timestamp % 300000)` then `groupBy([B, ...])` |
| `countDistinct(field)` | not a function | `count(field, distinct=true)` |
| `now() - 7d` (some contexts) | duration literal not always accepted | epoch ms: `now() - 604800000` |
| `regex(format("pat-%s", field), field=Y)` | `regex()` compiles at build time | lookup file + `match(file=...)` |
| `regex("(?i)pat", field=X)` | inline flags inconsistent | trailing flag: `X = /pat/i` |
| `field = /[A-Za-z-]/` | hyphen at end of char class | move to start: `[-A-Za-z]` |
| Uppercase `OR` / `AND` / `NOT` | Valid documented CQL | Use one consistent style; parenthesize mixed operators |
| `stddev` / `formattime` | case-sensitive | `stdDev` / `formatTime` |
| `field = otherField` | RHS of `=` is a literal — this tests `field == "otherField"` | `test(field == otherField)` to compare two fields |
| `x := /re/i` on RHS of `:=` | slash quirk — parsed as division | `x := regex("re", flags="i")`, or filter standalone `\| f = /re/i` |
| `EventName = groupBy` (a function name) | reserved word unquoted | quote it: `EventName = "groupBy"` |
