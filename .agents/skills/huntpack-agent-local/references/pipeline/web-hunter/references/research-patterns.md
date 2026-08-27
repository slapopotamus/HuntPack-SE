# Research Patterns

Search operators, dorks, and multi-hop tactics that consistently produce more signal than naive keyword searches.

## Table of contents
- Search operators that matter
- Dorks for common threat-intel needs
- The pivot patterns
- Anti-patterns (things that waste tokens)

---

## Search operators that matter

| Operator | Use for | Example |
|---|---|---|
| `site:` | Restrict to a known-good domain | `site:mandiant.com scattered spider` |
| `filetype:pdf` | Find long-form vendor reports behind blog posts | `filetype:pdf "lumma stealer" analysis` |
| `intitle:` | Surface pages with the keyword in the title (filters out passing mentions) | `intitle:"CVE-2026-35616"` |
| `inurl:` | Find canonical paths (vendor advisory pages, KB articles) | `inurl:advisory CVE-2026-35616` |
| `"exact phrase"` | Pin down a specific identifier or product name | `"CVE-2026-35616" "appendix"` |
| `-term` | Exclude noise | `scattered spider -netflix -tv-show` |
| `OR` | Cover synonym variants | `IOC OR "indicators of compromise" lumma` |
| `before:YYYY-MM-DD` / `after:YYYY-MM-DD` | Recency control | `lumma stealer after:2026-01-01` |

---

## Dorks for common threat-intel needs

### CVE research
```
CVE-XXXX-XXXXX NVD                                # Land on the NVD record
CVE-XXXX-XXXXX CISA KEV                           # Confirm exploited-in-the-wild status
[vendor] PSIRT CVE-XXXX-XXXXX                     # Find the vendor advisory
CVE-XXXX-XXXXX "indicators" OR "appendix"          # Find IOC-bearing writeups
CVE-XXXX-XXXXX filetype:pdf                       # Long-form analysis
"CVE-XXXX-XXXXX" exploit POC site:github.com      # Public PoC availability
"CVE-XXXX-XXXXX" site:reddit.com/r/blueteamsec    # Community discussion
```

### Campaign / actor research
```
[name] site:attack.mitre.org                       # Canonical TTP catalog
[name] site:mandiant.com                           # Mandiant analysis
[name] site:microsoft.com                          # Microsoft Threat Intelligence
[name] site:unit42.paloaltonetworks.com            # Unit 42
[name] site:cisa.gov                               # CISA advisory
[name] aliases                                     # Cross-vendor alias mapping
[name] IOCs OR indicators after:YYYY-MM-DD         # Recent IOC sets
[name] TTPs OR techniques                          # Behavior writeups
```

### Malware family research
```
[family] site:malpedia.caad.fkie.fraunhofer.de    # Canonical entry
[family] site:bazaar.abuse.ch                      # Recent samples
[family] site:threatfox.abuse.ch                   # Current C2
[family] site:app.any.run                          # Sandbox runs (behavior)
[family] yara                                      # Detection rules in circulation
[family] config extractor                          # Static config research
```

### Hardening research
```
[product] hardening guide site:[vendor.com]        # Vendor official baseline
[product] CIS benchmark filetype:pdf               # CIS PDF if openly hosted
[product] STIG site:public.cyber.mil               # DISA STIG
[product] security baseline                        # Catch-all
NIST SP [number] [topic]                           # NIST publication lookup
```

### Surfacing original vs. derivative coverage
```
[topic] -site:bleepingcomputer.com -site:thehackernews.com -site:darkreading.com
```
This excludes the most common aggregators and pushes original research to the top of results.

---

## The pivot patterns

### Pattern A — News article → primary
1. Read the news article
2. Identify every "according to [X]" or hyperlinked source
3. Fetch the primary source (the cited vendor report, advisory, or research blog)
4. Extract from the primary, not the news article

This is the single highest-leverage tactic in the whole skill. News articles always summarize and almost always omit the IOC appendix.

### Pattern B — Vendor blog → PDF appendix
Many vendor blogs are summaries of longer reports. Look for "download the full report" links or `filetype:pdf` searches on the same topic+vendor combination. The PDF will have more detail and structured tables the blog flattened.

### Pattern C — CVE → CVE family
When researching a CVE, search for nearby CVE numbers in the same product (e.g. CVE-2026-35614 through CVE-2026-35620 might all be related). Vendors often publish a batch advisory covering multiple CVEs together.

### Pattern D — Campaign → actor → other campaigns
When researching a campaign, identify the attributed actor (if any). Then look at the actor's other recent campaigns — TTPs often carry forward, and IOCs from a related campaign may show up in the current one.

### Pattern E — Malware family → loader chain
Most modern malware is delivered by a loader (SmokeLoader, Bumblebee, IcedID, etc.). When researching a payload, also research its current delivery loader — the loader's IOCs may be more visible than the payload's.

### Pattern F — Alias chaining
Threat actors and campaigns commonly have 3–5 aliases across vendors (Mandiant calls one group X, CrowdStrike calls them Y, Microsoft calls them Z). Always search all aliases — some sources only use one. ATT&CK Groups pages are the best alias-mapping reference.

### Pattern G — Wayback for dead links
If a cited source 404s or the vendor has taken a page down, try `web.archive.org/web/*/[URL]` once. If that fails, note the dead link in §9.

---

## Anti-patterns (things that waste tokens)

**Searching the same phrase three different ways.** If `"Lumma Stealer" IOCs` returns nothing useful, `Lumma indicators` and `Lumma C2` won't either. Broaden the topic instead, or accept that the gap is real and move on.

**Fetching every result on the first page.** Triage first by title and snippet; only fetch the ones likely to be primary or to add new facts.

**Fetching the same primary source twice via different URLs.** Vendor reports often appear at the vendor blog, on a mirror, in a PDF, and as a press release. Pick one canonical URL and stop.

**Asking the user "do you want me to keep searching".** If the brief has enough material to be useful, deliver it. If it doesn't, deliver what you have with §9 explaining the gaps. Don't bottleneck on permission.

**Naive translation to query syntax.** Stage 1 doesn't write queries. Resist the urge to draft a CQL query inside the brief — that breaks the contract; hypotheses belong to Stage 2 and query construction to Stage 3.

**Repeating IOCs across sections.** A SHA256 belongs in one row in §6.1 (file hashes). Don't also list it in the source-ledger description column or the summary. Use source numbers `[#1]` to indicate provenance instead.

**Trying to fetch paywalled content via workarounds.** If the primary source is paywalled, note it and use secondary coverage. Don't try cached versions, alt-URLs, or scraper services — these are restricted, and the loss of one source is rarely fatal to a brief.
