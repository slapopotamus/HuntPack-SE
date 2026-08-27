# Source Tier Taxonomy

A source's tier determines how much weight its claims should carry in the Research Brief and how much confidence you can assign to facts that depend on it.

## Table of contents
- Tier 1 — Primary
- Tier 2 — Reputable security press
- Tier 3 — Researcher blog / individual analyst
- Tier 4 — Forum / social / unverified
- Confidence calibration rules
- Edge cases

---

## Tier 1 — Primary

The originators of the facts. When a Tier-2 article says "according to X", X is almost always Tier 1.

### Vendor PSIRT and security advisories
The vendor that owns the affected product is the authoritative source for affected versions, patches, and (often) the most detailed technical writeup. Examples:
- Microsoft MSRC (`msrc.microsoft.com`)
- Cisco PSIRT (`sec.cloudapps.cisco.com/security/center/publicationListing.x`)
- Fortinet PSIRT (`fortiguard.com/psirt`)
- Ivanti Security (`forums.ivanti.com/s/product-lifecycle`)
- VMware Security (`vmware.com/security/advisories.html`)
- Apple Security Releases (`support.apple.com/HT201222`)
- Atlassian Security (`atlassian.com/trust/security/advisories`)
- Citrix Security (`support.citrix.com/security-bulletins`)
- Oracle CPU (`oracle.com/security-alerts/`)
- SAP Security Patch Day

### Government / national CERT advisories
Authoritative for confirmed-exploited status, sometimes the most structured IOC sources available, free of marketing tone:
- CISA Advisories (`cisa.gov/news-events/cybersecurity-advisories`) — joint advisories often co-authored with vendors and other CERTs
- CISA KEV catalog (`cisa.gov/known-exploited-vulnerabilities-catalog`)
- NCSC UK (`ncsc.gov.uk/section/advice-guidance/all-topics`)
- ACSC Australia (`cyber.gov.au/about-us/view-all-content/advisories`)
- CERT-EU (`cert.europa.eu`)
- BSI / CERT-Bund (Germany)
- JPCERT (Japan)

### Standards and canonical databases
- NVD (`nvd.nist.gov`) — official CVE record with CVSS, CWE, CPE
- MITRE ATT&CK (`attack.mitre.org`) — canonical TTP, group, and software pages
- MITRE CWE (`cwe.mitre.org`)
- First.org EPSS API (`api.first.org/data/v1/epss`)
- Malpedia (`malpedia.caad.fkie.fraunhofer.de`)

### Vendor threat-intel reports
Top-tier vendor research teams. These publish the original analyses that the security press summarizes:
- Mandiant (Google) — `cloud.google.com/security/resources/insights` and `mandiant.com`
- Microsoft Threat Intelligence — `microsoft.com/en-us/security/blog`
- Unit 42 (Palo Alto Networks) — `unit42.paloaltonetworks.com`
- CrowdStrike Counter Adversary Operations — `crowdstrike.com/blog/category/threat-intel-research/`
- Cisco Talos — `blog.talosintelligence.com`
- Sekoia.io — `blog.sekoia.io`
- DFIR Report — `thedfirreport.com` (independent but consistently primary-source-quality intrusion writeups)
- Trend Micro Research — `trendmicro.com/en_us/research.html`
- ESET Research — `welivesecurity.com`
- Kaspersky GReAT — `securelist.com`
- Symantec / Broadcom Threat Hunter — `symantec-enterprise-blogs.security.com/blogs/threat-intelligence`
- Sophos X-Ops — `news.sophos.com/en-us/category/threat-research/`
- Volexity — `volexity.com/blog/`
- watchTowr Labs — `labs.watchtowr.com` (excellent for n-day exploitation analysis)
- Horizon3.ai Attack Team — `horizon3.ai/attack-research/`
- Rapid7 Labs — `rapid7.com/blog/tag/rapid7-labs/`
- Tenable Research — `tenable.com/blog/research`
- Project Discovery — `projectdiscovery.io/blog`
- Recorded Future / Insikt Group — `recordedfuture.com/research`
- IBM X-Force — `securityintelligence.com/x-force/`
- Group-IB — `group-ib.com/blog`
- Lookout (mobile threats) — `lookout.com/threat-intelligence`
- Zimperium (mobile threats) — `zimperium.com/blog`

### Community-sourced primary feeds
- abuse.ch family: MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker
- AlienVault OTX (community pulses — Tier 1 for the contributed IOCs themselves, lower for the prose)
- VirusTotal (Tier 1 for the detection ratios and behavioral data, not for the "comments" field)

---

## Tier 2 — Reputable security press

Useful for recency, narrative, and finding which primary source to chase. Almost never authoritative for IOCs or version-affected lists.

- BleepingComputer (`bleepingcomputer.com`)
- The Record by Recorded Future (`therecord.media`)
- KrebsOnSecurity (`krebsonsecurity.com`)
- Dark Reading (`darkreading.com`)
- SC Media (`scmagazine.com`)
- The Hacker News (`thehackernews.com`)
- CyberScoop (`cyberscoop.com`)
- SecurityWeek (`securityweek.com`)
- Risky Business newsletter / podcast (`risky.biz`)

**Rule:** When a Tier-2 article cites a Tier-1 source, fetch the Tier-1 source. The article's IOC list will almost always be a subset of the primary's appendix.

---

## Tier 3 — Researcher blog / individual analyst

Useful when the author is known and reputable. Verify via cross-source where possible.

- Personal blogs of well-known researchers (assume Tier 3 unless they're at one of the Tier-1 vendor teams)
- Medium posts (variable quality — judge by author reputation)
- Substack security newsletters (TLDR Sec, tl;dr sec, Risky Business News, Detection Engineering Weekly)
- GitHub gists with IOC pastes (Tier 3 even when the IOCs are accurate)
- LOLBAS Project (`lolbas-project.github.io`) — Tier 1 for living-off-the-land binary catalog
- GTFOBins (`gtfobins.github.io`) — Tier 1 for Unix LOLBINs
- Detection-Engineering signal feeds (Florian Roth's Twitter, Sigma rule repos)

---

## Tier 4 — Forum / social / unverified

Useful as a lead generator only. Never the sole source for any indicator that lands in the brief.

- Twitter/X threads
- Reddit (r/blueteamsec, r/netsec — Tier 3 in practice, but the indicators themselves are Tier 4)
- Mastodon infosec instances
- Telegram channels
- Paste sites (pastebin, ghostbin, doxbin)
- Discord server scraping

**Rule:** Every T4 indicator must be confirmed in at least one T1 or T2 source before it appears in the IOC table. If it cannot be confirmed but is interesting, mention it in §9 (Gaps) as "unverified lead".

---

## Confidence calibration rules

The brief's overall confidence rating tracks the source mix:

| Confidence | Required source mix |
|---|---|
| **High** | ≥2 T1 sources agreeing on the core facts (affected versions, IOC set, TTPs) |
| **Medium** | 1 T1 source + ≥1 T2 source, OR ≥2 T2 sources agreeing |
| **Low** | T3/T4 sources only, OR sources actively contradicting each other |

For per-fact confidence (e.g. confidence in a specific IOC), apply the same rule to the sources that mention that fact. Don't carry the overall rating downward — if one specific IOC is only T4-sourced, flag it specifically, don't lower the whole brief.

---

## Edge cases

**A Tier-1 vendor publishes a marketing-heavy "report" that's really an ad for their product.** Treat it as T2 — the facts may be sound but the framing isn't to be trusted. Look for the underlying technical analysis (sometimes there's a separate technical blog, sometimes a PDF appendix).

**An individual researcher publishes from inside a Tier-1 org's blog.** Tier 1 — the org's editorial review is doing work.

**The same researcher publishes the same content on their personal blog and on their employer's blog.** Cite the employer's version (Tier 1 by org); the personal post is redundant.

**A Tier-2 outlet has been credited with breaking a story (the discovery is theirs, not someone else's).** Promote to Tier 1 for that specific story. Krebs has done this repeatedly; BleepingComputer occasionally.

**A government CERT publishes a joint advisory with vendor co-signers.** Tier 1, and arguably the strongest possible source because it represents multi-party verification.

**An OTX pulse with no author reputation and no cross-references.** Treat the prose as T4; treat the IOCs as leads to verify.

**A paste of "leaked" data from a forum.** Tier 4. Do not treat any indicator inside as confirmed; if interesting, mention as unverified in §9.
