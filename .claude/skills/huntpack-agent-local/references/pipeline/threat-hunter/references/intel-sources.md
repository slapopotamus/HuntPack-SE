# Threat Intel Sources

Organized by use case. Match your need to the right source — not all sources are useful for all query types.

---

## Source Decision Matrix

| You Need | Primary Sources | Secondary Sources |
|---|---|---|
| Is this CVE actively exploited? | CISA KEV, NVD | Vendor advisory, EPSS score |
| IOCs for a specific malware family | VirusTotal, MalwareBazaar, Any.run | ThreatFox, AlienVault OTX |
| TTPs for a named threat actor | MITRE ATT&CK Groups, Mandiant/Google TAG | CrowdStrike Adversary Intel blog |
| Recent campaign or ransomware activity | BleepingComputer, The Record | Unit42, Sophos X-Ops |
| CVE technical details + exploit availability | NVD, Tenable Research, AttackerKB | GitHub PoC search |
| Probability a CVE will be exploited | EPSS (api.first.org) | CISA KEV + CVSS together |
| Current C2 infrastructure IOCs | ThreatFox, VirusTotal | AlienVault OTX pulse search |
| Vendor-specific advisory | Vendor PSIRT / MSRC directly | BleepingComputer coverage |

---

## Category 1: Vulnerability Intelligence

### CISA KEV Catalog
- **What it provides:** Confirmed in-the-wild exploitation status; mandatory patching deadlines for federal agencies (useful as severity signal for all orgs)
- **Search pattern:** `CISA KEV [CVE-ID or vendor name] [current month year]`
- **Best for:** Confirming whether a CVE is actively being exploited — absence does NOT mean safe, only that CISA hasn't confirmed it yet
- **Freshness:** Updated within 1–3 days of confirmed exploitation evidence
- **Key signal:** CISA KEV entry = immediate action regardless of CVSS score

### NVD (National Vulnerability Database)
- **What it provides:** CVSS v3 scores, CWE root cause classification, CPE affected products list, references to vendor advisories and PoCs
- **Search pattern:** `NVD CVE [CVE-ID]` or direct: `nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN`
- **Best for:** Getting CVSS score, confirming affected software versions and CPE strings
- **Fields to extract:** `cvssV3BaseScore`, `cvssV3Vector`, affected CPE versions, reference links
- **Limitation:** NVD enrichment (analysis) can lag 1–2 weeks behind CVE publication; base score usually available within days

### Tenable Research / Rapid7 AttackerKB
- **What it provides:** Exploit complexity assessment, exploit availability timeline, proof-of-concept availability, analyst notes
- **Search pattern:** `Tenable Research [CVE-ID]` or `AttackerKB [CVE-ID]`
- **Best for:** Understanding whether working exploit code is publicly available and how easy it is to use — directly affects urgency

### EPSS (Exploit Prediction Scoring System)
- **What it provides:** Probability (0–1) that a CVE will be exploited in the wild within 30 days, based on threat intel signals
- **Search pattern:** `EPSS score [CVE-ID]` or API: `api.first.org/data/v1/epss?cve=[CVE-ID]`
- **Best for:** Prioritizing between multiple unpatched CVEs when you can't patch everything at once
- **Key threshold:** EPSS > 0.5 + CISA KEV = treat as Critical regardless of CVSS score

---

## Category 2: IOC & Malware Intelligence

### VirusTotal
- **What it provides:** Multi-engine detection rates, behavioral sandbox analysis, file relationships (dropped files, network connections), WHOIS for domains/IPs
- **Search pattern:** `VirusTotal [SHA256 hash]` or `VirusTotal [domain or IP]`
- **Best for:** Confirming maliciousness of a hash; finding related samples and C2 infrastructure; domain/IP reputation
- **Fields to extract:** Detection ratio, threat label/family name, first/last seen dates, related files and domains
- **Limitation:** High detection ratio ≠ definitively malicious; low detection ratio ≠ clean — especially for new samples

### MalwareBazaar (abuse.ch)
- **What it provides:** Malware samples with SHA256/MD5/SHA1 hashes, YARA rules, malware family tags, submission date
- **Search pattern:** `MalwareBazaar [malware family name]` or direct: `bazaar.abuse.ch/browse/`
- **Best for:** Getting fresh IOC hashes for a specific malware family (Cobalt Strike, QakBot, AsyncRAT, etc.)
- **Freshness:** Near-real-time community submissions
- **API:** `bazaar.abuse.ch/api/` for bulk lookups by family, tag, or hash

### ThreatFox (abuse.ch)
- **What it provides:** C2 IOCs (domains, IPs, URLs), malware family attribution, first/last seen
- **Search pattern:** `ThreatFox [malware or threat name]` or direct: `threatfox.abuse.ch/browse/`
- **Best for:** Getting current C2 infrastructure IOCs, especially for common C2 frameworks (Cobalt Strike, Sliver, Metasploit, Brute Ratel)
- **API:** `threatfox-api.abuse.ch/api/v1/` — supports bulk lookups and recent IOC feeds

### Any.run (Interactive Sandbox)
- **What it provides:** Dynamic analysis reports, behavioral IOCs, process trees, network IOCs, MITRE ATT&CK auto-mapping
- **Search pattern:** `any.run [malware name or hash]` or direct: `app.any.run/tasks/`
- **Best for:** Understanding malware behavior when you have a hash — provides TTPs, dropped files, network activity, and registry changes in one report
- **Key output:** Use the MITRE ATT&CK tab to get technique IDs and use the network tab to get C2 IOCs

### AlienVault OTX
- **What it provides:** Community-contributed threat intelligence "pulses" with IOC collections, CVE associations, MITRE TTP tags
- **Search pattern:** `OTX AlienVault [threat name or CVE]` or `otx.alienvault.com/pulse/`
- **Best for:** Getting broad IOC sets for well-known campaigns quickly; cross-referencing IP/domain reputation
- **Limitation:** Community quality varies significantly — always cross-reference high-impact IOCs against VirusTotal or ThreatFox before blocking

---

## Category 3: Threat Actor & Campaign Intelligence

### MITRE ATT&CK Groups
- **What it provides:** Authoritative TTP mapping per group, tools and malware used, campaign history, STIX data export
- **Search pattern:** `MITRE ATT&CK [threat actor name]` or direct: `attack.mitre.org/groups/`
- **Best for:** Getting the canonical technique list for a named threat actor before building MITRE-mapped detections
- **Key fields:** Techniques (with procedure examples showing exact tool usage), software (malware families + offensive tools), campaign history
- **Tip:** Use the "Techniques Used" table — the procedure examples describe exactly how the group uses each technique, which is more useful than the technique description alone

### CrowdStrike Adversary Intelligence
- **What it provides:** CrowdStrike's own adversary tracking (BEAR/PANDA/KITTEN/SPIDER naming convention), CQL-relevant TTPs
- **Search pattern:** `CrowdStrike [adversary name] blog` or `CrowdStrike [threat name] threat intelligence`
- **Best for:** CrowdStrike-specific context on adversaries they actively track; blog posts often include CrowdStrike-specific detection guidance
- **Note:** Counter Adversary Operations portal is paywalled; blog posts and public reports are free

### Google TAG / Mandiant
- **What it provides:** Nation-state and sophisticated threat actor research, zero-day exploitation analysis, detailed TTPs, campaign timelines
- **Search pattern:** `Google TAG [threat name]` or `Mandiant [threat actor] blog`
- **Best for:** APT and nation-state threat analysis; particularly strong for Google-product-targeting threats and zero-day exploitation chains

### Recorded Future / The Record
- **What it provides:** Threat intelligence reporting, ransomware group tracking, vulnerability exploit data
- **Search pattern:** `Recorded Future [threat name]` or `The Record [threat name]`
- **Best for:** Policy-context threat intelligence; ransomware group attribution and victim tracking

---

## Category 4: Current Threat News

### Source Reliability Ranking (for Phase 0 landscape scans)

| Source | Strengths | Best Search Pattern |
|---|---|---|
| **BleepingComputer** | Fast, accurate breaking coverage of ransomware and malware | `site:bleepingcomputer.com [threat name]` |
| **The Record (Recorded Future)** | Policy-focused; strong on nation-state and infrastructure attacks | `site:therecord.media [threat name]` |
| **Krebs on Security** | Investigative; strong on fraud, criminal operations, breach attribution | `site:krebsonsecurity.com [topic]` |
| **Ars Technica Security** | Technically rigorous; good for exploit analysis and zero-days | `Ars Technica security [CVE or threat]` |
| **CrowdStrike Blog** | Platform-relevant; often includes CQL-compatible indicators | `site:crowdstrike.com/blog [threat]` |
| **Palo Alto Unit42** | Deep technical reporting on campaigns and malware | `Unit42 [threat name]` |
| **Sophos X-Ops** | Strong ransomware and endpoint threat coverage | `Sophos X-Ops [threat name]` |
| **Microsoft MSRC** | Authoritative for Microsoft product vulnerabilities | `site:msrc.microsoft.com [CVE-ID]` |

### Vendor Advisory Search Patterns

| Vendor | Search Pattern |
|---|---|
| Microsoft | `site:msrc.microsoft.com [CVE-ID]` or `Microsoft Security Response Center [product] advisory` |
| Fortinet | `Fortinet PSIRT [CVE-ID]` or `Fortinet security advisory [product]` |
| Ivanti | `Ivanti security advisory [CVE-ID]` or `Ivanti PSIRT [product]` |
| Citrix | `Citrix security bulletin [CVE-ID]` |
| VMware / Broadcom | `VMware security advisory [CVE-ID]` or `Broadcom security advisory [product]` |
| Cisco | `Cisco Security Advisory [CVE-ID]` |
| Palo Alto Networks | `Palo Alto Networks Security Advisory [CVE-ID]` |
| F5 | `F5 security advisory [CVE-ID]` or `K-article [topic]` |
| SolarWinds | `SolarWinds security advisory [CVE-ID]` |

---

## Phase 0 Recommended Search Set

For the broadest, fastest landscape scan, run exactly these 4 searches in parallel:

1. `CISA KEV new additions [current month year]` — mandatory-attention vulnerabilities
2. `actively exploited CVE critical [current month year]` — confirmed in-the-wild exploitation
3. `ransomware campaign active [current month year]` — ongoing extortion and deployment activity
4. `[user's tech stack] vulnerability attack [current month year]` — environment-specific (skip if no context)

Stop at 4 searches. Go wide, not deep — depth comes in Phase 1 for selected threats only.

**If the environment is known**, replace search #4 with the most specific vendor advisory query for the user's highest-risk products (e.g., `Fortinet FortiGate vulnerability active exploitation [current month year]`).
