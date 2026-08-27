# Research Brief — Copy-Paste Template

This is a clean copy of the schema defined in STAGE.md. Use this as the starting point for every brief — fill in the placeholders, delete any tables that have no entries (replacing them with `(none published)` first). The brief stays in conversation context as Stage 2's input — do not write it to disk (conventions §1).

---

```markdown
# Research Brief: [Subject]
**Mode:** [CVE / Campaign / Actor / Malware family / Article / Hardening]
**Date:** YYYY-MM-DD
**Author:** per conventions §5 (`Pack author:` in `TECH_STACK.md`, else `cybersecurity analyst`)
**Confidence:** [Overall — High / Medium / Low]

---

## 1. Subject
- **Primary identifier:** [CVE ID / canonical name / family name]
- **Aliases:** [comma-separated]
- **First seen / disclosed:** [date]
- **Most recent reported activity:** [date]
- **Timeline:** | Disclosure | KEV listed | Public PoC | Exploitation observed |
                 |---|---|---|---|
                 | [date] [#N] | [date or —] [#N] | [date or —] [#N] | [date or —] [#N] |

## 2. Source ledger
| # | URL | Tier | Type | What this source contributed |
|---|-----|------|------|------------------------------|
| 1 |     | T?   |      |                              |

Tier definitions: T1 vendor/government primary; T2 reputable security press; T3 researcher blog; T4 forum/social.

## 3. Summary
[Two to four sentences — what is this, why does it matter, what's the current state.]

## 4. Affected surface
- **Products / versions:**
- **Configurations / prerequisites:**
- **Patch status:**
- **Workarounds:**
- **CVSS:** [score + vector, e.g. 9.8 / CVSS:3.1/AV:N/AC:L/...]   ← CVE mode
- **EPSS:** [score (percentile), e.g. 0.94 (99th)]                ← CVE mode
- **KEV due date:** [federal remediation deadline, or "not KEV-listed"]

## 5. TTPs (MITRE ATT&CK)
| Tactic | Technique | Sub-technique | Source | Behavioral context |
|---|---|---|---|---|
|        |           |               |        |                    |

## 6. Indicators of Compromise

### 6.1 File hashes
| Algo | Value | Source | Notes |
|---|---|---|---|
|      |       |        |       |

### 6.2 Network indicators
| Type | Value | Source | Notes |
|---|---|---|---|
|      |       |        |       |

### 6.3 Host indicators
| Type | Value | Source | Notes |
|---|---|---|---|
|      |       |        |       |

## 7. Detection opportunities
- [Observable behavior or artifact, with the source that mentions it]

## 8. Mitigation / Hardening
- **Vendor patch / fix:**
- **Configuration changes:**
- **Compensating controls:**
- **Vendor-recommended detections:**

## 9. Contradictions & gaps
- [Anything that doesn't agree across sources, anything you couldn't find, anything paywalled]

## 10. Handoff
- Brief complete → Stage 2 (threat-hunter).
```

---

## Filling tips

- **Date:** Today's date, ISO format.
- **Confidence:** Set this *last*, based on the source mix you actually ended up with.
- **Source ledger:** Number sources in the order you fetched them. Use `[#N]` to cite them in every other section — never restate URLs inside section bodies.
- **Tables with no entries:** Replace empty rows with `(none published)` so absence is visible. Don't delete the section.
- **Verbatim IOCs:** Copy hashes, domains, IPs *exactly* as the source published them. Capitalize hashes as the source does. If the source defanged (`evil[.]com`), refang to `evil.com` in the brief — the IOC table is the canonical, machine-readable copy.
- **Inferred TTPs:** Prefix with `(inferred)`. Don't claim a source said something it didn't.
- **§9 is not optional.** Every brief has some gap. If you cannot think of one, you haven't looked hard enough.
