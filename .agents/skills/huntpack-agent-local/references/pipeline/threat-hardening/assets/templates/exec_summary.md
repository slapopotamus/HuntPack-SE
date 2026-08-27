# Executive Summary Template — Worked Example

This is the first tier of Mode 2 (Standalone Hardening Assessment). One page. Written for a CISO who has 5 minutes between meetings.

---

# Executive Summary

## What we found

During recent threat-hunt activity, our team identified attempted credential theft against several Windows workstations. Specifically, attackers (or commodity malware) attempted to read the memory of the Windows authentication subsystem (`lsass.exe`) — a well-documented technique used to steal passwords and authentication tokens for use in lateral movement across the environment.

The attempts did not succeed in producing a confirmed compromise, but our current endpoint configuration does not reliably prevent this technique on all systems. A successful instance would allow an attacker to escalate from a single foothold to broad domain access in hours.

## Why it matters

Credential theft from LSASS is the most common second-stage technique used by ransomware operators and nation-state intrusions alike. The financial impact of a successful escalation, based on industry benchmarks for organizations of similar size, ranges from **$1.5M to $8M** in direct response costs (incident response retainer, legal, downtime, restoration) plus regulatory and reputational exposure. This estimate excludes ransomware payment, which we do not recommend paying under any circumstances.

The technique is also explicitly tracked under regulatory and insurance frameworks (PCI DSS 8.x, HIPAA Security Rule §164.308(a)(5), most cyber insurance underwriting questionnaires). Failing to remediate after evidence of attempts may affect insurance coverage in the event of a future claim.

## Recommended decisions

We recommend the leadership team approve the following three actions:

1. **Deploy four immediate hardening controls** (estimated 8 IT-hours, no per-seat cost, no user-visible change). These eliminate the most exploited variant of the attack. **Decision needed: approve IT to proceed this week.**
2. **Pilot Credential Guard on a small ring of test endpoints** before broader rollout (estimated 20 IT-hours, no per-seat cost, minor risk of compatibility breakage with two known legacy applications). **Decision needed: confirm pilot scope by end of next week.**
3. **Initiate a 90-day project to implement tiered administrative access** (estimated 80–120 IT-hours over the quarter, no per-seat cost, requires admin behavior change). This is the structural fix that ensures one compromised endpoint cannot become a domain-wide incident. **Decision needed: assign a project owner.**

## Cost / effort estimate

| Tier | Effort | Cost | Timeline |
|---|---|---|---|
| Immediate hardening | Low (~8 hrs) | $0 (no licensing) | This week |
| Credential Guard pilot | Medium (~20 hrs) | $0 (already licensed via Windows Enterprise) | 2–4 weeks |
| Tiered admin model | High (~80–120 hrs) | $0–$25K (optional PAM tooling) | 1 quarter |

**Total to "much harder to credential-dump":** roughly **30 hours of IT effort** spread over the next month, plus the structural project. No new spend required.

## What happens if we do nothing

A single user opening a malicious document on a workstation with local admin rights is the routine starting point for ransomware in this industry. Our hunt evidence indicates this has already been attempted; the next attempt may not be caught in time. The structural fix (item 3) is the difference between "one machine reimaged" and "three days of downtime and a regulatory disclosure."

---

# Template structure

Use the example above as the shape. The skeleton:

```markdown
# Executive Summary

## What we found
[2 short paragraphs in plain language. No jargon. Frame as evidence + risk.]

## Why it matters
[Business framing: financial, operational, regulatory. Include rough dollar ranges with caveats.]

## Recommended decisions
[3–5 numbered, each ending with "Decision needed: ..." so the reader knows exactly what's being asked.]

## Cost / effort estimate
[Table: tier / effort / cost / timeline. Be honest about uncertainty — ranges are fine.]

## What happens if we do nothing
[1 paragraph. Concrete consequence, not vague risk language.]
```

**Length:** One page when printed. ~500 words is the target. Resist the urge to add detail — that's what the Technical Detail section is for.

**Tone:** Confident but not alarmist. The CISO needs to take this to leadership and not look hysterical. Specific numbers and decision asks make this happen; vague threats make it not happen.
