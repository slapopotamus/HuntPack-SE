# Technical Detail Template — Structure

This is the second tier of Mode 2. It follows the Executive Summary in the same document. It is for the team implementing the controls — IT engineers, security engineers, sysadmins. Full prescriptive depth.

---

# Technical Detail

## 1. Threat & Observed Evidence

[Describe what was observed in concrete technical terms:
- Hunt query / alert that fired
- Affected hosts (anonymized as IT-XXX if going to a wider audience)
- Process / parent process / command line evidence
- Time window
- Whether prevention was triggered or not
- IOCs (hashes, IPs, domains) if any]

## 2. MITRE Technique Mapping

| Technique ID | Name | Tactic | Confidence |
|---|---|---|---|
| TXXXX.XXX | [Name] | [Tactic — e.g., Credential Access] | High / Medium / Low |

[For each technique, link to https://attack.mitre.org/techniques/TXXXX/ — the implementer will want it.]

**Primary mitigations referenced in this document:**

| M-num | Mitigation | Why it applies |
|---|---|---|
| M1025 | Privileged Process Integrity | LSASS access requires unprotected LSASS |
| M1040 | Behavior Prevention on Endpoint | EDR + ASR catch the access pattern |
| ... | ... | ... |

## 3. Current State Assessment

[What's already in place. This is critical — recommending controls the org already has makes the whole document look uninformed. Be honest.]

| Control | Current state | Source of truth |
|---|---|---|
| WDigest disabled | Unknown — needs verification | Spot-check 10 endpoints with PS command in §5 |
| RunAsPPL | Enabled on Server 2019+ (per group policy `Tier0-RunAsPPL`); not enforced on Win10/11 workstations | gpresult inspection |
| Credential Guard | Not deployed | None |
| Falcon Suspicious Process Block | Enabled (BLOCK) | Falcon Console > Prevention Policies > "Workstation Prod" |
| Tiered admin | Not implemented | Account audit |

## 4. Recommended Controls (tiered)

### 4.1 Immediate (deploy this week)

#### 4.1.1 Disable WDigest credential caching

**Rationale:** WDigest stores cleartext passwords in LSASS memory for legacy SSO scenarios. On a fleet last upgraded past Windows 7, no application needs this. Disabling removes the cleartext password pool entirely, so even a successful LSASS dump returns only hashes (which are slower to use and easier to detect).

**Framework:** MITRE M1027, CIS Windows 10 18.3.6 (Level 1), MS Security Baseline `Computer Configuration > Administrative Templates > MS Security Guide > WDigest Authentication = Disabled`.

**Configuration change:**

- GPO path: `Computer Configuration > Administrative Templates > MS Security Guide > WDigest Authentication`
- Set to: `Disabled`
- Equivalent registry write:
  - Key: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
  - Value name: `UseLogonCredential`
  - Type: `REG_DWORD`
  - Data: `0`

**PowerShell:**
```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
New-ItemProperty -Path $path -Name 'UseLogonCredential' -Value 0 -PropertyType DWORD -Force | Out-Null
```

**Validation:**
```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential -EA SilentlyContinue).UseLogonCredential
# Expect: 0 (or null if registry key absent)
```

**Compatibility / rollback:**
- No known modern compatibility issues. Legacy SSO products using HTTP Digest auth would break, but the org confirmed no such systems remain (current state per §3).
- Rollback: set the value to `1` and reboot.

---

#### 4.1.2 [Next control — same shape]

[Continue for each Immediate-tier control.]

### 4.2 Short-term (1–4 weeks, requires piloting)

[Same shape, but each control gets an additional "Pilot plan" subsection — what to test, on which endpoints, for how long, what success criteria.]

### 4.3 Long-term / structural (1–3 months)

[Same shape, but each control gets an additional "Project plan" subsection — owner, milestones, dependencies.]

## 5. Verification Plan

After the Immediate-tier controls are deployed, validate by running the following on a representative sample of 20 endpoints (10 workstations, 10 servers):

[Block of PowerShell that runs all the per-control validation checks consolidated, and writes results to a CSV or — preferred — a RMM custom field.]

**Pass criteria:**
- ≥95% of sampled endpoints show all Immediate controls in the expected state
- Any endpoint failing two or more checks gets a follow-up ticket

## 6. Rollback Procedures

Each control above includes its own rollback in its subsection. The summary:

| Control | Rollback method | Reboot? |
|---|---|---|
| WDigest disabled | Set `UseLogonCredential = 1` | No |
| RunAsPPL | Remove `RunAsPPL` reg value | Yes |
| Credential Guard | GPO: `VBS = Disabled`, then `bcdedit /set hypervisorlaunchtype off` from elevated cmd | Yes |
| ASR rule X | `Set-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Disabled` | No |

## 7. Detection Pairing

The hardening above is preventive. To know whether anything bypasses it post-deployment, also confirm the following detections are in place:

- Falcon CQL: `[paste the relevant detection query]`
- Defender ASR audit logs: Event ID 1121/1122 in `Microsoft-Windows-Windows Defender/Operational`
- Sysmon Event ID 10 (ProcessAccess) targeting `lsass.exe` (if Sysmon is deployed alongside Falcon)

If the user wants detection coverage built or refined, chain to the `threat-hunter` skill.

## Appendix A — Full PowerShell Deployment Script

[Consolidated script that applies all Immediate-tier changes in one go, with try/catch and logging. Note: for fleet deployment, hand this to your RMM deployment tooling for RMM custom-field writeback and admin checks.]

```powershell
# threat-hardening — Immediate tier for T1003.001 LSASS Memory Access
# Run elevated. Reboot required for RunAsPPL.

$ErrorActionPreference = 'Stop'
$results = @{}

# 1. Disable WDigest
try {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
  New-ItemProperty -Path $p -Name 'UseLogonCredential' -Value 0 -PropertyType DWORD -Force | Out-Null
  $results['WDigest'] = 'Applied'
} catch { $results['WDigest'] = "Failed: $_" }

# 2. Enable RunAsPPL (Credential Guard precursor; reboot required to take effect)
try {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  New-ItemProperty -Path $p -Name 'RunAsPPL' -Value 2 -PropertyType DWORD -Force | Out-Null
  $results['RunAsPPL'] = 'Applied (reboot required)'
} catch { $results['RunAsPPL'] = "Failed: $_" }

# 3. Enable ASR rule: Block credential stealing from LSASS
try {
  Set-MpPreference -AttackSurfaceReductionRules_Ids '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' `
                   -AttackSurfaceReductionRules_Actions Enabled
  $results['ASR_LSASS'] = 'Enabled (Block)'
} catch { $results['ASR_LSASS'] = "Failed: $_" }

# Output for log capture / RMM writeback
$results.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Value)" }
```

## Appendix B — References

- MITRE ATT&CK T1003.001 — https://attack.mitre.org/techniques/T1003/001/
- CIS Microsoft Windows 10 Enterprise Benchmark v2.0 (controls cited in §4)
- MS Security Baselines — https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- Microsoft "Configure additional LSA protection" — https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

---

# Template structure (summary)

When you generate Mode 2 output:

1. Executive Summary (use `exec_summary.md` template)
2. Technical Detail with these sections in order:
   - Threat & Observed Evidence
   - MITRE Technique Mapping
   - Current State Assessment
   - Recommended Controls (tiered: Immediate / Short-term / Long-term)
   - Verification Plan
   - Rollback Procedures
   - Detection Pairing
3. Appendices: deployment script, references

**Length:** Technical Detail is as long as it needs to be. Anchor on covering each recommended control with the same shape (Rationale / Framework / Configuration / PS / Validation / Compatibility).

**File format:** Use the `docx` skill. Read its SKILL.md before building. Use Heading 1 for top-level sections, Heading 2 for subsections, code-block style for PS/registry. Generate a working table of contents from headings