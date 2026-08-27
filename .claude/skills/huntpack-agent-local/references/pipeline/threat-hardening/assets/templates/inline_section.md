# Inline Section Template — Worked Example

This is what Mode 1 output should look like. Use this exact structure when appending a hardening section to an existing hunt report.

---

## Hardening & Prevention

**TTP:** LSASS Memory Access via Unsigned Process
**MITRE Technique:** T1003.001 — OS Credential Dumping: LSASS Memory
**Primary Mitigations:** M1025 (Privileged Process Integrity), M1040 (Behavior Prevention on Endpoint), M1043 (Credential Access Protection), M1027 (Password Policies)

### Immediate (deploy this week)

- **Disable WDigest credential caching.** Removes cleartext passwords from LSASS so even successful dumps yield less material to crack. Framework: MITRE M1027, CIS Windows 10 18.3.6 (L1), MS Baseline `Computer Configuration > Administrative Templates > MS Security Guide > WDigest Authentication = Disabled`.
- **Enable LSA Protection (RunAsPPL).** Marks LSASS as a Protected Process so unprivileged code can't open a memory handle to it. Framework: MITRE M1025, CIS 18.9.27.1.1 (L1), MS Baseline `MS Security Guide > LSA Protection = Enabled`.
- **Enable ASR rule `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2`** (Block credential stealing from LSASS) in Block mode. Defender will refuse memory access from non-allowlisted processes. Framework: MITRE M1040.
- **Confirm CrowdStrike Falcon Suspicious Process Block is set to ENABLED.** Catches the runtime LSASS access patterns that bypass the controls above. Framework: MITRE M1040.

### Short-term (1–4 weeks)

- **Pilot Credential Guard** on a 5–10 endpoint ring. Isolates LSASS in a VBS container — even SYSTEM cannot read it. Framework: MITRE M1025, CIS 18.9.45.5.1 (L1), MS Baseline `System > Device Guard > Turn On VBS = Enabled with UEFI lock`. **Compatibility note:** known to break legacy SSO products and some older endpoint security agents. Document any apps that break and decide before fleet rollout.
- **Add domain admins and tier-0 service accounts to the Protected Users group.** Forces Kerberos-only auth, disables credential caching, blocks NTLM/Digest/CredSSP. Framework: MITRE M1015. **Do not** add standard service accounts — it will break them.

### Long-term / structural (1–3 months)

- **Implement tiered admin (T0/T1/T2) with logon restrictions.** Domain admins should never authenticate to user workstations. This is the structural fix that makes a single LSASS dump non-catastrophic. Framework: MITRE M1026, M1030.
- **Roll out LAPS to all domain-joined endpoints.** Random per-machine local-admin password kills lateral movement via reused local admin credentials. Framework: MITRE M1018.

### What to verify after deployment

- **WDigest disabled** on a sample of endpoints:
  ```powershell
  (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential -EA SilentlyContinue).UseLogonCredential
  # Expect: 0 or null
  ```
- **RunAsPPL set** on a sample of endpoints:
  ```powershell
  (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL).RunAsPPL
  # Expect: 1 (basic) or 2 (UEFI-locked, preferred)
  ```
- **ASR rule in Block mode (not Audit):**
  ```powershell
  $i = (Get-MpPreference).AttackSurfaceReductionRules_Ids
  $a = (Get-MpPreference).AttackSurfaceReductionRules_Actions
  for ($n=0; $n -lt $i.Count; $n++) { if ($i[$n] -eq '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2') { "Action: $($a[$n])" } }
  # Expect: 1 (Block). 2 = Audit only, not enforcing.
  ```
- **Falcon spot-check** that LSASS access from unsigned processes drops to zero over 14 days post-deployment:
  ```
  #event_simpleName=ProcessRollup2
  | TargetProcessName=/lsass\.exe$/i
  | !ImageFileName=/(MsMpEng|csagent|svchost|services|wininit)\.exe$/i
  | groupBy([ComputerName, ImageFileName])
  ```

---

# Template structure

Use the example above as the shape. The skeleton:

```markdown
## Hardening & Prevention

**TTP:** [name from parent report]
**MITRE Technique:** [TXXXX.XXX — Name]
**Primary Mitigations:** [M-numbers]

### Immediate (deploy this week)
- [Control] — [rationale]. Framework: [citations].

### Short-term (1–4 weeks)
- ...

### Long-term / structural (1–3 months)
- ...

### What to verify after deployment
- [Measurable check, ideally a PS one-liner or CQL query]
```

**Length:** Aim for 250–500 words. This section drops into an existing report; it should not become the report.

**Tone:** Match the parent report. If the parent is an analyst-to-analyst email, write tight and technical. If the parent is a management writeup, lighten the jargon (but don't strip the framework citations — those are the trust-builders).
