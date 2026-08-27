# Deployable Playbook Template — Worked Example

This is what Mode 3 output should look like. The user is going to deploy this. Every snippet must be working, copy-paste-runnable PowerShell or a precise GPO/registry change. Don't pseudocode.

---

# Hardening Playbook: LSASS Credential Theft Prevention (T1003.001)

**MITRE:** T1003.001 (OS Credential Dumping: LSASS Memory) → M1025, M1027, M1040, M1043
**Estimated deploy time:** 1–2 hours (Immediate tier), 1 day per pilot ring (Credential Guard)
**Prerequisites:** Windows 10 1809+ / Server 2019+, Defender enabled (passive or active), local admin on target endpoints
**Reboot required:** Yes (RunAsPPL takes effect at reboot; Credential Guard requires reboot)

---

## Step 1 — Disable WDigest credential caching

**What it does:** Removes cleartext passwords from LSASS memory.
**Why it works:** Even if LSASS is dumped successfully, the attacker gets hashes (slower to use, easier to detect) instead of cleartext.

**PowerShell:**
```powershell
# Disable WDigest UseLogonCredential — removes cleartext password caching in LSASS
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
New-ItemProperty -Path $path -Name 'UseLogonCredential' -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Output "WDigest UseLogonCredential set to 0"
```

**GPO path:**
`Computer Configuration > Administrative Templates > MS Security Guide > WDigest Authentication`
Set: `Disabled`

**Registry key:**
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
- Value: `UseLogonCredential`
- Type: `REG_DWORD`
- Data: `0`

**Verify:**
```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential -EA SilentlyContinue).UseLogonCredential
# Expect: 0 (or null = effectively disabled)
```

**Rollback:**
```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 1
# Reboot to take effect
```

---

## Step 2 — Enable LSA Protection (RunAsPPL)

**What it does:** Marks LSASS as a Protected Process.
**Why it works:** Unprivileged code (and even much privileged code without the right signing) cannot open a process handle to a Protected Process. Mimikatz-style memory reads fail.

**PowerShell:**
```powershell
# Enable LSA Protection. Value 2 = UEFI-locked (preferred — survives offline tampering).
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
New-ItemProperty -Path $path -Name 'RunAsPPL' -Value 2 -PropertyType DWORD -Force | Out-Null
Write-Output "RunAsPPL set to 2. REBOOT REQUIRED."
```

**GPO path:**
`Computer Configuration > Administrative Templates > MS Security Guide > LSA Protection`
Set: `Enabled`

**Registry key:**
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
- Value: `RunAsPPL`
- Type: `REG_DWORD`
- Data: `2` (UEFI-locked) — use `1` only if endpoints lack UEFI

**Verify (after reboot):**
```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL).RunAsPPL
# Expect: 1 or 2

# Also check the boot event:
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=12 and Provider[@Name='Wininit']]]" -MaxEvents 1 |
  Select-Object TimeCreated, Message
# Look for: "LSASS.exe was started as a protected process with level: 4"
```

**Rollback:**
```powershell
Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL
# Reboot. If RunAsPPL was set to 2 (UEFI-locked), you must also clear the UEFI variable —
# Microsoft documents the procedure here: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
```

**Compatibility note:** Some legacy security agents (older McAfee Endpoint Security plugins, certain SSO tools that hook LSASS) will fail to load after RunAsPPL is enabled. Pilot on 5–10 endpoints first; check Event ID 3033 in `Microsoft-Windows-CodeIntegrity/Operational` for blocked plugin loads.

---

## Step 3 — Enable ASR rule: Block credential stealing from LSASS

**What it does:** Defender blocks attempts to read LSASS memory by processes that don't match its allowlist.
**Why it works:** Layer of defense independent of LSASS itself — even if an attacker has admin and bypasses RunAsPPL, the ASR rule still catches the read attempt.

**PowerShell:**
```powershell
# Enable ASR: Block credential stealing from LSASS (in Block mode, not Audit)
$asrRule = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'
Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRule `
                 -AttackSurfaceReductionRules_Actions Enabled
Write-Output "ASR rule $asrRule set to Enabled (Block)"
```

**GPO path:**
`Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules`
- Add value name: `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2`
- Value data: `1` (Block) — use `2` for Audit during pilot

**Verify:**
```powershell
$ids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$actions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
for ($i = 0; $i -lt $ids.Count; $i++) {
  if ($ids[$i] -eq '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2') {
    "ASR rule action: $($actions[$i]) (1=Block, 2=Audit, 6=WarnUser)"
  }
}
```

**Monitor for false positives:** Event ID 1121 (Block) and 1122 (Audit) in `Microsoft-Windows-Windows Defender/Operational`. If a legitimate tool trips it (rare — usually only specific endpoint backup tools), add an exclusion:
```powershell
Add-MpPreference -AttackSurfaceReductionOnlyExclusions 'C:\Program Files\YourTool\tool.exe'
```

**Rollback:**
```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' `
                 -AttackSurfaceReductionRules_Actions Disabled
```

---

## Step 4 — Confirm Falcon prevention policy

**What it does:** CrowdStrike's runtime behavioral prevention catches LSASS access patterns the static controls above don't cover.
**Why it works:** ML and indicator-of-attack (IOA) detection sees the *behavior* (e.g., `comsvcs.dll` minidump trick, in-memory PPLdump), not just process names — so it catches techniques that evade static rules.

**Not a script — Falcon Console UI:**

1. Falcon Console → Endpoint security → Prevention policies
2. For each policy applied to workstations and servers:
   - **Sensor visibility:** all toggles ON
   - **Cloud machine learning** → Detection: Aggressive; Prevention: Moderate (or Aggressive if false positives are tolerable)
   - **Suspicious processes:** ON (Block)
   - **Custom blocking → Suspicious Registry Operations:** ON (Block)
   - **Adversary Activity → Credential Dumping:** ON (Block)
   - **Tampering Protection:** ON

**Verify (from a target endpoint):**
```powershell
# Falcon agent installed and running
Get-Service CSFalconService | Select-Object Name, Status
# Status: Running

# Sensor version (some IOAs need recent sensor)
& "$env:ProgramFiles\CrowdStrike\CSSensorSettings.exe" --version
```

**Verify from Falcon Console:**
- Endpoint security → Activity → Search for `TargetProcessName:lsass.exe` over the last 24 hours
- Confirm a recent "Prevention triggered" or "Suspicious activity blocked" event from your test source

---

## Step 5 (Short-term / Pilot tier) — Credential Guard

**What it does:** Isolates LSASS in a virtualization-based security (VBS) container. Even kernel-mode malware cannot read it.
**Why it works:** The credentials live in a separate VM-level partition that the main OS cannot see at all.

**Prerequisites:** UEFI, Secure Boot, TPM 2.0, VBS-capable CPU, Windows 10/11 Enterprise or Education. **Run on a pilot ring first — known to break some legacy applications.**

**PowerShell:**
```powershell
# Enable VBS + Credential Guard with UEFI lock
$dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
New-ItemProperty -Path $dg -Name 'EnableVirtualizationBasedSecurity' -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $dg -Name 'RequirePlatformSecurityFeatures' -Value 3 -PropertyType DWORD -Force | Out-Null  # 3 = Secure Boot + DMA

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
New-ItemProperty -Path $lsa -Name 'LsaCfgFlags' -Value 1 -PropertyType DWORD -Force | Out-Null  # 1 = Enabled with UEFI lock

Write-Output "Credential Guard configured. REBOOT REQUIRED."
```

**GPO path:**
`Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security`
- Enabled
- Select Platform Security Level: `Secure Boot and DMA Protection`
- Credential Guard Configuration: `Enabled with UEFI lock`

**Verify (after reboot):**
```powershell
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$dg | Select-Object @{n='VBS';e={$_.VirtualizationBasedSecurityStatus}}, @{n='CredGuard';e={$_.SecurityServicesRunning -contains 1}}
# Expect: VBS=2 (running), CredGuard=True
```

**Rollback (UEFI-locked is intentionally hard to undo — that's the point):**
1. GPO: set Credential Guard Configuration → `Disabled`
2. PowerShell on the endpoint: `bcdedit /set hypervisorlaunchtype off` (elevated)
3. Reboot. After boot, Windows will prompt for a UEFI password to clear the Credential Guard lock. Confirm.
4. Reboot again to complete removal.

---

## Deploying via your RMM

The scripts above are raw PowerShell. To wrap them for RMM fleet deployment (admin check, error handling, custom-field writeback for compliance tracking, scheduled re-verification), hand them to your RMM deployment tooling and ask for a deployable package.

Suggested RMM custom field schema for this hardening package:
- `Hardening_LSASS_WDigest` — text — "Disabled" / "Enabled" / "Unknown"
- `Hardening_LSASS_RunAsPPL` — text — "0" / "1" / "2" / "Unknown"
- `Hardening_LSASS_ASR` — text — "Block" / "Audit" / "Disabled" / "Unknown"
- `Hardening_LSASS_CredGuard` — text — "Running" / "Configured" / "Not Deployed"
- `Hardening_LSASS_LastChecked` — date — last verification run

---

# Template structure

When you generate Mode 3 output:

```markdown
# Hardening Playbook: [TTP / Technique Name]

**MITRE:** TXXXX.XXX → M-num(s)
**Estimated deploy time:** [X hours]
**Prerequisites:** [...]
**Reboot required:** [Yes / No / per setting]

## Step 1 — [Control name]
**What it does:** [1 line]
**Why it works:** [1–2 lines]

**PowerShell:** [working code block]
**GPO path:** [...]
**Registry:** [key/value/type/data]
**Verify:** [working code block]
**Rollback:** [working code block or steps]

## Step 2 — ...

---

## Deploying via your RMM
[Standard footer — chain to your RMM deployment tooling]
```

**Critical:** Every PowerShell block must be syntactically valid and runnable as-is. Test in your head or in a scratchpad before emitting. Hardening that "looks right" but doesn't run is worse than no hardening — it produces false confidence.

**Critical:** Always include rollback. Always.
