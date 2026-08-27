# Common TTPs — Pre-Built Hardening Packages

This file contains worked hardening packages for the TTPs that show up most often in hunt findings. Use these as starting points — copy the structure and customize for the user's specific evidence.

Each entry has:
- **TTP / technique**
- **What attackers do** (one paragraph, plain language)
- **Immediate controls** (deploy this week)
- **Short-term controls** (1–4 weeks, may need piloting)
- **Long-term controls** (1–3 months, structural)
- **Verification queries** (CQL spot-checks where applicable)

---

## T1003.001 — LSASS Memory Access (credential dumping)

**What attackers do:** After landing on an endpoint with local admin, attackers read the memory of `lsass.exe` to extract password hashes, Kerberos tickets, and cleartext passwords for any session ever logged onto the box. Mimikatz, ProcDump, comsvcs.dll MiniDump, and many newer in-memory tools do this. Stolen credentials enable lateral movement, often as a domain admin or service account.

### Immediate
- **Disable WDigest credential caching.** Removes cleartext passwords from LSASS. MITRE M1027, CIS 18.3.6, MS Baseline `MS Security Guide > WDigest Authentication = Disabled`.
- **Enable LSA Protection (RunAsPPL).** Makes LSASS a Protected Process so unprivileged code can't read its memory. MITRE M1025, CIS 18.9.27.1.1, MS Baseline `MS Security Guide > LSA Protection = Enabled`.
- **Enable ASR rule `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2`** (Block credential stealing from LSASS). MITRE M1040.
- **Set CrowdStrike Falcon prevention policy: Suspicious Process Block = ENABLED.** This catches the in-the-wild LSASS dumping techniques even when the previous controls are bypassed.

### Short-term
- **Roll out Credential Guard** to all Windows 10/11 Enterprise endpoints. Isolates LSASS in a VBS container — even SYSTEM can't read the credentials. MITRE M1025, CIS 18.9.45.5.1, MS Baseline `System > Device Guard > Turn On VBS = Enabled with UEFI lock`. **Pilot first** — known to break legacy SSO and some EDR plugins.
- **Add affected accounts to Protected Users group.** Forces Kerberos-only auth, disables NTLM/Digest/CredSSP for them, and prevents credential caching. MITRE M1015. Don't put service accounts in this group — it'll break them.

### Long-term
- **Tier-0 isolation.** Domain admins should never log onto user workstations. Implement tiered admin (T0/T1/T2) with separate PAWs and conditional access policies preventing cross-tier logons. MITRE M1026, M1030.
- **Phase out password-based admin** in favor of LAPS (random per-machine local-admin passwords) and certificate-/FIDO2-based admin auth. MITRE M1018, M1032.

### Verify
```powershell
# WDigest disabled
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
# Expect: 0 or null

# RunAsPPL set
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
# Expect: 1 or 2 (2 = UEFI-locked, preferred)

# Credential Guard running
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
# Expect: includes 1
```

**Falcon CQL spot-check for ongoing LSASS access attempts:**
```
#event_simpleName=ProcessRollup2
| TargetProcessName=/lsass\.exe$/i
| !ImageFileName=/(MsMpEng|csagent|svchost)\.exe$/i
| groupBy([ComputerName, ImageFileName, CommandLine])
```

---

## T1558.003 — Kerberoasting

**What attackers do:** Any authenticated user can request Kerberos service tickets (TGS-REQ) for accounts with a Service Principal Name (SPN). The returned tickets are encrypted with the service account's password hash, which attackers extract and crack offline. Weak service-account passwords (the kind humans pick) crack in minutes; strong ones (≥25 random chars) effectively don't.

### Immediate
- **Audit current SPNs on highly privileged accounts.** Any SPN on a domain admin, enterprise admin, or AdminSDHolder-protected account is a critical finding. Remove them or move the function to a dedicated unprivileged account.
- **Enable Kerberos pre-authentication on all accounts.** Accounts with "Do not require Kerberos pre-authentication" can be AS-REProasted (worse than Kerberoasting because no auth needed at all). MITRE M1015.

### Short-term
- **Rotate weak service-account passwords to 25+ random characters.** No dictionary words, no patterns, no shared passwords across services. The math: at 25 random chars, AES256 ticket cracking is computationally infeasible. MITRE M1027.
- **Migrate eligible services to Group Managed Service Accounts (gMSAs).** gMSAs use 120-character auto-rotated passwords — impossible to crack. Eligible: anything running on Windows Server 2012+ that supports gMSA (most modern apps; some legacy don't). MITRE M1015, M1026.

### Long-term
- **Implement AD tiering** so service accounts can't authenticate outside their tier. MITRE M1015, M1030.
- **Detection: monitor for high-volume TGS-REQ from a single user** (Event ID 4769 spike), especially for RC4 ticket requests (downgrade attack). This complements the hardening — pair with a `threat-hunter` follow-up.

### Verify
```powershell
# Find SPNs on privileged accounts (run on DC)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, MemberOf |
  Where-Object { $_.MemberOf -match 'Domain Admins|Enterprise Admins|Schema Admins' } |
  Select-Object SamAccountName, ServicePrincipalName, MemberOf

# Find accounts with "Do not require pre-authentication"
Get-ADUser -Filter * -Properties DoesNotRequirePreAuth |
  Where-Object { $_.DoesNotRequirePreAuth -eq $true } |
  Select-Object SamAccountName
# Expect: empty (or only documented legacy exceptions)
```

---

## T1566.001 — Phishing Attachment

**What attackers do:** Email with a malicious attachment (macro doc, ISO/IMG with shortcut, HTML smuggling, OneNote attachment, password-protected ZIP) lands in a user inbox. User opens, macro/script executes, and the attacker has a foothold. Modern campaigns favor ISO/IMG and HTML smuggling because they bypass Mark-of-the-Web.

### Immediate
- **Enable ASR rule `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550`** (Block executable content from email and webmail). MITRE M1040.
- **Enable ASR rule `D4F940AB-401B-4EFC-AADC-AD5F3C50688A`** (Block all Office apps from creating child processes). Catches the macro → cmd → payload pattern. MITRE M1040.
- **Block macros from running in Office files from the Internet** (GPO `Block macros from running in Office files from the Internet = Enabled`). Microsoft already enables this by default on Microsoft 365 Apps but verify it's enforced for any Office 2019/perpetual installs. MITRE M1054.
- **Block ISO/IMG mounting for standard users.** Set `HKCU\Software\Classes\Windows.IsoFile` and `Windows.VhdFile` to not have a default Open action, or use AppLocker to block `vds.exe` invocation by user-launched processes.

### Short-term
- **Deploy Defender for Office 365 Safe Attachments + Safe Links** (or equivalent: Proofpoint TAP, Mimecast Attachment Protect). Detonate attachments in a sandbox before delivery. MITRE M1031.
- **Phishing-resistant attachment policies in M365**: block password-protected zips at the mail gateway (they bypass scanning), block executable file types as attachments (`.exe`, `.js`, `.vbs`, `.ps1`, `.hta`, `.iso`, `.img`, `.lnk`).
- **Enable Mark-of-the-Web propagation** so files extracted from ZIPs inherit MOTW. Modern Windows does this by default but legacy apps (older 7-Zip) don't.

### Long-term
- **Phishing-resistant user training** with periodic simulated phishing campaigns (KnowBe4, Hoxhunt, Microsoft Attack Simulator). MITRE M1017. Measure click-through over time; aim for <2%.
- **Move to phishing-resistant MFA (FIDO2 hardware keys)** for any user with elevated access. Eliminates the credential-theft payoff even if a payload runs. MITRE M1032.

### Verify
```powershell
# ASR rule status
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
# Look for BE9BA2D9... and D4F940AB... at action 1 (Block)

# Office macro policy (per app)
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Word\Security' -Name 'BlockContentExecutionFromInternet' -ErrorAction SilentlyContinue
# Expect: 1
```

---

## T1218 — Signed Binary Proxy Execution (LOLBins)

**What attackers do:** Run malicious code via legitimate signed Microsoft binaries to evade AV/EDR detection that focuses on unsigned executables. Common LOLBins: `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `installutil.exe`, `msbuild.exe`, `wmic.exe`.

### Immediate
- **Disable `mshta.exe` for standard users** via AppLocker path rule (or remove the file association for `.hta`). Mshta has near-zero legitimate enterprise use. MITRE M1042.
- **Enable ASR rule `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC`** (Block execution of potentially obfuscated scripts). MITRE M1040.
- **Enable PowerShell ScriptBlock logging** (Event ID 4104) — doesn't prevent, but every LOLBin chain ends in script execution, and this gives you forensic visibility. CIS 18.9.100.2.

### Short-term
- **Deploy AppLocker or WDAC in audit mode** on a pilot group covering the top LOLBins (`mshta`, `regsvr32`, `rundll32` when invoked by user processes). Move to enforce mode after 30 days of auditing.
- **Block `bitsadmin.exe` and `certutil.exe` for non-admin users** — both have legitimate IT uses but should never be invoked by a standard user.

### Long-term
- **Full WDAC code integrity policy** in audit-then-enforce mode. The gold standard for execution prevention — only signed and approved binaries can run. MITRE M1045. High effort, high payoff. Pilot on knowledge-worker tier first; servers second.

### Verify
```powershell
# AppLocker policy effective
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# WDAC policy active
CiTool.exe -lp
```

---

## T1486 — Data Encrypted for Impact (Ransomware)

**What attackers do:** Encrypt files on disk and demand ransom. Modern groups also exfiltrate first (double extortion) and often go for shadow copies, online backups, and AD/VMware infrastructure before encryption to maximize leverage.

### Immediate
- **Set CrowdStrike Falcon prevention policies to BLOCK** for: Suspicious Process, Custom IOA Rule Action = Block, Ransomware Detection, Adversary Activity. MITRE M1040.
- **Enable ASR rule `C1DB55AB-C21A-4637-BB3F-A12568109D35`** (Use advanced protection against ransomware). MITRE M1040.
- **Enable Controlled Folder Access** in Defender, with protected folders covering user profiles, shared file servers, and known backup locations. MITRE M1040.

### Short-term
- **Verify backups are immutable and offline.** Online-only backups get encrypted right alongside production. Use cloud immutable storage (S3 Object Lock, Azure Blob immutability) or air-gapped tape rotation. MITRE M1053.
- **Test restore procedures quarterly.** Backups that can't actually restore are not backups. Time the full-environment restore — that's your RTO.
- **Restrict access to backup infrastructure** behind separate credentials, MFA, and network segmentation. The backup admin should not be the same person/account as the AD admin.

### Long-term
- **Network segmentation between user, server, backup, and AD tiers.** Limits blast radius. MITRE M1030.
- **EDR-in-block-mode on servers (especially file servers and DCs).** Many ransomware operators specifically avoid blocking-mode EDR — confirming it's on is a strong deterrent. MITRE M1040.

### Verify
```powershell
# Controlled Folder Access state
(Get-MpPreference).EnableControlledFolderAccess
# Expect: 1 (Enabled) or 2 (Audit)

# Falcon policy (requires Falcon API or Console UI check — no native PS)
```

---

## How to use this file

When a hunt finding maps to one of these TTPs, **start from the package above** and customize:

1. Pull the relevant Immediate/Short-term/Long-term blocks
2. Trim controls the user already has in place (ask if you're not sure)
3. Add environment-specific context (e.g., "Since you mentioned VMware, also enforce vCenter MFA per [T1486 specifics]")
4. Always include the Verify section — adapt to what's measurable in the user's environment

If the TTP isn't here, build the package from `mitre_mitigations.md` → `cis_lookup.md` → `ms_baselines.md` in that order: technique → mitigation IDs → concrete settings.
