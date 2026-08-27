# Microsoft Security Baselines Reference

Microsoft Security Baselines are the *exact GPO settings Microsoft recommends* for hardening Windows, Edge, Office, and M365 Apps. They're shipped via the Microsoft Security Compliance Toolkit (SCT) as GPO backups you can import directly into AD, or as Intune-importable JSON.

This file gives you the most-cited GPO paths and registry keys, organized by attack surface. Use it when you need the *exact* place an analyst or sysadmin will click to apply a control.

**Tooling:**
- SCT (the official tool): https://www.microsoft.com/en-us/download/details.aspx?id=55319
- Baselines for current OS: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines

---

## Credential / authentication hardening

### Disable WDigest (stops clear-text password caching in LSASS)

**GPO path:**
`Computer Configuration > Administrative Templates > MS Security Guide > WDigest Authentication`
Set: `Disabled`

**Registry (direct):**
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
- Value: `UseLogonCredential`
- Type: `REG_DWORD`
- Data: `0` (or absent = effectively disabled on supported builds)

**PowerShell to set:**
```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
New-ItemProperty -Path $path -Name 'UseLogonCredential' -Value 0 -PropertyType DWORD -Force | Out-Null
```

**Verify:**
```powershell
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
# Expect: 0 (or null)
```

---

### LSA Protection (RunAsPPL — makes LSASS a Protected Process)

**GPO path:**
`Computer Configuration > Administrative Templates > MS Security Guide > LSA Protection`
Set: `Enabled`

**Registry:**
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
- Value: `RunAsPPL`
- Type: `REG_DWORD`
- Data: `1` (basic) or `2` (UEFI-locked, recommended)

**PowerShell:**
```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
New-ItemProperty -Path $path -Name 'RunAsPPL' -Value 2 -PropertyType DWORD -Force | Out-Null
# Reboot required
```

**Verify:**
```powershell
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL).RunAsPPL
# Event ID 12: "LSASS was started as a protected process" should appear in System log post-reboot
```

---

### Credential Guard (virtualization-based LSASS isolation)

**Requirements:** Windows 10/11 Enterprise or Server 2016+, UEFI, Secure Boot, TPM 2.0, VBS-capable CPU.

**GPO path:**
`Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security`
- Set: `Enabled`
- "Select Platform Security Level": `Secure Boot and DMA Protection`
- "Credential Guard Configuration": `Enabled with UEFI lock`

**Registry:**
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`
- Value: `EnableVirtualizationBasedSecurity` (REG_DWORD = 1)
- Value: `RequirePlatformSecurityFeatures` (REG_DWORD = 3 = Secure Boot + DMA)
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
- Value: `LsaCfgFlags` (REG_DWORD = 1 = enabled with UEFI lock)

**Compatibility risk:** Breaks software that hooks LSASS — some legacy SSO products, older McAfee Endpoint Security, certain RDP plugins. **Pilot before fleet rollout.**

**Verify:**
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning, VirtualizationBasedSecurityStatus
# SecurityServicesRunning should include 1 (Credential Guard)
# VirtualizationBasedSecurityStatus should be 2 (running)
```

---

## Execution prevention

### Attack Surface Reduction (ASR) rules — high-leverage subset

ASR rules are GUID-identified policies that block specific behaviors. Deploy in `AuditMode` first (Defender Event ID 1122), confirm no legitimate workflow trips, then flip to `Enabled (Block)` (Event ID 1121).

**GPO path:**
`Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules`

**PowerShell (per-rule):**
```powershell
# Block credential stealing from LSASS
Set-MpPreference -AttackSurfaceReductionRules_Ids '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' `
                 -AttackSurfaceReductionRules_Actions Enabled
```

**The 12 rules worth knowing by heart:**

| GUID | Rule | Mitigates |
|---|---|---|
| `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550` | Block executable content from email client and webmail | T1566.001 |
| `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` | Block all Office apps from creating child processes | T1204.002 |
| `3B576869-A4EC-4529-8536-B80A7769E899` | Block Office apps from creating executable content | T1566 |
| `75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84` | Block Office apps from injecting code into other processes | T1055 |
| `D3E037E1-3EB8-44C8-A917-57927947596D` | Block JavaScript/VBScript from launching downloaded executable | T1059.007 |
| `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` | Block execution of potentially obfuscated scripts | T1027 |
| `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B` | Block Win32 API calls from Office macros | T1059.005 |
| `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2` | Block credential stealing from LSASS (lsass.exe) | T1003.001 |
| `D1E49AAC-8F56-4280-B9BA-993A6D77406C` | Block process creations originating from PsExec/WMI commands | T1047, T1569 |
| `B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4` | Block untrusted/unsigned processes from USB | T1091 |
| `26190899-1602-49E8-8B27-EB1D0A1CE869` | Block Office comm apps (Outlook) from creating child processes | T1204 |
| `7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C` | Block Adobe Reader from creating child processes | T1204 |
| `E6DB77E5-3DF2-4CF1-B95A-636979351E5B` | Block persistence through WMI event subscription | T1546.003 |

Full ASR rule list with descriptions:
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference

---

### PowerShell hardening

**Disable PowerShell v2** (it bypasses ScriptBlock/Module logging — attackers love it):

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
```

**Enable ScriptBlock logging:**

**GPO:** `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging` → `Enabled`

**Registry:**
- Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
- Value: `EnableScriptBlockLogging` (REG_DWORD = 1)

Logs land in `Microsoft-Windows-PowerShell/Operational` Event ID 4104.

**Enable Module logging:**

**GPO:** `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging` → `Enabled`, modules = `*`

---

## SMB / lateral movement

### Disable SMBv1 (client + server)

```powershell
# Server side
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# Client side (Windows feature)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
```

**Verify:**
```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### Require SMB signing

**GPO:**
`Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`
- `Microsoft network client: Digitally sign communications (always)` → `Enabled`
- `Microsoft network server: Digitally sign communications (always)` → `Enabled`

---

## Office macro hardening

**GPO (per Office version, e.g., Office 2016+):**
`User Configuration > Administrative Templates > Microsoft <App> > <App> Options > Security > Trust Center`
- `Block macros from running in Office files from the Internet` → `Enabled`
- `VBA Macro Notification Settings` → `Disable all except digitally signed macros`

Apply to: Word, Excel, PowerPoint, Outlook, Access, Project, Publisher, Visio. Don't forget Outlook — Outlook macros are often overlooked.

---

## How to use this file

When recommending a Windows-specific control:

1. Find the setting in the section above (credential / execution / SMB / etc.)
2. Cite the GPO path **and** the registry key when both apply — different sysadmins prefer different deploy paths
3. Always include the verify command — controls that can't be verified are controls that won't stick

If a setting isn't here, fall back to:
- Microsoft Security Baseline downloads (SCT) for the exact recommended value
- `gpresult /h report.html` on a configured machine to find the exact path

Never invent registry keys or GPO paths — wrong paths produce hardening that *looks* applied but does nothing.
