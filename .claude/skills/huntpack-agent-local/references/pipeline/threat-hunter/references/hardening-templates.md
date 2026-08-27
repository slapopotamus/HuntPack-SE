# Endpoint Hardening Templates

Pre-built hardening recommendations organized by attack category. Each entry includes the specific GPO path, registry key, or Intune setting — not just the concept.

When recommending hardening actions in Phase 3 Output 3, pull the relevant sections from here and classify each recommendation using the Phase 4 risk tiers (Low / Medium / High risk to deploy).

---

## How to Use This Reference

1. Match the attack technique to the relevant category
2. Copy the specific setting name, path, and value
3. Classify the deployment risk using the Phase 4 risk tier system
4. Group into "Immediate" (specific to the threat) and "Strategic" (broader attack surface reduction)

---

## Category 1: PowerShell Hardening

Relevant for: T1059.001, T1086, macro-based delivery, post-exploitation tooling

### ScriptBlock Logging (detects obfuscated/encoded scripts)
- **GPO Path:** `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell`
- **Setting:** `Turn on PowerShell Script Block Logging` → **Enabled**
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` → `EnableScriptBlockLogging = 1` (DWORD)
- **Risk:** Low — read-only logging; no operational impact
- **Note:** Enable `Log script block invocation start/stop events` as well for full coverage

### Module Logging (logs all pipeline execution)
- **GPO Path:** Same as above
- **Setting:** `Turn on Module Logging` → **Enabled**; Module Names: `*`
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` → `EnableModuleLogging = 1` (DWORD); `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames` → `* = *` (String)
- **Risk:** Low — generates significant log volume; ensure SIEM/log collection is sized appropriately

### PowerShell Transcription (full session recording)
- **GPO Path:** Same as above
- **Setting:** `Turn on PowerShell Transcription` → **Enabled**; Output Directory: `[specify secure log path]`
- **Risk:** Low — creates transcript files on disk; ensure output directory is protected (non-admin write)

### Constrained Language Mode (restricts PowerShell capabilities)
- **Method:** Set via Windows Defender Application Control (WDAC) policy or manually via:
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` → `__PSLockdownPolicy = 4` (String)
- **Risk:** Medium — breaks many legitimate PowerShell scripts and management tools; test thoroughly in pilot before broad deployment
- **Verify:** `$ExecutionContext.SessionState.LanguageMode` should return `ConstrainedLanguage`

### Execution Policy (weakest control — defense-in-depth only)
- **GPO Path:** `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on Script Execution`
- **Setting:** `Allow only signed scripts` or `Allow local scripts and remote signed scripts`
- **Note:** Execution policy is not a security boundary — `powershell.exe -ExecutionPolicy Bypass` trivially bypasses it. Enable logging controls above instead of relying on execution policy.

---

## Category 2: Office Macro Controls

Relevant for: T1566.001, T1204.002, document-based initial access

### Block Macros from Internet-Sourced Documents (MOTW-based)
- **GPO Path:** `User Configuration → Administrative Templates → Microsoft Office [version] → Security Settings → Trust Center`
  - Per-app paths: `...Microsoft Word 2016\Security\Trust Center`, `...Microsoft Excel 2016\Security\Trust Center`
- **Setting:** `Block macros from running in Office files from the Internet` → **Enabled**
- **Registry (per-app, example for Word):** `HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security` → `blockcontentexecutionfrominternet = 1` (DWORD)
- **Risk:** Low-Medium — blocks macros in files downloaded from the internet (MOTW set); minimal impact on internal macro-enabled files from network shares without MOTW

### Disable All Macros with Notification
- **GPO Path:** Per-app `Trust Center → Macro Settings`
- **Setting:** `Disable all macros with notification` (VBAWarnings = 2) — users see a prompt but cannot enable
- **Registry (Word example):** `HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security` → `VBAWarnings = 2` (DWORD)
- **Risk:** Medium — breaks workflows that depend on user-enabled macros; requires change management communication

### Disable All Macros Without Exception (maximum restriction)
- **Registry:** `VBAWarnings = 4`
- **Risk:** High — breaks all macro-dependent workflows; requires full inventory of macro-dependent processes before deployment

### Disable XLM (Excel 4.0) Macros
- **Registry (Excel):** `HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security` → `MacroRuntimeScanScope = 2` (DWORD) — scans all macros
- **Setting:** `HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security` → `XL4MacroSheets = 0` (DWORD) to disable XLM entirely
- **Risk:** Low — XLM macros are a legacy feature rarely needed in modern environments

---

## Category 3: Credential Protection

Relevant for: T1003.001, T1555, T1552, T1110, pass-the-hash attacks

### LSA Protection (Protect LSASS from memory reading)
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `RunAsPPL = 1` (DWORD)
- **Requires:** Reboot to take effect; drivers and plugins accessing LSASS must be WHQL-signed
- **Risk:** Medium — can break some legacy AV products and monitoring agents that are not PPL-compatible; audit LSASS-accessing software before enabling
- **Verify:** After reboot, check `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `RunAsPPL` = 1

### Credential Guard (hardware-isolated credential storage)
- **GPO Path:** `Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security`
- **Settings required:**
  - `Select Platform Security Level`: Secure Boot and DMA Protection
  - `Credential Guard Configuration`: Enabled with UEFI lock (prevents disabling without physical access)
- **Requirements:** UEFI firmware, Secure Boot, 64-bit OS, Hyper-V capable hardware
- **Risk:** Medium-High — incompatible with some virtualization solutions; breaks Kerberos unconstrained delegation; test in pilot group
- **Note:** Credential Guard prevents Mimikatz-style LSASS dumping of NTLM hashes and Kerberos tickets

### Disable WDigest Authentication (prevents plaintext password caching)
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` → `UseLogonCredential = 0` (DWORD)
- **Risk:** Low — WDigest is disabled by default on Windows 8.1+ and Server 2012 R2+; this ensures it stays disabled
- **Applies to:** Windows 7 / Server 2008 R2 where it's enabled by default

### Protected Users Security Group
- **Method:** Add high-value accounts (Domain Admins, executives, service accounts with elevated privileges) to the `Protected Users` AD security group
- **Effect:** Prevents NTLM authentication, disables DES/RC4 Kerberos encryption, prevents credential caching, limits Kerberos TGT lifetime
- **Risk:** Medium — prevents NTLM fallback which can break access to legacy systems; test each account before moving

### Disable NTLM (maximum restriction)
- **GPO Path:** `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`
- **Setting:** `Network Security: Restrict NTLM: NTLM authentication in this domain` → `Deny All`
- **Risk:** High — breaks all NTLM-dependent authentication; requires comprehensive audit of NTLM use in the environment first (use audit mode: `Network Security: Restrict NTLM: Audit NTLM authentication in this domain`)

---

## Category 4: Protocol Hardening

Relevant for: T1557 (MitM / LLMNR/NBNS poisoning), credential relay attacks, Responder-based attacks

### Disable LLMNR (Link-Local Multicast Name Resolution)
- **GPO Path:** `Computer Configuration → Administrative Templates → Network → DNS Client`
- **Setting:** `Turn off multicast name resolution` → **Enabled**
- **Risk:** Low — LLMNR is a fallback name resolution protocol; disabling it has no impact in environments with properly functioning DNS

### Disable NetBIOS over TCP/IP (NBT-NS)
- **Method:** GPO (preferred) or registry per-adapter
- **GPO:** `Computer Configuration → Preferences → Network Options` → WINS tab → `Disable NetBIOS over TCP/IP`
- **Registry (per adapter):** `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}` → `NetbiosOptions = 2` (DWORD)
- **Risk:** Low — NBT-NS is a legacy protocol; modern environments do not require it

### Disable WPAD (Web Proxy Auto-Discovery)
- **Registry:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad` → `WpadOverride = 1` (DWORD)
- **GPO:** Configure proxy settings directly rather than via auto-detection
- **Risk:** Low in environments with explicitly configured proxies; may affect environments relying on WPAD for proxy distribution

### Require SMB Signing
- **GPO Path (Server):** `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`
  - `Microsoft network server: Digitally sign communications (always)` → **Enabled**
- **GPO Path (Client):** Same location
  - `Microsoft network client: Digitally sign communications (always)` → **Enabled**
- **Risk:** Low-Medium — performance overhead on high-throughput file servers; breaks some older NAS devices that don't support SMB signing

### Disable NTLMv1
- **GPO Path:** `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`
- **Setting:** `Network security: LAN Manager authentication level` → `Send NTLMv2 response only. Refuse LM & NTLM`
- **Risk:** Low — NTLMv1 is cryptographically broken and should not be in use in any modern environment

---

## Category 5: BYOVD and Driver Controls

Relevant for: BYOVD attacks (Bring Your Own Vulnerable Driver), ransomware using driver exploits, EDR kill tooling

### Hypervisor-Protected Code Integrity (HVCI)
- **GPO Path:** `Computer Configuration → Administrative Templates → System → Device Guard`
- **Setting:** `Turn On Virtualization Based Security` → **Enabled**; `Virtualization Based Protection of Code Integrity`: Enabled with UEFI Lock
- **Risk:** High — incompatible with some older drivers; run the `HVCI compatibility check` before deployment; may cause BSODs on incompatible systems
- **Effect:** Prevents loading unsigned or revoked kernel drivers — defeats most BYOVD techniques

### Windows Defender Application Control (WDAC) — Vulnerable Driver Blocklist
- **Microsoft provides a maintained blocklist of known vulnerable drivers**
- **Apply via:** WDAC policy with the Microsoft Recommended Driver Block Rules
- **GPO:** Deploy WDAC policy via `Computer Configuration → Windows Settings → Security Settings → Application Control Policies`
- **Risk:** Medium — the Microsoft blocklist blocks known-bad drivers; custom WDAC policies block more but require full driver inventory

### Driver Signature Enforcement
- **Status:** Enabled by default on 64-bit Windows; ensure Secure Boot is enabled to prevent bypass via boot options
- **Verify:** `bcdedit /enum | findstr testsigning` — should not show `testsigning Yes`

---

## Category 6: Network Segmentation for Lateral Movement

Relevant for: T1021.001 (RDP), T1021.002 (SMB), T1047 (WMI), T1570 (lateral tool transfer)

### Block Workstation-to-Workstation SMB
- **Method:** Windows Firewall GPO
- **GPO Path:** `Computer Configuration → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security → Inbound Rules`
- **Rule:** Block TCP 445 inbound from workstation subnets (allow from server/admin subnets only)
- **Risk:** Medium — breaks peer-to-peer file sharing which is rare but present in some environments

### Restrict RDP Access
- **Firewall rule:** Allow TCP 3389 inbound only from designated jump hosts / admin subnets
- **Require NLA (Network Level Authentication):**
  - **GPO:** `Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security`
  - **Setting:** `Require use of specific security layer for remote (RDP) connections` → `SSL (TLS 1.0)`
  - **Setting:** `Require user authentication for remote connections by using NLA` → **Enabled**
- **Risk:** Low — NLA is standard practice; firewall restriction requires knowledge of admin subnets

### Disable Admin Shares (C$, ADMIN$, IPC$)
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters` → `AutoShareWks = 0` (DWORD)
- **Risk:** High — breaks legitimate admin tools (PsExec, SCCM, backup agents) that rely on admin shares; do not deploy without a full audit of admin share usage

---

## Category 7: Application Controls (LOLBin Restriction)

Relevant for: T1218 (signed binary proxy execution), T1059.005/007, T1564 (hiding artifacts)

### Block Scripting Engines via AppLocker or WDAC
Block execution of `cscript.exe`, `wscript.exe`, `mshta.exe` from user-writable paths:

**AppLocker Rule (example for wscript.exe):**
- **Rule Type:** Path Rule
- **Path:** `%OSDRIVE%\Users\*\AppData\*` → Deny for `Everyone`
- **Applies to:** Script execution from user temp/download locations

**WDAC Publisher Rule:**
- Block by hash for known LOLBin abuse patterns, or use path rules for user-writable directories

### Restrict certutil.exe (common download tool abuse)
- **AppLocker/WDAC:** Block execution of `certutil.exe` with `-urlcache` or `-decode` arguments via Custom IOA or application control policy
- **Note:** Fully blocking certutil breaks PKI operations — prefer Custom IOA detection over full block

### Attack Surface Reduction (ASR) Rules via Microsoft Defender
When Defender is deployed alongside CrowdStrike, ASR rules add behavioral controls:

| ASR Rule Name | GUID | Mode | Impact |
|---|---|---|---|
| Block Office apps from creating child processes | `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` | Block | Low |
| Block all Office applications from creating executable content | `3B576869-A4EC-4529-8536-B80A7769E899` | Block | Medium |
| Block execution of potentially obfuscated scripts | `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` | Block | Medium |
| Block credential stealing from LSASS | `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B0` | Block | Low |
| Block abuse of exploited vulnerable signed drivers | `56A863A9-875E-4185-98A7-B882C64B5CE5` | Block | Low |

**Deploy ASR rules via GPO:** `Computer Configuration → Administrative Templates → Windows Defender Antivirus → Windows Defender Exploit Guard → Attack Surface Reduction`

**Risk:** Medium — test each ASR rule in Audit mode before switching to Block; some rules break legitimate software (notably the Office child process rule breaks some PDF readers that open from Office)
