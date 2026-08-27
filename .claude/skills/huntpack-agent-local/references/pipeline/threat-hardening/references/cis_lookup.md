# CIS Benchmarks Lookup

The CIS (Center for Internet Security) Benchmarks are the most widely-accepted prescriptive config baselines. Two big things to know:

- **Levels:** Level 1 = functional baseline, almost no friction; Level 2 = stricter, may break legacy software. Default-recommend L1 unless the user has stated higher requirements.
- **Numbering:** CIS uses dotted decimal (e.g., `2.3.10.7`). The numbers are stable across benchmark versions for the same setting, so you can cite them confidently.

Full benchmarks: https://www.cisecurity.org/cis-benchmarks/ (requires free account; PDF download)

This file contains the **most-referenced CIS items** when responding to hunt findings — not the full benchmark.

---

## Windows 10/11 Enterprise (the big ones)

### Credential & authentication hardening

| CIS # | Setting | Level | Hunt relevance |
|---|---|---|---|
| 2.3.10.4 | Network access: Do not allow anonymous enumeration of SAM accounts | L1 | Enumeration recon |
| 2.3.10.5 | Network access: Do not allow anonymous enumeration of SAM accounts and shares | L1 | Recon |
| 2.3.10.7 | Network access: Let Everyone permissions apply to anonymous users | L1 (Disabled) | Recon |
| 2.3.11.1 | Network security: Allow Local System to use computer identity for NTLM | L1 (Enabled) | NTLM relay |
| 2.3.11.2 | Network security: Allow LocalSystem NULL session fallback | L1 (Disabled) | NTLM relay |
| 2.3.11.4 | Network security: LAN Manager authentication level | L1 (Send NTLMv2 response only. Refuse LM & NTLM) | NTLMv1 hunts |
| 2.3.11.7 | Network security: LDAP client signing requirements | L1 (Negotiate signing) | LDAPS hunts |
| 18.3.6 | WDigest Authentication (disable) | L1 | T1003 LSASS / Mimikatz |
| 18.4.1 | Apply UAC restrictions to local accounts on network logons | L1 | Lateral movement |
| 18.9.27.1.1 | LSA Protection (RunAsPPL) | L1 | T1003.001 LSASS |
| 18.9.45.5.1 | Credential Guard | L1 (Enabled with UEFI lock) | T1003, T1550.002 |

### Execution prevention

| CIS # | Setting | Level | Hunt relevance |
|---|---|---|---|
| 18.9.47.5.1.x | Windows Defender Attack Surface Reduction rules (multiple) | L1 (Block) | Office macros, LSASS access, child processes |
| 18.9.47.5.1.2 | ASR: Block credential stealing from LSASS | L1 | T1003.001 |
| 18.9.47.5.1.4 | ASR: Block Office apps from creating child processes | L1 | T1204, T1203 |
| 18.9.47.5.1.5 | ASR: Block Office apps from injecting code | L1 | T1055 |
| 18.9.47.5.1.6 | ASR: Block JS/VBS from launching downloaded content | L1 | T1059.007 |
| 18.9.47.5.1.7 | ASR: Block execution of potentially obfuscated scripts | L1 | T1027, T1059 |
| 18.9.47.5.1.8 | ASR: Block Win32 API calls from Office macros | L1 | T1059.005 |
| 18.9.47.5.1.10 | ASR: Block executable content from email | L1 | T1566.001 |
| 18.9.47.5.1.11 | ASR: Block executable files unless trust criteria met | L1 | Generic exec |
| 18.9.47.5.1.12 | ASR: Use advanced protection against ransomware | L1 | T1486 |
| 18.9.47.5.1.13 | ASR: Block process creations originating from PSExec and WMI commands | L1 | T1047, T1569 |
| 18.9.47.5.1.14 | ASR: Block untrusted and unsigned processes that run from USB | L1 | T1091 |
| 18.9.47.5.1.15 | ASR: Block Office communication apps from creating child processes | L1 | T1204 |
| 18.9.47.5.1.17 | ASR: Block Adobe Reader from creating child processes | L1 | T1204 |
| 18.9.47.5.1.18 | ASR: Block persistence through WMI event subscription | L1 | T1546.003 |

### PowerShell hardening

| CIS # | Setting | Level | Hunt relevance |
|---|---|---|---|
| 18.9.100.1 | Turn on Module Logging | L1 | T1059.001 detection |
| 18.9.100.2 | Turn on PowerShell ScriptBlock Logging | L1 | T1059.001 detection + IR |
| 18.9.100.3 | Turn on PowerShell Transcription | L2 | Forensics |
| Disable PSv2 (no CIS #, MS recommended) | `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2` | — | PSv2 bypass for logging |

### SMB & lateral movement

| CIS # | Setting | Level | Hunt relevance |
|---|---|---|---|
| 18.3.3 | Disable SMBv1 client | L1 | EternalBlue, lateral |
| 2.3.8.1 | Microsoft network client: Digitally sign communications (always) | L1 (Enabled) | NTLM relay |
| 2.3.9.1 | Microsoft network server: Digitally sign communications (always) | L1 (Enabled) | NTLM relay |
| 2.3.10.10 | Network access: Restrict anonymous access to Named Pipes and Shares | L1 (Enabled) | Recon |

### Macro & Office hardening

| Setting | Level | Hunt relevance |
|---|---|---|
| Block macros from running in Office files from the Internet (Group Policy: User Configuration > Admin Templates > Microsoft Office <ver> > Security Settings) | L1 | T1566.001 |
| VBA Macro Notification Settings = "Disable all except digitally signed macros" | L1 | T1204 |
| Block Excel 4.0 (XLM) macros | L1 | T1059.005 |

---

## Windows Server 2022 — additions over Windows 10/11

| CIS # | Setting | Level | Hunt relevance |
|---|---|---|---|
| 2.3.1.1 | Accounts: Block Microsoft accounts | L1 | Identity |
| 2.3.5.1 | Domain controller: LDAP server signing requirements | L1 (Require signing) | LDAP relay |
| 2.3.5.2 | Domain controller: Refuse machine account password changes | L1 (Disabled) | AD hygiene |
| 5.x | Service hardening (many) | L1 | Disable Print Spooler on non-print servers (PrintNightmare CVE-2021-34527) |

---

## Active Directory specific

| Setting | Level | Hunt relevance |
|---|---|---|
| LAPS deployed on all domain-joined endpoints | — | T1550.002, T1078, lateral movement |
| KRBTGT password rotated twice in last 12 months | — | Golden Ticket protection |
| Protected Users group used for tier-0 accounts | — | T1003.001, T1550 |
| AdminSDHolder ACL audit (no unexpected entries) | — | T1098 |
| No SPNs on tier-0 accounts (KrbtGT, krbtgt-*, domain admins) | — | T1558.003 Kerberoasting |
| gMSAs used instead of standard service accounts where possible | — | T1558.003, T1078 |

---

## Microsoft 365 / Entra ID

| Setting | Hunt relevance |
|---|---|
| Conditional Access: Require MFA for all admin roles | T1078, T1110 |
| Conditional Access: Block legacy authentication | T1110 (basic auth bypasses MFA) |
| Security defaults OR full CA implementation (don't run with neither) | T1078 |
| Disable POP/IMAP/SMTP basic auth on mailboxes | T1110, T1078.004 |
| External email tagging enabled | T1566 |
| Defender for Office 365 Safe Attachments + Safe Links | T1566 |
| Audit logging enabled and retained ≥1 year | All |
| Restrict guest invites to admins only | T1078.004 |
| Allow only verified publisher apps (admin consent policy) | T1528 OAuth consent phishing |

---

## How to cite

When recommending a CIS-backed control, use this format:

> *Disable WDigest credential caching — CIS Microsoft Windows 10 Enterprise Benchmark 18.3.6 (Level 1).*

Include the benchmark name (Windows 10, Windows Server 2022, M365 Foundations, etc.) because numbering can shift across CIS benchmark families.

If you're recommending something not in this lookup, check the full benchmark before citing — don't invent CIS numbers, that's a fast way to lose credibility.
