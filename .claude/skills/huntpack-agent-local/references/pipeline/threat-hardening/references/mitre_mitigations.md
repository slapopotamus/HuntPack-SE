# MITRE ATT&CK Mitigations Reference

The M-numbers are the connective tissue between an observed technique and a concrete defensive control. This file gives you (a) the M-number catalog, (b) the most-used technique → mitigation map, and (c) what each M-number actually means in terms of "things you configure on a Windows endpoint."

Full catalog: https://attack.mitre.org/mitigations/enterprise/

---

## M-number catalog (high-leverage subset)

| M-num | Name | What it actually means on a Windows endpoint |
|---|---|---|
| M1013 | Application Developer Guidance | Code-signing requirements, secure SDLC; rarely actionable for endpoint hardening |
| M1015 | Active Directory Configuration | LAPS, tiered admin model, protected groups, AdminSDHolder hygiene, KRBTGT rotation |
| M1016 | Vulnerability Scanning | Continuous vuln management (MDE TVM, Tenable, Rapid7, or your RMM patching) |
| M1017 | User Training | Phishing-resistant training, MFA fatigue awareness — Long-term tier |
| M1018 | User Account Management | Just-in-time admin, removing local-admin rights, breaking glass accounts |
| M1019 | Threat Intelligence Program | Mostly process — rarely a single config |
| M1020 | SSL/TLS Inspection | NGFW decryption, proxy MITM with cert distribution |
| M1021 | Restrict Web-Based Content | DNS filtering (Cisco Umbrella, Cloudflare Gateway), web proxy categories, browser policy |
| M1022 | Restrict File and Directory Permissions | NTFS ACLs, removing Everyone:Full on shares, AppLocker path rules |
| M1024 | Restrict Registry Permissions | Lock down sensitive keys (Run keys, Image File Execution Options, autorun) |
| M1025 | Privileged Process Integrity | Credential Guard, Protected Process Light (PPL) for LSASS, RunAsPPL |
| M1026 | Privileged Account Management | LAPS, PIM/PAM, separation of duties, no daily-driver domain admin |
| M1027 | Password Policies | Length > complexity, banned-password lists, disable WDigest, NTLM auditing |
| M1028 | Operating System Configuration | The catchall for "configure Windows correctly" — most CIS controls live here |
| M1029 | Remote Data Storage | Off-host backups, immutable storage, 3-2-1 backup rule |
| M1030 | Network Segmentation | VLAN isolation, microseg, RDP only via jump host, deny lateral SMB |
| M1031 | Network Intrusion Prevention | NGFW IPS signatures, Snort/Suricata, NDR tools |
| M1032 | Multi-factor Authentication | MFA on all admin, conditional access policies, phishing-resistant (FIDO2) preferred |
| M1033 | Limit Software Installation | AppLocker, WDAC, Intune app protection, Software Restriction Policies |
| M1034 | Limit Hardware Installation | USB control via GPO or EDR, BitLocker enforcement |
| M1035 | Limit Access to Resource Over Network | Disable SMBv1, restrict NTLM, Kerberos armoring, SMB signing required |
| M1036 | Account Use Policies | Logon hours, lockout thresholds, smart card required for interactive logon |
| M1037 | Filter Network Traffic | Egress filtering, block unauthorized outbound, deny direct internet for servers |
| M1038 | Execution Prevention | ASR rules, AppLocker, WDAC, SmartScreen, Office macro restrictions |
| M1040 | Behavior Prevention on Endpoint | **CrowdStrike Falcon ML prevention policy, ASR rules, MDE EDR-in-block-mode** |
| M1041 | Encrypt Sensitive Information | BitLocker, EFS, certificate-based encryption, S/MIME |
| M1042 | Disable or Remove Feature or Program | **Disable SMBv1, LLMNR, NBT-NS, WDigest, NTLMv1, RDP if unused, PowerShell v2** |
| M1043 | Credential Access Protection | Credential Guard, LSA Protection (RunAsPPL), disable cached creds for shared workstations |
| M1044 | Restrict Library Loading | DLL search order hardening (SafeDllSearchMode), HMPA, OS Code Integrity |
| M1045 | Code Signing | WDAC code integrity policy, only allow signed drivers (Vulnerable Driver Blocklist) |
| M1046 | Boot Integrity | Secure Boot, Measured Boot, TPM 2.0 attestation, Device Health Attestation |
| M1047 | Audit | Advanced Audit Policy, Sysmon (if not relying solely on Falcon telemetry), DSAS for AD |
| M1048 | Application Isolation and Sandboxing | Windows Sandbox, browser isolation (Menlo, Cloudflare), MDAG, App Guard for Office |
| M1049 | Antivirus/Antimalware | Defender + Falcon, regular pattern updates, scheduled scans, prevention policies in BLOCK |
| M1050 | Exploit Protection | EMET → built into Win10/11 as "Exploit Protection"; per-app mitigations, system-wide DEP/SEHOP/ASLR |
| M1051 | Update Software | Patch cadence, KEV-tracked priority patching, third-party patching via your RMM |
| M1052 | User Account Control | UAC at "Always Notify" for admins, deny elevation prompts for standard users |
| M1053 | Data Backup | 3-2-1, immutable backups, regular restore tests, offline copy |
| M1054 | Software Configuration | Office macro restrictions, browser policy, app-specific hardening (Adobe, Java) |
| M1055 | Do Not Mitigate | Rarely used — only when the technique is acceptable risk or has no viable mitigation |
| M1056 | Pre-compromise | Threat intel, attack surface management, deception (canary tokens, honeyaccounts) |

---

## Technique → mitigation quick lookup

Use this as a starting point. Cross-reference with the actual MITRE technique page for the full list — the entries below are the *high-leverage* mitigations, not exhaustive.

| Technique | Name | Primary Mitigations |
|---|---|---|
| T1003.001 | LSASS Memory dump | M1025, M1040, M1043 (Credential Guard, RunAsPPL, Falcon LSASS protection) |
| T1003.002 | Security Account Manager | M1025, M1027, M1043 |
| T1003.003 | NTDS extraction | M1015, M1026, M1030 (tier 0 isolation, restrict DC access) |
| T1003.006 | DCSync | M1015, M1026, M1018 (audit DS-Replication-Get-Changes, restrict to DCs/svc accts) |
| T1018 | Remote System Discovery | M1030, M1037 (egress filtering, restrict SMB enumeration) |
| T1021.001 | RDP lateral movement | M1030, M1032, M1035, M1042 (disable if unused, MFA on RDP, jump hosts) |
| T1021.002 | SMB/Admin Shares | M1030, M1035, M1042 (SMB signing required, disable SMBv1, deny lateral SMB) |
| T1027 | Obfuscated Files | M1040, M1049 (Falcon ML, AMSI, Defender behavior monitoring) |
| T1036 | Masquerading | M1038, M1045 (AppLocker by hash/publisher, WDAC) |
| T1047 | WMI execution | M1038, M1040, M1042 (audit WMI activity, ASR rule, restrict Win-RM) |
| T1053.005 | Scheduled Task | M1018, M1022, M1047 |
| T1055 | Process Injection | M1040, M1050 (ASR rule `D1E49AAC-8F56-4280-B9BA-993A6D77406C`, Exploit Protection) |
| T1059.001 | PowerShell | M1038, M1042, M1047 (Constrained Language, PSv2 disable, ScriptBlock logging, AMSI) |
| T1059.003 | cmd.exe / Windows shells | M1038, M1042 (AppLocker, restrict cmd for standard users) |
| T1068 | Exploitation for Privilege Escalation | M1050, M1051 (patch + Exploit Protection) |
| T1078 | Valid Accounts | M1018, M1026, M1032, M1036 (MFA, JIT admin, conditional access, anomaly detection) |
| T1098 | Account Manipulation | M1015, M1018, M1026 |
| T1110 | Brute Force | M1027, M1032, M1036 (smart lockout, MFA, banned passwords) |
| T1133 | External Remote Services | M1030, M1032, M1035 (no direct internet exposure, MFA, restrict to allowlisted IPs) |
| T1134 | Token Manipulation | M1018, M1025, M1026 |
| T1136 | Create Account | M1018, M1026, M1047 |
| T1187 | Forced Authentication (NTLM relay) | M1027, M1035, M1042 (LDAP/SMB signing required, disable NTLM where possible) |
| T1190 | Exploit Public-Facing Application | M1016, M1030, M1031, M1051 |
| T1197 | BITS Jobs | M1042 (disable BITS for users), M1040 |
| T1203 | Exploitation for Client Execution | M1038, M1048, M1050 (ASR for Office child processes, App Guard for Office) |
| T1204.002 | Malicious File / User Execution | M1017, M1038, M1054 (Office macro block, attachment filtering, AppLocker) |
| T1207 | Rogue Domain Controller | M1015, M1018, M1047 |
| T1210 | Exploitation of Remote Services | M1030, M1031, M1051 |
| T1218 | Signed Binary Proxy Execution (LOLBins) | M1038, M1040, M1042 (AppLocker on rundll32, regsvr32, mshta; WDAC) |
| T1218.005 | Mshta | M1038, M1042 (disable mshta.exe via AppLocker or remove) |
| T1218.010 | Regsvr32 (Squiblydoo) | M1038, M1040 |
| T1218.011 | Rundll32 | M1038, M1040 |
| T1219 | Remote Access Software | M1031, M1037, M1042 (NGFW block known RMM C2, AppLocker on unauthorized RMM) |
| T1486 | Data Encrypted for Impact (ransomware) | M1040, M1049, M1053 (Falcon prevention BLOCK, controlled folder access, immutable backup) |
| T1518.001 | Security Software Discovery | M1018, M1040 (low-privilege users can't enumerate, Falcon tamper protection) |
| T1547.001 | Run keys / Registry persistence | M1024, M1038, M1040, M1047 |
| T1548.002 | UAC Bypass | M1026, M1052 (UAC Always Notify, remove local admin) |
| T1550.002 | Pass the Hash | M1015, M1025, M1026, M1027, M1043 (Credential Guard, no admin reuse, LAPS) |
| T1552.001 | Credentials in Files | M1022, M1027, M1041 (file ACLs, credential scanning, encrypted secrets vault) |
| T1556 | Modify Authentication Process | M1015, M1025, M1047 |
| T1558.003 | Kerberoasting | M1015, M1027, M1026 (no SPNs on highly-privileged accts, strong svc-acct passwords ≥25 char, gMSAs) |
| T1562.001 | Disable Security Tools | M1018, M1040 (Falcon tamper protection, deny SetService on critical svcs, app block on `taskkill`) |
| T1566.001 | Phishing Attachment | M1017, M1031, M1038, M1054 (mail filter, attachment sandbox, ASR rule for Office child procs) |
| T1566.002 | Phishing Link | M1017, M1021, M1031 (URL rewriting, SafeLinks, DNS filtering) |
| T1569.002 | Service Execution | M1018, M1022, M1038 |
| T1574.002 | DLL Side-Loading | M1038, M1044, M1045 |

---

## How to use this file

When you're recommending a control:

1. Find the technique ID in the lookup table above
2. Pick the **2–3 highest-leverage** mitigations (don't include all of them — pick the ones that actually move the needle for the user's environment)
3. For each M-number, find the concrete implementation in the catalog at the top
4. Cite it in the format: `MITRE M1042 (Disable or Remove Feature or Program)`
5. Cross-reference to `cis_lookup.md` and `ms_baselines.md` for the actual config

If a technique isn't in the lookup, go to https://attack.mitre.org/techniques/TXXXX/ — every technique page has a "Mitigations" section with the official M-number list.
