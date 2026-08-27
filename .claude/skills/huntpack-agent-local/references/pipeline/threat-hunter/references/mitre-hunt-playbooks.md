# MITRE ATT&CK Hunt Playbooks

Pre-built detection patterns organized by MITRE tactic. Each entry includes the observable behavior, the CrowdStrike event types that capture it, a ready-to-adapt CQL pattern, and known false positive sources.

For deep CQL syntax help or the full event field reference, see the `crowdstrike-logscale` skill.

---

## How to Use This Reference

1. Find the tactic and technique that matches your hunt
2. Copy the CQL pattern into a CrowdStrike LogScale query
3. Substitute `[CUSTOMIZE]` placeholders with environment-specific values
4. Review each example's `// FALSE POSITIVES:` and `// TUNING:` lines and add exclusions for your environment before running broadly
5. Emit the full canonical CQL comment header on every query. The line set, order, and vocabulary are defined once in the skill's `references/conventions.md` §7 "Canonical CQL header" (`../../../conventions.md`) — that file is the authority, and `scripts/verify_huntpack.py` hard-fails any query that deviates. The technique ID belongs on the `// MITRE:` line, and `// TUNING:` is required whenever `// FP:` is medium or high.

---

## TA0001 — Initial Access

### T1190 — Exploit Public-Facing Application (Web Shell / RCE)
**Observable:** A web/application server process (IIS, Apache, nginx) spawning unexpected child processes with command-line execution capability.

```
// HUNT: T1190 - Exploit Public-Facing Application (Web Shell / RCE)
// HYPOTHESIS: H01 - If a web shell is active, we should see web server processes spawning command shells or scripting engines with unexpected arguments
// USE: hunt
// MITRE: T1190
// CONF: medium
// FP: medium
// COST: medium
// TIMEFRAME: 7d - one deployment/change week of web server child processes
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with ParentBaseFileName, ChildBaseFileName, CommandLine, UserName, SHA256HashData
// FALSE POSITIVES: legitimate admin scripts running from web server context; IIS app pools running scheduled maintenance; deployment scripts
// TUNING: exclude the known maintenance and deployment command lines launched under the app-pool parent
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| ParentBaseFileName = /^(w3wp\.exe|httpd\.exe|nginx\.exe|tomcat.*\.exe|java\.exe)$/i
| ChildBaseFileName = /^(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|certutil\.exe)$/i
| groupBy([ComputerName, ParentBaseFileName, ChildBaseFileName, CommandLine],
          function=collect([UserName, SHA256HashData, @timestamp]))
| sort(_count, order=desc)
```

---

### T1566.001 — Phishing: Spearphishing Attachment (Office Macro Execution)
**Observable:** Office application spawning scripting engines or command shells — hallmark of macro-based payload delivery.

```
// HUNT: T1566.001 - Phishing Attachment / Office Macro Execution
// HYPOTHESIS: H02 - Macro-embedded documents will cause Office processes to spawn scripting engines or download payloads via LOLBins
// USE: hunt
// MITRE: T1566.001
// CONF: medium
// FP: medium
// COST: medium
// TIMEFRAME: 14d - phishing waves land over several days; two weeks catches slow-burn delivery
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with ParentBaseFileName, ChildBaseFileName, CommandLine, UserName, SHA256HashData
// FALSE POSITIVES: legitimate macro-enabled workbooks exist in many environments; finance automation macros; IT admin Excel tools; Access database apps
// TUNING: exclude the specific finance/IT macro workbooks and their child command lines by CommandLine
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| ParentBaseFileName = /^(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|onenote\.exe)$/i
| ChildBaseFileName = /^(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|
                         regsvr32\.exe|rundll32\.exe|certutil\.exe|bitsadmin\.exe)$/i
| groupBy([ComputerName, UserName, ParentBaseFileName, ChildBaseFileName, CommandLine],
          function=collect([@timestamp, SHA256HashData]))
| sort(_count, order=desc)
```

---

### T1078 — Valid Accounts (Anomalous Authentication)
**Observable:** Authentication from unusual locations, times, or with unusual patterns for a given account.

```
// HUNT: T1078 - Valid Accounts (Off-hours / unusual source authentication)
// HYPOTHESIS: H03 - Compromised credentials will show authentication patterns inconsistent with normal behavior for that account
// USE: hunt
// MITRE: T1078
// CONF: low
// FP: high
// COST: medium
// TIMEFRAME: 7d - one week of logons gives a per-account baseline to compare against
// REQUIRES: UserLogon with LogonType_decimal, UserName, LogonDomain, UserIp, ComputerName
// FALSE POSITIVES: travel, VPN, shift workers, and service accounts all generate noise; remote workers; on-call staff; service accounts with scheduled tasks
// TUNING: exclude service accounts and known VPN/egress source ranges, then rank on first-seen UserIp per UserName
// VALIDATION: STATIC-ONLY

#event_simpleName = UserLogon
| LogonType_decimal = 3   // Network logon — interactive (10) also relevant
| UserName != /\$$/ // Exclude computer accounts
| groupBy([UserName, LogonDomain, UserIp], function=[collect([@timestamp, ComputerName]), count()])
| sort(_count, order=desc)
```

---

## TA0002 — Execution

### T1059.001 — PowerShell
**Observable:** PowerShell execution with encoded commands, download cradles, or suspicious flags.

```
// HUNT: T1059.001 - PowerShell Execution (Suspicious Patterns)
// HYPOTHESIS: H04 - Malicious PowerShell will use encoded commands, download cradles, or bypass execution policy to avoid logging
// USE: hunt
// MITRE: T1059.001
// CONF: medium
// FP: medium
// COST: medium
// TIMEFRAME: 7d - one admin scripting cycle, enough to separate routine from anomalous
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with BaseFileName, CommandLine, ParentBaseFileName, UserName, SHA256HashData
// FALSE POSITIVES: legitimate admin scripts use these same patterns; SCCM/Intune deployment scripts; monitoring agents; patching tools
// TUNING: exclude by ParentBaseFileName, or by CommandLine containing known tool paths (SCCM/Intune, monitoring, patching)
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| BaseFileName = /^powershell(\.exe)?$/i
| CommandLine = /(-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee][Dd]|-[Ww][Ii][Nn][Dd][Oo][Ww][Ss][Tt][Yy][Ll][Ee]\s+[Hh]|-[Ee][Xx][Ee][Cc][Uu][Tt][Ii][Oo][Nn][Pp][Oo][Ll][Ii][Cc][Yy]\s+[Bb][Yy][Pp][Aa][Ss][Ss]|[Nn][Ee][Tt]\.[Ww][Ee][Bb][Cc][Ll][Ii][Ee][Nn][Tt]|[Ii][Nn][Vv][Oo][Kk][Ee]-[Ee][Xx][Pp][Rr][Ee][Ss][Ss][Ii][Oo][Nn]|[Ii][Ee][Xx])/
| groupBy([ComputerName, UserName, CommandLine], function=collect([@timestamp, ParentBaseFileName, SHA256HashData]))
| sort(_count, order=desc)
```

---

### T1059.003 — Windows Command Shell (Suspicious cmd.exe)
**Observable:** cmd.exe executing commands typically associated with enumeration, download, or evasion.

```
// HUNT: T1059.003 - Windows Command Shell (Suspicious Patterns)
// HYPOTHESIS: H05 - cmd.exe launched by Office, web server, or script-host parents indicates enumeration, download, or evasion rather than routine admin work
// USE: hunt
// MITRE: T1059.003
// CONF: medium
// FP: high
// COST: medium
// TIMEFRAME: 7d - one week of shell activity; cmd.exe volume makes longer windows expensive
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with BaseFileName, ParentBaseFileName, CommandLine, UserName, SHA256HashData
// FALSE POSITIVES: cmd.exe is ubiquitous; installer/uninstaller scripts; build pipelines; IT admin tasks
// TUNING: confidence depends on the parent-process filter - keep it tight and exclude installer and build-pipeline parents
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| BaseFileName =~ "cmd.exe"
| ParentBaseFileName = /^(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|
                          w3wp\.exe|mshta\.exe|wscript\.exe|cscript\.exe)$/i
| groupBy([ComputerName, UserName, ParentBaseFileName, CommandLine],
          function=collect([@timestamp, SHA256HashData]))
| sort(_count, order=desc)
```

---

### T1047 — Windows Management Instrumentation (WMI)
**Observable:** WMI provider host (`wmiprvse.exe`) spawning child processes — common lateral movement and persistence technique.

```
// HUNT: T1047 - WMI Execution (wmiprvse.exe spawning children)
// HYPOTHESIS: H06 - Malicious WMI execution will show wmiprvse.exe spawning shells or payloads that wouldn't normally originate from WMI
// USE: hunt
// MITRE: T1047
// CONF: medium
// FP: medium
// COST: medium
// TIMEFRAME: 14d - WMI lateral movement is bursty and intermittent; two weeks catches repeat use
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with ParentBaseFileName, ChildBaseFileName, CommandLine, UserName, SHA256HashData
// FALSE POSITIVES: WMI is legitimately used by monitoring agents and RMM tools
// TUNING: exclude known RMM tools (CrowdStrike itself, Tanium, SCCM WMI queries) by CommandLine or SHA256
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| ParentBaseFileName =~ "wmiprvse.exe"
| ChildBaseFileName != /^(WmiPrvSE\.exe|unsecapp\.exe|msiexec\.exe)$/i
| groupBy([ComputerName, UserName, ChildBaseFileName, CommandLine],
          function=collect([@timestamp, SHA256HashData]))
| sort(_count, order=desc)
```

---

### T1053.005 — Scheduled Task (Creation of Suspicious Tasks)
**Observable:** `schtasks.exe` creating tasks that point to unusual locations, scripting engines, or encoded commands.

```
// HUNT: T1053.005 - Scheduled Task Creation (Suspicious)
// HYPOTHESIS: H07 - Attackers use scheduled tasks for persistence; malicious tasks often point to temp directories, AppData, or use encoded PowerShell
// USE: hunt
// MITRE: T1053.005
// CONF: medium
// FP: medium
// COST: low
// TIMEFRAME: 7d - schtasks.exe creation is low volume; a week surfaces newly planted persistence
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with BaseFileName, CommandLine, ParentBaseFileName, UserName
// FALSE POSITIVES: software installers and monitoring tools create scheduled tasks; CrowdStrike sensor updates; Windows Update tasks
// TUNING: exclude known software by the /TR value in CommandLine
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| BaseFileName =~ "schtasks.exe"
| CommandLine = /\/[Cc][Rr][Ee][Aa][Tt][Ee]/
| CommandLine = /(%[Tt][Ee][Mm][Pp]%|%[Aa][Pp][Pp][Dd][Aa][Tt][Aa]%|\\[Tt][Ee][Mm][Pp]\\|
                  [Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]|[Ee][Nn][Cc][Oo][Dd][Ee][Dd]|
                  [Ww][Ss][Cc][Rr][Ii][Pp][Tt]|[Mm][Ss][Hh][Tt][Aa])/
| groupBy([ComputerName, UserName, CommandLine], function=collect([@timestamp, ParentBaseFileName]))
| sort(_count, order=desc)
```

---

## TA0003 — Persistence

### T1547.001 — Registry Run Keys / Startup Folder
**Observable:** New or modified registry autorun keys pointing to unusual locations.

```
// HUNT: T1547.001 - Registry Run Key Persistence
// HYPOTHESIS: H08 - Malware establishes persistence via HKCU/HKLM Run keys pointing to temp directories, AppData, or scripting engines
// USE: hunt
// MITRE: T1547.001
// CONF: medium
// FP: medium
// COST: low
// TIMEFRAME: 14d - autorun writes are rare and low volume; a longer window catches slow persistence
// REQUIRES: AsepValueUpdate/RegGenericValueUpdate with RegObjectName, RegValueName, RegStringValue, ComputerName, UserName
// FALSE POSITIVES: software installers legitimately write Run keys; Windows Update, Teams, Slack
// TUNING: exclude known software vendors by RegStringValue path
// VALIDATION: STATIC-ONLY

#event_simpleName = /AsepValueUpdate|RegGenericValueUpdate/
| RegObjectName = /\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\[Mm][Ii][Cc][Rr][Oo][Ss][Oo][Ff][Tt]\\[Ww][Ii][Nn][Dd][Oo][Ww][Ss]\\[Cc][Uu][Rr][Rr][Ee][Nn][Tt][Vv][Ee][Rr][Ss][Ii][Oo][Nn]\\[Rr][Uu][Nn]/
| RegStringValue = /(%[Tt][Ee][Mm][Pp]%|\\[Tt][Ee][Mm][Pp]\\|%[Aa][Pp][Pp][Dd][Aa][Tt][Aa]%|
                     [Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]|[Ww][Ss][Cc][Rr][Ii][Pp][Tt]|[Mm][Ss][Hh][Tt][Aa])/
| groupBy([ComputerName, UserName, RegObjectName, RegValueName, RegStringValue],
          function=collect([@timestamp]))
| sort(_count, order=desc)
```

---

### T1543.003 — Create or Modify System Process: Windows Service
**Observable:** New service creation pointing to unusual paths or using sc.exe with suspicious arguments.

```
// HUNT: T1543.003 - Malicious Service Creation
// HYPOTHESIS: H09 - Malicious service creation points ServiceImagePath at temp, AppData, public, or recycle-bin paths rather than a vendor install directory
// USE: hunt
// MITRE: T1543.003
// CONF: medium
// FP: medium
// COST: low
// TIMEFRAME: 7d - service creation is low volume; a week is small enough to review every new service
// REQUIRES: ServiceCreated with ServiceDisplayName, ServiceImagePath, ComputerName, UserName
// FALSE POSITIVES: software installers create services; RMM tools create services; Windows features
// TUNING: exclude known software by ServiceImagePath
// VALIDATION: STATIC-ONLY

#event_simpleName = ServiceCreated
| ServiceImagePath = /(%[Tt][Ee][Mm][Pp]%|\\[Tt][Ee][Mm][Pp]\\|%[Aa][Pp][Pp][Dd][Aa][Tt][Aa]%|
                       [Uu][Ss][Ee][Rr][Ss]\\[Pp][Uu][Bb][Ll][Ii][Cc]|[Rr][Ee][Cc][Yy][Cc][Ll][Ee])/
| groupBy([ComputerName, UserName, ServiceDisplayName, ServiceImagePath],
          function=collect([@timestamp]))
| sort(_count, order=desc)
```

---

## TA0004 — Privilege Escalation

### T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC
**Observable:** Known UAC bypass techniques — typically involve auto-elevation paths or COM object hijacking.

```
// HUNT: T1548.002 - UAC Bypass (fodhelper / eventvwr / other auto-elevate paths)
// HYPOTHESIS: H10 - UAC bypass will show specific binaries spawning elevated processes or registry modifications to HKCU COM object paths before elevation
// USE: alert-candidate
// MITRE: T1548.002
// CONF: high
// FP: low
// COST: low
// TIMEFRAME: 14d - bypass attempts are rare and single-shot; a longer window costs little
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with ParentBaseFileName, ChildBaseFileName, CommandLine, UserName, SHA256HashData
// FALSE POSITIVES: custom automation that legitimately uses fodhelper for elevation (rare)
// VALIDATION: STATIC-ONLY

// Pattern 1: fodhelper.exe spawning children (common bypass vector)
#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| ParentBaseFileName =~ "fodhelper.exe"
| ChildBaseFileName != /^(fodhelper\.exe|conhost\.exe)$/i
| groupBy([ComputerName, UserName, ChildBaseFileName, CommandLine],
          function=collect([@timestamp, SHA256HashData]))
```

---

## TA0005 — Defense Evasion

### T1055 — Process Injection
**Observable:** Processes allocating executable memory in remote processes or writing to remote process memory.

```
// HUNT: T1055 - Process Injection (Remote Memory Allocation)
// HYPOTHESIS: H11 - Injection will show a source process allocating executable memory in an unrelated target process (e.g., svchost.exe)
// USE: hunt
// MITRE: T1055
// CONF: medium
// FP: medium
// COST: high
// TIMEFRAME: 7d - RemoteThreadCreated is high volume; keep the window short enough to stay searchable
// REQUIRES: RemoteThreadCreated with SourceImageFileName, TargetImageFileName, ComputerName, UserName
// FALSE POSITIVES: AV, DLP, and monitoring tools legitimately inject into processes; CrowdStrike sensor, AV products, DLP agents
// TUNING: exclude security tooling by SourceImageFileName
// VALIDATION: STATIC-ONLY

#event_simpleName = RemoteThreadCreated
| TargetImageFileName != /^(.*\\(CrowdStrike|Cylance|SentinelOne|Carbon Black).*\.exe)$/i
| SourceImageFileName != TargetImageFileName
| groupBy([ComputerName, UserName, SourceImageFileName, TargetImageFileName],
          function=[collect([@timestamp]), count()])
| sort(_count, order=desc)
```

---

### T1218 — Signed Binary Proxy Execution (LOLBins)
**Observable:** Common living-off-the-land binaries executing in unusual ways — downloading, executing from memory, loading DLLs.

```
// HUNT: T1218 - LOLBin Abuse (certutil, mshta, regsvr32, rundll32)
// HYPOTHESIS: H12 - Signed system binaries invoked with URLs, UNC paths, scriptlets, or decode flags indicate proxy execution rather than normal use
// USE: hunt
// MITRE: T1218
// CONF: medium
// FP: medium
// COST: medium
// TIMEFRAME: 14d - LOLBin abuse is intermittent; two weeks catches repeat tradecraft
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with BaseFileName, CommandLine, ParentBaseFileName, UserName, SHA256HashData
// FALSE POSITIVES: these are legitimate system tools; PKI infrastructure uses certutil legitimately; script host use in enterprise
// TUNING: exclude PKI hosts and known enterprise script-host command lines; keep the focus on unusual arguments
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| BaseFileName = /^(certutil\.exe|mshta\.exe|regsvr32\.exe|regasm\.exe|regsvcs\.exe|
                    installutil\.exe|msiexec\.exe|wmic\.exe|cmstp\.exe)$/i
| CommandLine = /(http[s]?:\/\/|\\\\[0-9]{1,3}\.[0-9]{1,3}|[Ss][Cc][Rr][Ii][Pp][Tt][Ll][Ee][Tt]|
                  \/[Uu][Rr][Ll][Cc][Aa][Cc][Hh][Ee]|\/[Dd][Ee][Cc][Oo][Dd][Ee])/
| groupBy([ComputerName, UserName, BaseFileName, CommandLine],
          function=collect([@timestamp, ParentBaseFileName, SHA256HashData]))
| sort(_count, order=desc)
```

---

### T1562.001 — Impair Defenses: Disable or Modify Tools
**Observable:** Commands that stop, disable, or modify security tools or Windows Defender.

```
// HUNT: T1562.001 - Disabling Security Tools
// HYPOTHESIS: H13 - Attacker will attempt to stop AV/EDR services or disable Defender before deploying ransomware or additional payloads
// USE: alert-candidate
// MITRE: T1562.001
// CONF: high
// FP: low
// COST: low
// TIMEFRAME: 7d - tamper attempts are rare, so a week of coverage is cheap and catches staged activity
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with CommandLine, ParentBaseFileName, ComputerName, UserName
// FALSE POSITIVES: authorized testing windows; software updates that temporarily stop services
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| CommandLine = /(sc\s+(stop|delete|config)\s+(WinDefend|MsMpSvc|SENSE|CrowdStrike|csfalcon)|
                  Set-MpPreference.*-DisableRealtimeMonitoring|
                  taskkill.*\/[Ff]\s+\/[Ii][Mm]\s+(MsMpEng|CSFalconService|sensesvc))/i
| groupBy([ComputerName, UserName, CommandLine], function=collect([@timestamp, ParentBaseFileName]))
| sort(_count, order=desc)
```

---

## TA0006 — Credential Access

### T1003.001 — OS Credential Dumping: LSASS Memory
**Observable:** Processes reading LSASS memory — hallmark of credential harvesting tools (Mimikatz, ProcDump against LSASS).

```
// HUNT: T1003.001 - LSASS Memory Access (Credential Dumping)
// HYPOTHESIS: H14 - Credential dumping tools will open a handle to lsass.exe with read memory access (PROCESS_VM_READ)
// USE: hunt
// MITRE: T1003.001
// CONF: medium
// FP: medium
// COST: medium
// TIMEFRAME: 14d - credential access is a single short event; a two-week window avoids missing it
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with ImageFileName, TargetProcessId_decimal, CommandLine, ParentBaseFileName, UserName, SHA256HashData
// FALSE POSITIVES: AV and EDR tools legitimately access LSASS; CrowdStrike sensor, Windows Defender, backup agents
// TUNING: exclude known security tools by process name in ImageFileName
// VALIDATION: STATIC-ONLY

#event_simpleName = ProcessRollup2
| TargetProcessId_decimal = lsass_pid  // [CUSTOMIZE: may need to correlate LSASS PID]
| ImageFileName != /^(.*\\(MsMpEng|CSFalcon|WindowsSensor|ekrn|bdagent).*\.exe)$/i

// Alternative: detect procdump/minidump style access
#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| CommandLine = /(procdump.*lsass|rundll32.*MiniDump|comsvcs.*MiniDump|
                  sekurlsa::logonpasswords|lsadump::)/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine],
          function=collect([@timestamp, ParentBaseFileName, SHA256HashData]))
```

---

### T1110 — Brute Force (Authentication Failures)
**Observable:** High volume of failed authentication events from a single source.

```
// HUNT: T1110 - Brute Force Authentication
// HYPOTHESIS: H15 - Password guessing will show a single account or source IP accumulating an abnormal burst of logon failures
// USE: hunt
// MITRE: T1110
// CONF: medium
// FP: medium
// COST: low
// TIMEFRAME: 24h - brute force is burst behavior; a single day keeps the failure counts meaningful
// REQUIRES: UserLogonFailed2 with UserName, UserIp, ComputerName
// FALSE POSITIVES: locked accounts, misconfigured service accounts, bad passwords
// TUNING: exclude known service accounts and hold the threshold at >20 failures in 10 minutes
// VALIDATION: STATIC-ONLY

#event_simpleName = UserLogonFailed2
| UserName != /\$$/   // Exclude computer accounts
| groupBy([UserName, UserIp, ComputerName], function=[count(), collect(@timestamp)])
| _count > 20
| sort(_count, order=desc)
```

---

## TA0007 — Discovery

### T1082 — System Information Discovery
**Observable:** Execution of system enumeration commands (systeminfo, whoami, ipconfig, net commands) in sequence.

```
// HUNT: T1082 - System Information Discovery (Enumeration Chain)
// HYPOTHESIS: H16 - Post-exploitation enumeration produces a burst of discovery commands from the same process within a short time window
// USE: hunt
// MITRE: T1082
// CONF: low
// FP: high
// COST: medium
// TIMEFRAME: 7d - a week of parent-grouped bursts; discovery commands are high volume
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with BaseFileName, ParentBaseFileName, ComputerName, UserName
// FALSE POSITIVES: high standalone, lower when chained with other suspicious activity; IT asset inventory tools; RMM agents; onboarding scripts
// TUNING: exclude inventory and RMM parents, and use this as a correlation signal rather than a standalone alert
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| BaseFileName = /^(systeminfo\.exe|whoami\.exe|ipconfig\.exe|net\.exe|netstat\.exe|
                    nltest\.exe|arp\.exe|route\.exe|tasklist\.exe|quser\.exe|hostname\.exe)$/i
| groupBy([ComputerName, UserName, ParentBaseFileName],
          function=[collect(BaseFileName), count()])
| _count > 5   // 5+ distinct enumeration tools from same parent = suspicious
| sort(_count, order=desc)
```

---

## TA0008 — Lateral Movement

### T1021.001 — Remote Services: Remote Desktop Protocol
**Observable:** RDP connections originating from unusual source hosts or to unusual targets.

```
// HUNT: T1021.001 - RDP Lateral Movement (Workstation-to-Workstation)
// HYPOTHESIS: H17 - Lateral movement via RDP will show workstations connecting to other workstations on port 3389, which is unusual in most environments
// USE: hunt
// MITRE: T1021.001
// CONF: medium
// FP: medium
// COST: medium
// TIMEFRAME: 7d - a week of RDP flows shows which workstation pairs are genuinely new
// REQUIRES: NetworkConnectIP4 with RemotePort, LocalAddressIP4, RemoteAddressIP4, ComputerName, UserName
// FALSE POSITIVES: IT admins do use RDP and VDI environments carry many RDP connections; IT admin jump hosts; VDI broker connections; help desk remote support
// TUNING: exclude known admin subnets, jump hosts, and VDI brokers by LocalAddressIP4/RemoteAddressIP4
// VALIDATION: STATIC-ONLY

#event_simpleName = NetworkConnectIP4
| RemotePort = 3389
| LocalAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*admin.*/   // [CUSTOMIZE: exclude known admin subnets]
| groupBy([ComputerName, LocalAddressIP4, RemoteAddressIP4, UserName],
          function=[count(), collect(@timestamp)])
| sort(_count, order=desc)
```

---

### T1021.002 — Remote Services: SMB/Windows Admin Shares
**Observable:** Remote process execution via admin shares (PsExec pattern, Service creation over SMB).

```
// HUNT: T1021.002 - Lateral Movement via Admin Shares (PsExec-style)
// HYPOTHESIS: H18 - PsExec and similar tools create a service on the target to execute commands; the service binary is typically dropped to ADMIN$ or C$
// USE: hunt
// MITRE: T1021.002
// CONF: medium
// FP: medium
// COST: low
// TIMEFRAME: 7d - service creation over SMB is low volume; a week covers a full admin cycle
// REQUIRES: ServiceCreated with ServiceDisplayName, ServiceImagePath, ComputerName, UserName
// FALSE POSITIVES: IT uses PsExec and similar tools for legitimate remote management; authorized remote management operations
// TUNING: exclude known admin accounts and management subnets
// VALIDATION: STATIC-ONLY

#event_simpleName = ServiceCreated
| ServiceImagePath = /\\\\.*\\(ADMIN\$|C\$|IPC\$)/
| groupBy([ComputerName, UserName, ServiceDisplayName, ServiceImagePath],
          function=collect([@timestamp]))
| sort(_count, order=desc)
```

---

## TA0011 — Command and Control

### T1071.001 — Application Layer Protocol: Web Protocols (HTTP/S C2)
**Observable:** Unusual processes making outbound HTTP/HTTPS connections to non-browser, non-standard destinations.

```
// HUNT: T1071.001 - HTTP/S C2 Beaconing (Unusual Processes Making Web Requests)
// HYPOTHESIS: H19 - C2 agents will make periodic HTTP/S connections from unusual processes (not browsers or known updaters)
// USE: hunt
// MITRE: T1071.001
// CONF: low
// FP: high
// COST: high
// TIMEFRAME: 24h - outbound web connections are very high volume; a day keeps the aggregation tractable
// REQUIRES: NetworkConnectIP4 with RemotePort, RemoteAddressIP4, ImageFileName, ComputerName, UserName
// FALSE POSITIVES: many legitimate applications make HTTP connections; browsers, updaters, and telemetry agents dominate results
// TUNING: exclude known browsers and updaters by ImageFileName, then combine with beaconing interval analysis before escalating
// VALIDATION: STATIC-ONLY

#event_simpleName = NetworkConnectIP4
| RemotePort in (80, 443, 8080, 8443)
| ImageFileName != /^(.*\\(chrome|firefox|msedge|iexplore|MsMpEng|svchost|lsass|System).*\.exe)$/i   // [CUSTOMIZE]
| groupBy([ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort],
          function=[count(), collect(@timestamp)])
| sort(_count, order=desc)
```

---

### T1071.004 — Application Layer Protocol: DNS (DNS C2)
**Observable:** High volume of DNS queries to a single domain or queries with unusually long/encoded subdomains (DNS tunneling indicators).

```
// HUNT: T1071.004 - DNS C2 / Tunneling
// HYPOTHESIS: H20 - DNS tunneling uses high-entropy, long subdomains to exfiltrate data, and C2 over DNS shows high query volume to a small number of parent domains
// USE: hunt
// MITRE: T1071.004
// CONF: medium
// FP: medium
// COST: high
// TIMEFRAME: 24h - DNS volume is very high; a day is enough to see tunneling query rates
// REQUIRES: DnsRequest with DomainName, ComputerName, UserName
// FALSE POSITIVES: CDNs, telemetry endpoints, and some enterprise software use DNS heavily; Akamai, Cloudflare, Microsoft telemetry
// TUNING: exclude known-good parent domains (CDN and vendor telemetry) from DomainName
// VALIDATION: STATIC-ONLY

// Unusually long subdomain names (>50 chars before the TLD suggests encoding)
#event_simpleName = DnsRequest
| DomainName = /^.{50,}\./
| DomainName != /\.(microsoft|windows|office365|akadns|akamai|cloudfront|amazonaws)\.com$/i
| groupBy([ComputerName, UserName, DomainName], function=[count(), collect(@timestamp)])
| sort(_count, order=desc)
```

---

## TA0040 — Impact

### T1486 — Data Encrypted for Impact (Ransomware)
**Observable:** Rapid, high-volume file modification or creation of ransom note files — hallmark of ransomware execution.

```
// HUNT: T1486 - Ransomware File Encryption Activity
// HYPOTHESIS: H21 - Ransomware will modify/create thousands of files rapidly, often changing extensions or creating ransom note files in every directory
// USE: alert-candidate
// MITRE: T1486
// CONF: high
// FP: low
// COST: medium
// TIMEFRAME: 24h - encryption runs fast, so a short window keeps this close to real time
// REQUIRES: MotwWritten/PeFileWritten/PartiallyIntercepted with TargetFileName, ImageFileName, ComputerName, UserName
// FALSE POSITIVES: bulk file conversion tools; backup agents that create many temp files
// VALIDATION: STATIC-ONLY

// Ransom note creation pattern
#event_simpleName = /MotwWritten|PeFileWritten|PartiallyIntercepted/
| TargetFileName = /\.(txt|html|hta)$/i
| TargetFileName = /(ransom|decrypt|recover|readme|how.to|restore)/i
| groupBy([ComputerName, UserName, ImageFileName, TargetFileName],
          function=[count(), collect(@timestamp)])
| sort(_count, order=desc)
```

---

### T1490 — Inhibit System Recovery (VSS / Backup Deletion)
**Observable:** Commands deleting Volume Shadow Copies or disabling backup/recovery mechanisms — universally precedes ransomware deployment.

```
// HUNT: T1490 - VSS / Backup Deletion (Pre-Ransomware Indicator)
// HYPOTHESIS: H22 - Ransomware actors delete shadow copies and disable recovery BEFORE deploying the encryptor, so this is a pre-encryption detection opportunity
// USE: alert-candidate
// MITRE: T1490
// CONF: high
// FP: low
// COST: low
// TIMEFRAME: 7d - VSS deletion is rare; a week of coverage is inexpensive and any hit warrants immediate investigation
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with CommandLine, ParentBaseFileName, ComputerName, UserName, SHA256HashData
// FALSE POSITIVES: authorized backup system maintenance; storage team operations
// VALIDATION: STATIC-ONLY

#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| CommandLine = /(vssadmin.*delete shadows|vssadmin.*resize shadowstorage|
                  wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|
                  bcdedit.*bootstatuspolicy.*ignoreallfailures|
                  wbadmin.*delete.*catalog|diskshadow.*delete shadows)/i
| groupBy([ComputerName, UserName, CommandLine, ParentBaseFileName],
          function=collect([@timestamp, SHA256HashData]))
| sort(_count, order=desc)
```

---

## Correlation Queries (Multi-Event Behavioral Patterns)

### Ransomware Pre-Deployment Chain
Looks for the sequence: discovery → lateral movement indicator → defense evasion → backup deletion — all from the same host within a time window.

```
// HUNT: Ransomware Pre-Deployment Activity Chain
// HYPOTHESIS: H23 - Ransomware deployment follows a recognizable sequence, so detecting the chain provides earlier warning than any single event
// USE: hunt
// MITRE: T1490, T1562.001 - analyst-inferred from the two steps this query actually anchors on
// CONF: high
// FP: low
// COST: medium
// TIMEFRAME: 24h - the chain plays out within hours; a one-day window keeps the steps correlatable
// REQUIRES: ProcessRollup2/SyntheticProcessRollup2 with CommandLine, ComputerName, aid; step 2 must be run separately and correlated by host
// FALSE POSITIVES: low when the full chain is present; individual steps in isolation are noisy (backup maintenance, authorized security tooling)
// VALIDATION: STATIC-ONLY

// Step 1: Find hosts with VSS deletion (highest-confidence anchor event)
#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/
| CommandLine = /(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no)/i
| groupBy([ComputerName, aid], function=collect(@timestamp))
| rename(field=ComputerName, as=AffectedHost)

// Step 2: Cross-reference those hosts for security tool disabling in the same window
// (Run separately and correlate by host — CQL selfJoinFilter for same-aid correlation)
```
