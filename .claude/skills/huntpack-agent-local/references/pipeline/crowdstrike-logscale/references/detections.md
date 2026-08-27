# CQL Detection Query Examples

Ready-to-use detection queries for common threat hunting and security monitoring scenarios with MITRE ATT&CK mappings.

> **v3 note:** every IP-range exclusion below uses `cidr()` because it communicates IP-range intent. Quoted
> wildcard patterns are valid CQL, but they are not a substitute for CIDR semantics. Validate fields against a
> real sample row before deploying (endpoint fields are stable; SaaS/IdP fields are parser-prefixed per tenant).

## Execution Detection

### T1059.001 - Encoded PowerShell Commands
```
#event_simpleName = ProcessRollup2
| ImageFileName = /powershell\.exe$/i
| CommandLine = /(?:-e|-enc|-encodedcommand)\s+(?<EncodedCommand>[A-Za-z0-9+\/=]{20,})/i
| base64Decode(field=EncodedCommand, as=decoded)
| table([@timestamp, ComputerName, UserName, CommandLine, decoded])
```

### T1218 - LOLBins Execution with Network
```
// Method 1: Join DNS with Process
#event_simpleName = DnsRequest
| rename(field=ContextProcessId_decimal, as=TargetProcessId_decimal)
| join(query={
    #event_simpleName = /ProcessRollup2/
    | FileName = /powershell\.exe|certutil\.exe|regsvr32\.exe|rundll32\.exe|bitsadmin\.exe/i
}, field=[aid, TargetProcessId_decimal])
| table([ComputerName, ImageFileName, DomainName, CommandLine])
```

```
// Method 2: selfJoinFilter correlation
#event_simpleName = /ProcessRollup2|DnsRequest/
| falconPID := ContextProcessId
| falconPID := TargetProcessId
| selfJoinFilter(field=[aid, falconPID], where=[
    {#event_simpleName = /ProcessRollup2/},
    {#event_simpleName = /DnsRequest/}
])
| FileName = /rundll32\.exe|powershell\.exe|certutil\.exe/i
| DomainName = *                       // keep rows that HAVE a resolved domain (field exists)
| groupBy([aid, ComputerName, falconPID], function=collect([FileName, DomainName, CommandLine]))
```

### T1059.003 - BITSAdmin Download
```
#event_simpleName = ProcessRollup2
| FileName = /bitsadmin\.exe/i
| CommandLine = /(\/Transfer|\/Addfile)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, SHA256HashData])
```

### T1055 - In-Memory .NET Assembly (C2 Frameworks)
Detects SilverC2, Metasploit, Cobalt Strike .NET loaders:
```
#event_simpleName = ImageHash
| rename(field=[[FileName, Dll_Loaded], [FilePath, Dll_Path]])
| selfJoinFilter(field=[aid, TargetProcessId], where=[
    {#event_simpleName = /ProcessRollup2/},
    {FileName != /powershell\.exe/i},
    {#event_simpleName = ImageHash}
])
| in(field=Dll_Loaded, values=["mscoree.dll", "clr.dll", "clrjit.dll", "mscorlib.ni.dll", "mscoreei.dll"], ignoreCase=true)
| groupBy([aid, ComputerName, TargetProcessId], function=collect([FileName, CommandLine, Dll_Loaded, Dll_Path]))
```

### Process Execution from Temp Directories
```
#event_simpleName = ProcessRollup2
| ImageFileName = /(\\Temp\\|\\tmp\\|\\AppData\\Local\\Temp)/i
| ImageFileName != /\.tmp$/i
| groupBy([ComputerName, ImageFileName], function=count())
| sort(_count, order=desc)
```

### T1566.001 - Office Spawning Shells (Phishing)
```
#event_simpleName = ProcessRollup2
| ParentBaseFileName = /(wscript|cscript|mshta)\.exe$/i
| ImageFileName = /(cmd|powershell|pwsh)\.exe$/i
| table([@timestamp, ComputerName, ParentBaseFileName, CommandLine])
```

## Persistence Detection

### T1547.001 - Registry Run Key Modification
```
#event_simpleName = /AsepValueUpdate|RegGenericValueUpdate/
| event_platform = Win
| RegObjectName = /\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
| AuthenticationId_decimal = 999  // SYSTEM
| groupBy([ComputerName, RegObjectName, RegValueName], function=count())
```

**AuthenticationId values:**
- 999 = SYSTEM level privileges
- 996 = Network Service
- 997 = Local Service

### T1053.005 - Scheduled Task Creation
```
#event_simpleName = ProcessRollup2
| ImageFileName = /schtasks\.exe$/i
| CommandLine = /\/create/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

### T1543.003 - Service Installation
```
#event_simpleName = ProcessRollup2
| ImageFileName = /sc\.exe$/i
| CommandLine = /(create|config)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

## Credential Access

### T1003 - LSASS Access
```
#event_simpleName = ProcessRollup2
| CommandLine = /(lsass|sekurlsa|mimikatz|procdump.*lsass)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine])
```

### T1558.003 - Kerberoasting Activity
```
#event_simpleName = ProcessRollup2
| CommandLine = /(invoke-kerberoast|get-spnticket|asreproast|rubeus)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

### Credential Dumping Tools
```
#event_simpleName = ProcessRollup2
| CommandLine = /(lazagne|mimikatz|rubeus|safetykatz|pypykatz)/i 
    or SHA256HashData = /^(known_bad_hash_1|known_bad_hash_2)$/
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine])
```

## Defense Evasion

### T1036.003 - Renamed Executable (Masquerading)
```
#event_simpleName = NewExecutableRenamed
| rename(field=TargetFileName, as=ImageFileName)
| join(query={#event_simpleName = /ProcessRollup2/}, field=[ImageFileName])
| table([aid, ComputerName, SourceFileName, ImageFileName, CommandLine])
```

### T1070.004 - File Deletion
```
#event_simpleName = ProcessRollup2
| CommandLine = /(del\s|remove-item|rm\s-rf)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

### Disabling Security Tools
```
#event_simpleName = ProcessRollup2
| CommandLine = /(net stop|sc stop|taskkill).*(defender|sense|csfalcon|carbonblack|crowdstrike)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

## Lateral Movement

### T1021.001 - Remote Desktop Connections
```
#event_simpleName = UserLogon
| LogonType = 10
| groupBy([ComputerName, UserName, RemoteAddressIP4], function=count())
| sort(_count, order=desc)
```

### T1021.002 - SMB/Windows Admin Shares
```
#event_simpleName = NetworkConnectIP4
| RemotePort = 445
| rename(field=ContextProcessId_decimal, as=TargetProcessId_decimal)
| join(query={#event_simpleName = ProcessRollup2}, field=TargetProcessId_decimal)
| groupBy([ComputerName, RemoteAddressIP4, ImageFileName], function=count())
| sort(_count, order=desc)
```

### T1569.002 - PsExec Usage
```
#event_simpleName = ProcessRollup2
| ImageFileName = /psexe(c|svc)\.exe$/i or CommandLine = /\\\\.*\\admin\$/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

### T1047 - WMI Remote Execution
```
#event_simpleName = ProcessRollup2
| ImageFileName = /wmiprvse\.exe$/i
| CommandLine = *
| groupBy([ComputerName, UserName], function=[count(), collect(CommandLine, limit=5)])
```

### Suspicious Network Connections (Non-standard Ports)
```
#event_simpleName = NetworkConnectIP4
// Use cidr() for IP ranges; quoted wildcards are valid but do not express CIDR semantics.
| !cidr(RemoteAddressIP4, subnet="127.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="10.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="192.168.0.0/16")
| !cidr(RemoteAddressIP4, subnet="172.16.0.0/12")
| !in(RemotePort, values=[80, 443, 22, 53, 389, 445, 135, 88])
| rename(field=ContextProcessId_decimal, as=TargetProcessId_decimal)
| join(query={#event_simpleName = ProcessRollup2}, field=[aid, TargetProcessId_decimal])
| table([ComputerName, ImageFileName, RemoteAddressIP4, RemotePort, CommandLine])
```

## Discovery

### T1087 - Account Discovery
```
#event_simpleName = ProcessRollup2
| CommandLine = /(net user|net group|net localgroup|whoami|quser)/i
| groupBy([ComputerName, UserName], function=collect(CommandLine))
```

### T1018 - Remote System Discovery
```
#event_simpleName = ProcessRollup2
| CommandLine = /(net view|nltest|dsquery|ping -n|nslookup)/i
| groupBy([ComputerName, UserName], function=[count(), collect(CommandLine)])
```

### T1069 - Permission Groups Discovery
```
#event_simpleName = ProcessRollup2
| CommandLine = /(Get-ADUser|Get-ADComputer|Get-ADGroup|Get-DomainUser|Find-LocalAdmin)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

### DNS Queries to Suspicious TLDs
```
#event_simpleName = DnsRequest
| DomainName = /\.(top|club|xyz|tk|ml|ga|cf|gq|pw)$/i
| rename(field=ContextProcessId_decimal, as=TargetProcessId_decimal)
| join(query={#event_simpleName = ProcessRollup2}, field=TargetProcessId_decimal)
| table([ComputerName, ImageFileName, DomainName, CommandLine])
```

## Data Exfiltration

### Large Outbound Transfers
```
#event_simpleName = NetworkConnectIP4
// cidr() for ranges; quoted wildcard patterns are valid but less precise for IP ranges.
| !cidr(RemoteAddressIP4, subnet="10.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="192.168.0.0/16")
| !cidr(RemoteAddressIP4, subnet="172.16.0.0/12")
| groupBy([ComputerName, RemoteAddressIP4, ContextBaseFileName], function=[count(as=Conns), sum(BytesSent, as=TotalBytes)])
| TotalBytes > 100000000
| sort(TotalBytes, order=desc)
```

### Cloud Storage Uploads
```
#event_simpleName = NetworkConnectIP4
| DomainName = /(dropbox|box\.com|onedrive|drive\.google|mega\.nz|pastebin)/i
| groupBy([ComputerName, UserName, DomainName], function=count())
```

## Identity Protection Queries

### Failed Authentication Surge
```
#event_simpleName = ActiveDirectoryAuthenticationFailure
| Bucket5m := @timestamp - (@timestamp % 300000)        // 5-min bucket (portable epoch-ms math)
| groupBy([Bucket5m, SamAccountName], function=count(as=Failures))
| Failures > 10
```

### Account Lockout Timeline
```
#event_simpleName = ActiveDirectoryAccountLocked
| timeChart(span=1h, function=count())
```

### Privileged Account Activity
```
#event_simpleName = ActiveDirectoryAuthentication
| SamAccountName = /(admin|administrator|svc-|service)/i
| groupBy([SamAccountName, SourceEndpointHostName], function=count())
| sort(_count, order=desc)
```

### Off-Hours Authentication
```
#event_simpleName = ActiveDirectoryAuthentication
| Hour := formatTime("%H", field=@timestamp)            // zero-padded "00".."23" (string)
| Hour < "06" or Hour > "20"                            // lexical compare is correct for 2-digit hours
| groupBy([SamAccountName, SourceEndpointHostName, Hour], function=count(as=Logons))
```

## Ransomware Indicators

### Mass File Encryption
```
#event_simpleName = RansomwareOpenFile
| groupBy([ComputerName, UserName], function=count(as=FilesTouched))
| FilesTouched > 100
| sort(FilesTouched, order=desc)
```

### Shadow Copy Deletion
```
#event_simpleName = ProcessRollup2
| CommandLine = /(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

## Dashboard Queries

### Security Event Summary
```
* 
| groupBy(#event_simpleName, function=count())
| sort(_count, order=desc)
| head(20)
```

### Top Hosts by Events
```
*
| groupBy(ComputerName, function=count())
| sort(_count, order=desc)
| head(10)
```

### Authentication Overview
```
#event_simpleName = /Authentication|Logon/
| case {
    #event_simpleName = *Failure* or #event_simpleName = *Failed* | status := "Failed";
    * | status := "Success";
}
| timeChart(status, span=1h, function=count())          // series field — positional or series=status both work
```
