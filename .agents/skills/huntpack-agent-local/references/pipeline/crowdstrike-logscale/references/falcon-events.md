# Falcon Event Correlation Reference

## Process ID Correlation Fields

The key to effective threat hunting is correlating events across different telemetry types. These are the primary process ID fields for correlation:

| Source Event | Field | Correlates With |
|--------------|-------|-----------------|
| `ProcessRollup2` | `TargetProcessId` | Child processes |
| `ProcessRollup2` | `ParentProcessId_decimal` | Parent process |
| `DnsRequest` | `ContextProcessId_decimal` | `TargetProcessId_decimal` |
| `NetworkConnectIP4` | `ContextProcessId_decimal` | `TargetProcessId_decimal` |
| `ImageHash` | `TargetProcessId` | `TargetProcessId` |
| `FileWritten` events | `ContextProcessId_decimal` | `TargetProcessId_decimal` |

## Standard Correlation Patterns

### Pattern 1: DNS + Process
```
#event_simpleName = DnsRequest
| rename(field=ContextProcessId_decimal, as=TargetProcessId_decimal)
| join(query={#event_simpleName = ProcessRollup2}, field=TargetProcessId_decimal)
```

### Pattern 2: Network + Process
```
#event_simpleName = NetworkConnectIP4
| rename(field=ContextProcessId_decimal, as=TargetProcessId_decimal)
| join(query={#event_simpleName = ProcessRollup2}, field=TargetProcessId_decimal)
```

### Pattern 3: selfJoinFilter (Multiple Event Types)
```
#event_simpleName = /ProcessRollup2|DnsRequest|NetworkConnectIP4/
| falconPID := ContextProcessId
| falconPID := TargetProcessId
| selfJoinFilter(field=[aid, falconPID], where=[
    {#event_simpleName = /ProcessRollup2/},
    {#event_simpleName = /DnsRequest|NetworkConnectIP4/}
])
```

### Pattern 4: Process Tree (Parent-Child)
```
#event_simpleName = ProcessRollup2
| rename(field=TargetProcessId_decimal, as=ParentProcessId_decimal)
| join(query={#event_simpleName = ProcessRollup2}, field=ParentProcessId_decimal, include=[FileName, CommandLine])
```

## Common Falcon Event Types

### Process Events
| Event | Use Case |
|-------|----------|
| `ProcessRollup2` | Primary process execution telemetry |
| `SyntheticProcessRollup2` | Enriched process data |
| `ProcessBlocked` | Blocked process execution |
| `NewExecutableRenamed` | File renamed before/after execution |
| `NewExecutableWritten` | New executable created |
| `JarFileWritten` | Java archive written |

### Network Events
| Event | Use Case |
|-------|----------|
| `NetworkConnectIP4` | IPv4 outbound connections |
| `NetworkConnectIP6` | IPv6 outbound connections |
| `NetworkListenIP4` | Listening ports |
| `DnsRequest` | DNS queries |
| `SuspiciousDnsRequest` | Flagged DNS activity |

### File Events
| Event | Use Case |
|-------|----------|
| `NewExecutableWritten` | EXE/DLL created |
| `PeFileWritten` | PE file written |
| `ElfFileWritten` | Linux executable written |
| `ZipFileWritten` | Archive created |
| `DocumentFileWritten` | Office doc created |

### Registry Events
| Event | Use Case |
|-------|----------|
| `AsepValueUpdate` | Auto-start registry changes |
| `RegGenericValueUpdate` | Generic registry modification |
| `RegSystemConfigValueUpdate` | System config changes |

### Authentication Events
| Event | Use Case |
|-------|----------|
| `UserLogon` | Successful login |
| `UserLogoff` | Logout |
| `UserLogonFailed2` | Failed login |
| `UserAccountAddedToGroup` | Group membership change |

### Identity Protection Events
| Event | Use Case |
|-------|----------|
| `ActiveDirectoryAccountLocked` | Account lockout |
| `ActiveDirectoryAuthenticationFailure` | AD auth failure |
| `ActiveDirectoryAccountCreated` | New AD account |
| `ActiveDirectoryAccountPasswordUpdate` | Password change |
| `ActiveDirectoryAccountDirectContainingGroupEntitiesUpdate` | Direct group change |

## Key Field Reference

### Process Fields
| Field | Description |
|-------|-------------|
| `aid` | Agent/sensor ID (unique per endpoint) |
| `ImageFileName` | Full path to executable |
| `FileName` | Just the filename |
| `CommandLine` | Full command line |
| `ParentBaseFileName` | Parent process filename |
| `SHA256HashData` | File hash |
| `TargetProcessId` / `TargetProcessId_decimal` | Process ID |
| `ParentProcessId_decimal` | Parent PID |
| `UserSid` | User security identifier |
| `UserName` | Username |
| `ComputerName` | Hostname |
| `timestamp` / `@timestamp` | Event time |

### Signature / Authenticode Fields
Present on `ProcessRollup2`, `PeFileWritten` and module-load events. These are what
you hunt with when the *threat is the signature itself* — stolen or fraudulently
obtained code-signing certs used to make malware look trusted (SmartScreen bypass).

| Field | Description |
|-------|-------------|
| `AuthenticodeHashData` | Authenticode hash of the PE (identity of the *signed* image, stable across recompiles of the same signed blob). Empty/absent on unsigned files. |
| `SignInfoFlags` | Bitmask describing the sensor's signature verdict for the image (signed / verified / trusted-chain state). Exact bit meanings are tenant/sensor-version dependent — project it and baseline the values you see before filtering on a specific one. |

> Do NOT invent certificate-subject or serial-number fields for the Falcon event
> stream — the sensor does not publish the signer CN or cert serial as a queryable
> field. Hunt stolen-cert abuse via `AuthenticodeHashData` presence + known-bad
> `SHA256HashData`, and pivot to Sysmon EventID 1 (`Signature`, `SignatureStatus`)
> or `Get-AuthenticodeSignature` for the subject/serial half.

### Network Fields
| Field | Description |
|-------|-------------|
| `RemoteAddressIP4` | Destination IP |
| `RemotePort` / `RemotePort_decimal` | Destination port |
| `LocalAddressIP4` | Source IP |
| `LocalPort` | Source port |
| `ContextProcessId_decimal` | Initiating process |
| `ContextBaseFileName` | Process name |
| `Protocol_decimal` | Network protocol (6=TCP, 17=UDP) |

### DNS Fields
| Field | Description |
|-------|-------------|
| `DomainName` | Queried domain |
| `ContextProcessId` | Process making query |
| `QueryType` | DNS record type |

### Identity Fields
| Field | Description |
|-------|-------------|
| `SamAccountName` | AD username |
| `AccountDomain` | AD domain |
| `AccountObjectSid` | Account SID |
| `SourceEndpointHostName` | Source hostname |
| `SourceEndpointIp` | Source IP |
| `FailureReason` | Auth failure reason |
| `LogonType` | Type of logon |

## LogonType Values

| Value | Type | Description |
|-------|------|-------------|
| 2 | Interactive | Local console logon |
| 3 | Network | Network logon (SMB, etc.) |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth |
| 9 | NewCredentials | RunAs with /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached credentials |

## Protocol Values

| Value | Protocol |
|-------|----------|
| 6 | TCP |
| 17 | UDP |
| 1 | ICMP |

## AuthenticationId Values

| Value | Context |
|-------|---------|
| 999 | SYSTEM |
| 996 | Network Service |
| 997 | Local Service |

## Falcon Helper Functions

Enrich telemetry with built-in functions:
```
| $falcon/helper:enrich(field=ProductType)
| $falcon/helper:enrich(field=Protocol)
```

## Saved Search References
```
| join(query={$falcon/investigate:usersid_username_win()}, field=[UserSid], include=UserName)
```

## Process Explorer Links
Generate clickable links to Falcon console:
```
| rootURL := "https://falcon.crowdstrike.com/"  // US-1
// | rootURL := "https://falcon.us-2.crowdstrike.com/"  // US-2
// | rootURL := "https://falcon.laggar.gcw.crowdstrike.com/"  // Gov
// | rootURL := "https://falcon.eu-1.crowdstrike.com/"  // EU
| format("[View Process](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=[rootURL, aid, TargetProcessId], as=ProcessLink)
```
