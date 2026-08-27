# IOC Management Reference

Formatting specifications, expiry policies, governance workflow, and API patterns for CrowdStrike IOC Management (Falcon IOC Management / Custom IOCs).

---

## IOC Type Decision Guide

### What CrowdStrike IOC Management Supports

| IOC Type | CrowdStrike Field | Notes |
|---|---|---|
| SHA256 hash | `sha256` | Preferred hash type; most reliable |
| MD5 hash | `md5` | Supported; SHA256 preferred when available |
| Domain | `domain` | Exact match on full domain; does not match subdomains unless you add them separately |
| IPv4 address | `ipv4` | Exact match; no CIDR range support in IOC Management |
| IPv6 address | `ipv6` | Exact match |

### What CrowdStrike IOC Management Does NOT Support
- URLs (path + query string) — use domain IOC and CQL hunt query together
- IP ranges / CIDR notation — must enumerate individual IPs (not scalable; use firewall rules instead)
- Certificates / code signing thumbprints — use Custom IOA detection in Falcon instead
- File paths (without a hash) — use Custom IOA rule with file creation detection instead

### When to Use Each IOC Type

| Scenario | Recommended Approach |
|---|---|
| Confirmed malware sample hash | SHA256 IOC, action: `prevent` |
| C2 domain confirmed, not shared hosting | Domain IOC, action: `detect` first; promote to `prevent` after review |
| C2 IP, short-lived | IPv4 IOC, action: `detect` only; 30-day expiry |
| Malicious URL path on legitimate domain | Domain IOC will over-block; use CQL hunt + Custom IOA only |
| File extension or name pattern | Custom IOA rule (File Creation event type) |
| Registry key | Custom IOA rule (Registry Operation event type) |

---

## Expiry Policy Standards

Always set an expiration date. IOCs without expiry accumulate, degrade performance, and generate stale alerts.

| IOC Type | Standard Expiry | Rationale |
|---|---|---|
| SHA256 hash | 1 year (or indefinite for confirmed persistent malware family) | File hashes don't change; confirmed malware stays malicious |
| MD5 hash | 1 year | Same as SHA256; MD5 is less reliable due to collision risk |
| Domain | 90 days | C2 infrastructure is frequently abandoned and re-registered by legitimate parties |
| IPv4 | 30 days | IP addresses are highly volatile — shared hosting, VPNs, Tor exits, and CDNs rotate constantly |
| IPv6 | 30 days | Same as IPv4 |

### Expiry Review Triggers
Set a calendar reminder to review IOCs before expiry for:
- **Active campaigns:** Extend by 90 days if the campaign is still active
- **Dormant IOCs:** Let them expire or archive
- **Infrastructure overlap:** If the domain/IP has been observed in multiple campaigns, consider extension
- **Re-registration:** Check if a domain has been re-registered by a legitimate party before extending a block

---

## Action Selection Guide

| Action | CrowdStrike Value | When to Use |
|---|---|---|
| **Prevent (Block)** | `prevent` | High-confidence, low-collateral-damage IOCs: SHA256 hashes of confirmed malware. After validation period in Detect mode for domains. |
| **Detect (Alert Only)** | `detect` | Default starting action for all IOCs. Domains and IPs should almost always stay in Detect. |
| **No Action** | `no_action` | Tracking/observability only — logs matches without generating alerts. Use for low-confidence IOCs you want to monitor without alert fatigue. |

### Recommended Action Promotion Path
```
New IOC → Detect (observe for 48 hours)
    ↓
Low FP rate + confirmed TP? → Promote to Prevent (for hashes)
    ↓                          Stay in Detect (for domains/IPs)
Expiry reached → Archive or Extend
```

**Never skip Detect for domains and IPs.** Shared hosting and CDN infrastructure means an IP or domain may be serving both malicious and legitimate content. A block on `evil.com` may be correct today and wrong in 30 days after re-registration.

---

## Bulk Import CSV Format

For importing IOCs in bulk via the Falcon UI bulk upload or API:

```csv
type,value,action,severity,expiration,description,tags
sha256,aabbcc0011223344556677889900aabbcc0011223344556677889900aabbccdd,prevent,critical,2027-04-14,Malware family: CobaltStrike beacon - Operation DesertStorm,campaign:DesertStorm|source:ThreatFox|actor:APT28
md5,aabbcc001122334455667788990000aa,detect,high,2027-04-14,Malware family: CobaltStrike beacon MD5 - Operation DesertStorm,campaign:DesertStorm|source:ThreatFox
domain,evil-c2.example.com,detect,high,2024-07-14,C2 domain - Operation DesertStorm,campaign:DesertStorm|source:VirusTotal|tlp:white
ipv4,198.51.100.42,detect,medium,2024-05-14,C2 IP - Operation DesertStorm - expires 30d,campaign:DesertStorm|source:ThreatFox
```

### Field Specifications

| Field | Required | Valid Values | Notes |
|---|---|---|---|
| `type` | Yes | `sha256`, `md5`, `domain`, `ipv4`, `ipv6` | Lowercase |
| `value` | Yes | The IOC value | SHA256: 64 hex chars; MD5: 32 hex chars; domain: no leading `http://`; IP: standard dotted notation |
| `action` | Yes | `prevent`, `detect`, `no_action` | Use `detect` as default |
| `severity` | Yes | `critical`, `high`, `medium`, `low`, `informational` | Match to threat severity from Phase 1 brief |
| `expiration` | Yes | `YYYY-MM-DD` (ISO 8601) | Always populate; see Expiry Policy above |
| `description` | Recommended | Free text (max 200 chars) | Include malware family and campaign name |
| `tags` | Recommended | Pipe-separated `key:value` pairs | See Tag Conventions below |
| `platforms` | Optional | `windows`, `mac`, `linux` | Omit to apply to all platforms |
| `applied_globally` | Optional | `true`, `false` | Default: true (applies to all sensor groups) |

### Tag Conventions

Use consistent tag prefixes for searchability and governance:

| Prefix | Purpose | Example |
|---|---|---|
| `campaign:` | Links IOC to a named campaign or operation | `campaign:BlackCat-Ransomware` |
| `source:` | Intel feed or report where the IOC was found | `source:ThreatFox`, `source:CISA-AA24-001` |
| `actor:` | Threat actor attribution | `actor:APT29`, `actor:LockBit` |
| `tlp:` | Traffic Light Protocol classification | `tlp:white`, `tlp:green`, `tlp:amber` |
| `cve:` | Associated CVE if the IOC is tied to exploitation | `cve:CVE-2025-1234` |
| `hunt:` | Links back to the hunt ticket or query name | `hunt:HUNT-2024-042` |

Multiple tags: Use pipe `|` separator in CSV; use comma in JSON API.

---

## Governance Workflow

### Standard IOC Promotion Process

```
1. IDENTIFY
   ├── IOC found in threat intel / hunt results
   ├── Confirm IOC type is supported (hash / domain / IP)
   └── Assess initial confidence (High / Medium / Low)

2. STAGE (Detect mode)
   ├── Create IOC with action: detect
   ├── Apply to test sensor group if available
   ├── Set expiry per policy (30 / 90 / 365 days)
   └── Tag with campaign:, source:, tlp:

3. VALIDATE (48-hour observation)
   ├── Review all alerts generated
   ├── Classify each alert as TP (true positive) or FP (false positive)
   ├── FP rate > 10%? → Do NOT promote to Prevent; investigate FP source
   └── FP rate < 5%? → Eligible for promotion

4. PROMOTE (hashes only — domains/IPs stay in Detect)
   ├── Change action from detect → prevent
   ├── Document FP rate and TP count in description or ticket
   └── Apply to all sensor groups

5. REVIEW (at expiry)
   ├── Still active campaign? → Extend expiry
   ├── Campaign dormant > 180 days? → Downgrade to no_action or delete
   └── Domain re-registered? → Delete immediately
```

### Who Approves What

| Change | Approval Required |
|---|---|
| Create hash IOC (Detect) | Analyst self-service |
| Create domain/IP IOC (Detect) | Analyst self-service |
| Promote hash to Prevent | Peer review (second analyst sign-off) |
| Promote domain to Prevent | Change management ticket |
| Bulk import > 50 IOCs | Team lead review |
| Delete existing IOC | Analyst self-service (with documented reason) |

---

## CrowdStrike IOC Management API

### Base URL
`https://api.crowdstrike.com`

### Authentication
Use OAuth2 client credentials (Client ID + Secret from Falcon API settings):
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Body: client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}
```
Response includes `access_token` (valid 30 minutes).

### Create IOCs (single or bulk)
```
POST /iocs/entities/indicators/v1
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "indicators": [
    {
      "type": "sha256",
      "value": "HASH_HERE",
      "action": "prevent",
      "severity": "critical",
      "description": "Malware family: X - Campaign Y",
      "tags": ["campaign:Y", "source:ThreatFox"],
      "applied_globally": true,
      "expiration": "2026-04-14T00:00:00Z",
      "platforms": ["windows"]
    }
  ]
}
```

### Query IOCs (paginated)
```
GET /iocs/queries/indicators/v1?limit=500&offset=0&filter=type:'sha256'
Authorization: Bearer {access_token}
```

### Bulk Import Example (Python)
```python
import requests
import json
import csv

FALCON_CLIENT_ID = "YOUR_CLIENT_ID"
FALCON_CLIENT_SECRET = "YOUR_CLIENT_SECRET"
BASE_URL = "https://api.crowdstrike.com"

def get_token():
    resp = requests.post(
        f"{BASE_URL}/oauth2/token",
        data={"client_id": FALCON_CLIENT_ID, "client_secret": FALCON_CLIENT_SECRET}
    )
    return resp.json()["access_token"]

def bulk_create_iocs(csv_path, token):
    indicators = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            indicators.append({
                "type": row["type"],
                "value": row["value"],
                "action": row["action"],
                "severity": row["severity"],
                "expiration": f"{row['expiration']}T00:00:00Z",
                "description": row.get("description", ""),
                "tags": row.get("tags", "").split("|") if row.get("tags") else [],
                "applied_globally": True
            })

    # API limit: 200 IOCs per request
    for batch in [indicators[i:i+200] for i in range(0, len(indicators), 200)]:
        resp = requests.post(
            f"{BASE_URL}/iocs/entities/indicators/v1",
            headers={"Authorization": f"Bearer {token}"},
            json={"indicators": batch}
        )
        print(f"Batch result: {resp.status_code} — {len(batch)} IOCs")

token = get_token()
bulk_create_iocs("iocs.csv", token)
```

### Delete IOCs
```
DELETE /iocs/entities/indicators/v1?ids={indicator_id_1}&ids={indicator_id_2}
Authorization: Bearer {access_token}
```

### Rate Limits
- Create: 400 IOCs/minute
- Query: 1000 requests/minute
- Batch size: 200 IOCs per POST request
- For bulk imports > 2000 IOCs, add 1-second delays between batches to avoid rate limiting

---

## IOC Quality Checklist

Before submitting any IOC to production, verify:

- [ ] IOC type is supported by Falcon IOC Management
- [ ] Value format is correct (SHA256 = 64 hex chars, no `0x` prefix; domain = no `http://` or trailing `/`)
- [ ] Action is appropriate (`detect` for domains/IPs; `prevent` only for validated hashes)
- [ ] Expiry date is set per policy (not blank, not > 1 year for domains/IPs)
- [ ] Description includes malware family and campaign name
- [ ] Tags include at minimum `campaign:` and `source:`
- [ ] For domains: confirmed the domain is not currently registered to a legitimate party (check WHOIS)
- [ ] For IPs: confirmed the IP is not a CDN, shared host, or known legitimate service (check Shodan/VirusTotal)
- [ ] TLP classification is set if the intel came with a TLP designation
