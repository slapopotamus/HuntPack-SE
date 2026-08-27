# Technology Stack — Hunt Scoping Template

Technology-stack configuration is optional advanced scoping. Copy this file to
`TECH_STACK.md`, then replace the bracketed examples, or ask Codex or Claude Code to
**configure my HuntPack stack** and use the guided setup.

Keep this file current when products or versions change. Record product names and versions,
but never passwords, keys, IP addresses, or hostnames. The real `TECH_STACK.md` stays local
and is excluded from distributions.

## Quick profile

**Pack author:** cybersecurity analyst

**Versions current as of:** [YYYY-MM-DD]

**Environment summary:** [Example: Hybrid Windows environment using CrowdStrike Falcon and Microsoft 365]

> `Pack author` is the team or analyst handle printed on every HuntPack. A team/role name is
> preferable to a personal legal name.

---

## 1. Security Platform — EDR / SIEM

| Capability | Product, modules, and notes |
|---|---|
| Endpoint EDR | [Example: CrowdStrike Falcon Prevent + Insight XDR] |
| SIEM / log platform | [Example: Falcon Next-Gen SIEM / LogScale] |
| Identity protection | [Product/modules, or None] |
| Managed SOC / hunting | [Provider/service, or Self-managed] |
| Other licensed modules | [Example: Spotlight, Discover, Device Control, or None] |
| Queryable telemetry | [Briefly list what the hunt pipeline can query] |

## 2. Endpoints & Servers

Use `Yes` or `No` in the hunt-scope column.

| Surface | Deployed versions / notes | Hunt scope? |
|---|---|---|
| Windows workstations | [Versions and approximate count] | [Yes/No] |
| Windows Server | [Versions and approximate count] | [Yes/No] |
| Linux servers | [Distributions and approximate count] | [Yes/No] |
| macOS | [Versions/count, or None deployed] | [Yes/No] |
| Mobile devices | [iOS/Android and management use, or None] | [Yes/No] |

## 3. Identity & Productivity

| Capability | Product / configuration |
|---|---|
| Directory | [AD, Entra ID, Okta, hybrid, or None] |
| Federation | [AD FS or other federation, or None] |
| Productivity suite | [Microsoft 365, Google Workspace, or None] |
| MFA | [Provider(s), or None] |

## 4. Email Security

| Layer | Product / configuration |
|---|---|
| Primary filtering | [Gateway, Defender for Office 365/EOP, or None] |
| Additional defenses | [Secondary filtering, sandboxing, or None] |

## 5. Network & Perimeter

Firmware versions are important because they drive vulnerability relevance.

| Type | Vendor / product | Quantity | OS / firmware |
|---|---|---:|---|
| Firewall | [Vendor and model] | [#] | [Version] |
| VPN | [Vendor and model, or None] | [#] | [Version] |
| NAC | [Vendor and model, or None] | [#] | [Version] |
| Other appliance | [Type and product, or None] | [#] | [Version] |

## 6. Virtualization & Backup

| Capability | Product / configuration |
|---|---|
| Virtualization | [VMware, Hyper-V, Nutanix, or None] |
| Backup | [Product and whether immutable/offline copies exist] |

## 7. Endpoint Management

| Capability | Product / configuration |
|---|---|
| RMM / patching | [Product, or None] |
| Configuration management | [GPO or other tooling, or None] |
| MDM | [Intune, Jamf, or None] |

## 8. Cloud IaaS

| Provider | Workloads in scope |
|---|---|
| AWS | [Workloads, or None] |
| Azure IaaS | [Workloads, or None] |
| GCP | [Workloads, or None] |

If no cloud IaaS is deployed, state **None — on-premises only** so cloud-IaaS queries are
suppressed.

## 9. Key Applications & Remote Access

List only systems useful for hunting or vulnerability matching.

| Type | Product / notes |
|---|---|
| Remote access | [RDP, remote-support product, VPN, or None] |
| Business-critical apps | [Products, or None] |
| File services / NAS | [Products, or None] |
| Wi-Fi | [Product/platform, or None] |
| VoIP | [Product/platform, or None] |
| Other security-relevant systems | [Products, or None] |

---

## 10. Hunt Scoping Rules

This is the pipeline's authoritative scope. Derive it from sections 1–9.

**In scope:**

- [Every deployed OS, identity platform, appliance, management plane, and key application
  the pipeline may hunt]

**Out of scope — never build queries for:**

- [Anything not deployed or intentionally excluded, such as macOS, mobile OS, or cloud IaaS]

**Flex rule:** A hunt may extend beyond the documented stack only when the threat clearly
warrants it. Flag the exception inside the HuntPack.

## 11. CVE Watch-List Anchors

List concrete products and versions that make a vulnerability automatically relevant during
auto-pick. Include security tools, appliances, virtualization, identity, management, email,
file services, and business-critical applications.

| Product / platform | Version or release family | Why it matters |
|---|---|---|
| [Vendor product] | [Version] | [Firewall, VPN, identity, endpoint, etc.] |
| [Vendor product] | [Version] | [Short relevance note] |
