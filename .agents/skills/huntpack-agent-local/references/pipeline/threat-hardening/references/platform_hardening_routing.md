# Platform Hardening Routing

The hunt's threat data decides the platform; this table decides the authority. Find the
platform(s) the threat touches, then pull controls from the listed sources. MITRE ATT&CK
Mitigations (M-numbers) apply across **all** rows — always include the M-number as the *why*,
then add the platform-specific *what/where* from here.

The Windows/AD/M365 row is served by the in-repo Windows module (`cis_lookup.md`,
`ms_baselines.md`, `common_ttps.md`). Every other row routes to an external authority — name it
and cite it; if you don't have the exact item number to hand, cite the benchmark/guide by name
and the specific setting, and the analyst can pull the line number.

| Platform / tech | Primary authorities | Typical control surface |
|---|---|---|
| **Windows / Active Directory** | CIS Microsoft Windows Benchmarks; Microsoft Security Baselines (SCT); DISA Windows STIGs | GPO, registry, LSA/Credential Guard, ASR rules, AD delegation/ACLs, LAPS |
| **Microsoft 365 / Entra ID** | CIS Microsoft 365 Foundations; CIS Entra ID Benchmark; Microsoft Secure Score guidance | Conditional Access, MFA, legacy-auth block, OAuth app consent policy, audit logging |
| **Linux (servers/endpoints)** | CIS Distribution Benchmarks (RHEL, Ubuntu, etc.); DISA Linux STIGs; vendor hardening guides | sysctl, PAM, SSH config, sudoers, SELinux/AppArmor, auditd, package integrity |
| **macOS** | CIS Apple macOS Benchmark; mSCP (macOS Security Compliance Project); Apple Platform Security guidance | configuration profiles (MDM), Gatekeeper/XProtect, FileVault, TCC, login items |
| **AWS** | CIS AWS Foundations Benchmark; AWS Security Best Practices / Well-Architected (Security Pillar) | IAM policy + MFA, CloudTrail, GuardDuty, S3 public-access block, SCPs, KMS |
| **Azure** | CIS Microsoft Azure Foundations Benchmark; Microsoft Cloud Security Benchmark | RBAC + PIM, Defender for Cloud, NSG/firewall, Key Vault, diagnostic logging |
| **GCP** | CIS Google Cloud Platform Foundations Benchmark; Google security foundations blueprint | IAM, org policies, VPC service controls, Cloud Audit Logs, CMEK |
| **Containers / Kubernetes** | CIS Kubernetes Benchmark; CIS Docker Benchmark; NSA/CISA Kubernetes Hardening Guide | RBAC, Pod Security Admission, network policies, image provenance/signing, runtime policy |
| **Network & VPN appliances** (Fortinet, Ivanti, Cisco, Palo Alto, Citrix, F5) | Vendor hardening guide + admin guide; DISA STIG for the platform where one exists; the specific CVE's PSIRT advisory | disable exposed mgmt/web portals, interface binding, ACLs, firmware/fixed-version upgrade, MFA on admin |
| **Email / collaboration gateways** | Vendor hardening guidance; CIS benchmark where applicable; M365 Defender for Office config | attachment/link detonation, anti-spoof/DMARC/DKIM/SPF, external-sender controls |
| **Identity providers (non-Entra: Okta, Ping, etc.)** | Vendor security best-practice; NIST SP 800-63 | MFA/phishing-resistant auth, session policy, admin-role hardening, log forwarding |
| **OT / ICS** | NIST SP 800-82; ISA/IEC 62443; vendor guidance; CISA ICS advisories | network segmentation, conduit/zone controls, allowlisting, remote-access hardening |

## Cross-platform / fallback authorities

When a threat spans platforms or the tech is niche/new and no platform benchmark covers it yet:

- **MITRE ATT&CK Mitigations** — always the technique-level *why*.
- **NIST SP 800-53** control families — broad, platform-neutral control language.
- **CISA / NCSC / ACSC advisories and the ACSC Essential Eight** — current, threat-aligned
  guidance, often the fastest authoritative source for an active campaign or fresh CVE.
- **The vendor's own PSIRT advisory** — authoritative for the specific affected product/version.
- **Documented vendor best-practice** — acceptable when nothing formal exists yet; cite it and
  flag the control `⚠ best-practice, no formal benchmark`. Never withhold a sound control for
  lack of a benchmark entry.

## How to cite

Give the reader a path to dig deeper without over-claiming precision:

- Have the exact item number → cite it: `CIS Ubuntu 22.04 5.2.5`, `CIS AWS Foundations 1.5`.
- Don't have the number → cite benchmark + setting by name: *"CIS RHEL 9 Benchmark — disable
  `kdump` service"* — accurate and discoverable.
- CVE-specific → cite the advisory ID and fixed version: *"Fortinet FG-IR-24-xxx — upgrade to
  FortiOS 7.x.y; disable SSL-VPN until patched."*
- Best-practice only → name the source and flag it: *"Vendor admin guide — bind management to a
  dedicated interface. ⚠ best-practice, no formal benchmark."*
