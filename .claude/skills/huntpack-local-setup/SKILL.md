---
name: huntpack-local-setup
description: "Optional advanced setup wizard for HuntPack Local. Interviews the user about their environment and writes TECH_STACK.md for environment-specific hunt scoping plus a Pack author handle. Use when the user asks to configure or update their stack, improve hunt relevance, change the author, create TECH_STACK.md, or invokes '$huntpack-local-setup' or '/huntpack-local-setup'. Hunts do not require this setup; without it they run in General mode. This is an interactive conversation."
---

# HuntPack Local — Setup Wizard

This is the onboarding conversation for a fresh copy of the kit. Its job: interview the
user about their environment and produce a complete, well-formed `TECH_STACK.md` at the
project root, plus their **Pack author** handle. Once that exists, `huntpack-agent-local`
can run.

**This skill is interactive** — the "never prompt the user" rule belongs to the hunt
*pipeline*, not to setup. Here you ask questions and wait for answers. Be conversational,
not a form dump.

Read `../huntpack-agent-local/references/conventions.md` §3 (author) and §4 (stack
scoping), and `TECH_STACK.example.md` at the project root, before you start — the example
file is the exact shape of the output you're building.

---

## On invoke

1. **Check for an existing `TECH_STACK.md`** at the project root.
   - **Present** → say so and offer: *"You already have a TECH_STACK.md. Want to (a) update
     specific sections, (b) just change the Pack author, or (c) rebuild it from scratch?"*
     For (a)/(b), edit only what they name — never clobber the whole file. For (c), confirm
     explicitly before overwriting, then proceed as below.
   - **Absent** → *"Let's build your TECH_STACK.md — it's what scopes every hunt to your
     environment. I'll ask about each layer of your stack; say 'skip', 'none', or 'unknown'
     for anything that doesn't apply."* Then start the interview.

2. Greet briefly and set expectations (≈9 short topics, a couple of minutes).

---

## The interview

Ask **one topic at a time**, in this order, mirroring `TECH_STACK.example.md`. Keep each
question plain-language; accept "none / unknown / skip." Summarize what you captured after
each answer so the user can correct you. Don't move on until they confirm or answer.

0. **Pack author** — *"First, what handle should I stamp on every pack (Hunt Ticket, header,
   credits)? Default is `cybersecurity analyst`. Tip: use a team/role handle, not a personal
   legal name, if these packs may be shared."*

1. **Security platform (EDR/SIEM)** — *"What EDR and log platform do you run? This pipeline
   speaks CrowdStrike Falcon CQL — if you're on Falcon, which modules are licensed (Insight
   XDR, Next-Gen SIEM / LogScale, Identity Protection, OverWatch/Complete, Spotlight,
   Discover)? If you're on a different EDR/SIEM, tell me which — queries will need adapting."*
   Capture whether a **managed SOC** also watches (drives the OverWatch note in packs).

2. **Endpoints & servers** — *"Which OSes are in scope? Windows 10/11, Windows Server, Linux
   (which distros)? Any macOS — or none deployed? Mobile devices (MDM/MFA only)?"* Flag macOS
   and mobile as out-of-scope unless they specifically hunt them.

3. **Identity & productivity** — *"Directory: on-prem AD, Entra ID, hybrid, Okta? Any
   federation (AD FS)? Productivity suite (Microsoft 365, Google Workspace)? MFA provider(s)?"*

4. **Email security** — *"What filters your mail — a gateway (MX redirect), Microsoft
   Defender for Office 365 / EOP, both, or none?"*

5. **Network / perimeter** — *"List your firewalls, VPN concentrators, and NAC — manufacturer,
   model, rough quantity, and firmware version if you know it. Firmware versions feed the CVE
   watch-list, so include them where you can."*

6. **Virtualization** — *"Virtualization platform (VMware vSphere/ESXi, Hyper-V, Nutanix,
   none)? And your backup platform — worth documenting; immutable/offline backups are the
   decisive ransomware control."*

7. **Endpoint management** — *"How do you patch and manage endpoints — an RMM (which one), AD
   Group Policy, MDM (Intune/Jamf)?"*

8. **Cloud IaaS** — *"Any cloud IaaS workloads — AWS, Azure IaaS, GCP — or on-prem only?"*
   If none, record that explicitly (suppresses cloud-IaaS queries).

9. **Key apps & remote access** — *"Any key line-of-business apps, file services/NAS, Wi-Fi
   platform, VoIP, or internal RDP worth hunting around?"*

---

## Deriving §10 and §11

After the interview, derive the two rule sections from the answers — don't ask these
directly, compute them and show the user for confirmation:

- **§10 Hunt Scoping Rules**
  - *In scope:* every surface they said they run (OSes, identity, virtualization, appliances,
    management planes, key apps).
  - *Out of scope:* what they don't run — always include macOS if none deployed, cloud-IaaS if
    on-prem only, and mobile OS.
  - *Flex rule:* keep the standard wording (extend beyond stack when a threat clearly warrants
    it, flagged inline).
- **§11 CVE Watch-List Anchors** — the concrete products + firmware versions from §5 and the
  key products from §1–§9, so auto-pick mode treats a CVE in any of them as automatically
  relevant.

Show the derived §10/§11 back to the user in the chat: *"Here's what I'll enforce as in/out
of scope and the CVE anchors — anything to add or correct?"*

---

## Writing the file

1. Write `TECH_STACK.md` at the **project root** using the `TECH_STACK.example.md` structure,
   with the user's answers filled in and the `Pack author:` field set. Replace every
   bracketed placeholder; leave no template prompts behind. Put today's date in
   "Versions current as of".
2. Never write secrets — product names + versions only. If a user offers a real hostname, IP,
   or password, decline it and record the generic product/version instead (conventions §5).
3. Confirm the file was written and show a short recap (author handle, in-scope surfaces,
   number of CVE anchors).

---

## After setup

Tell the user how to run their first hunt:

> **Setup complete.** Your `TECH_STACK.md` is written and every hunt will scope to it.
>
> Build your first pack:
> - **Name a threat** — *"build a local hunt pack for CVE-2026-XXXXX"* or a campaign/actor/malware name.
> - **Auto-pick** — *"/huntpack-agent-local auto"* scans fresh CISA KEV + threat news, filters
>   against your stack, and builds packs for anything new and relevant.
>
> Output lands in `packs/<YYYY-MM>/` and the local `index.html` library. Nothing is pushed
> to GitHub. Update `TECH_STACK.md` (or re-run me) whenever your environment changes.

Never push anything anywhere; never invoke the hunt pipeline yourself — hand back to the user
to start their first hunt.
