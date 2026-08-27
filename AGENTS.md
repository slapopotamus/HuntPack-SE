# HUNTPACK_LOCAL — Local-Only Hunt Environment

This project is the **local, ad-hoc HuntPack environment**. Hunts run here stay here.

## Rules

1. **Generated hunts never leave the machine.** The framework source may be cloned,
   forked, and improved on GitHub, but never push, publish, or sync anything under
   `packs/`, `.runs/`, `TECH_STACK.md`, source snapshots, validation sidecars, or the
   mutable local index. Never invoke `github-huntpack-push` for generated output.
2. **Use the local skill.** Hunt requests in this project go through
   `huntpack-agent-local` (`.agents/skills/huntpack-agent-local/`) — a self-contained
   six-stage pipeline. Do not chain the global/plugin HuntPack skills here.
3. **Optional stack scoping.** If `TECH_STACK.md` exists, queries and hardening are
   scoped to its §10 in-scope list. If it is absent, run in General mode with broadly
   applicable Falcon coverage and clearly label the pack as unscoped. Stack setup is
   an advanced option, not a prerequisite.
4. **Fail-closed publication.** Assemble under `.runs\<run-id>\`, run the local
   static gate orchestrator, publish the exact-stem HTML/sources/validation sidecar to
   `packs\<YYYY-MM>\`, then update `index.html` last. File existence alone never
   authorizes index self-healing.
5. **Author handle** on packs: the `Pack author:` field in `TECH_STACK.md` (default
   `cybersecurity analyst`). Change it there or via the setup wizard — never hardcode a name.
6. **Gold-standard HuntPack parity.** The packs at
   `https://slapopotamus.github.io/HuntPack/` are the visual gold standard for local
   HuntPack HTML. Local reports should look and navigate like those packs. Use the repository's
   shared HuntPack template and preserve its dark visual system, teal-green accent, fixed
   grouped TOC, the 15 numbered sections, query cards with per-card `Looks for:` /
   `Accomplishes:` rationale, badges, Copy CQL/Open in Falcon actions, responsive
   behavior, and print styling. Keep stronger local validation and privacy controls
   even when the public packs do not yet display them.

See `README.md` for usage and `.agents/skills/huntpack-agent-local/references/conventions.md`
for the full convention set. Local static checks do not prove Falcon parsing or tenant behavior.
