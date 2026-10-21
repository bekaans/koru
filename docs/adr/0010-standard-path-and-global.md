# ADR-0010: The standard path and English as the project language

- **Status:** Accepted. **Date:** 2026-10-19.
- **Related:** [README](../../README.md#roadmap), [CONTRIBUTING.md](../../CONTRIBUTING.md#protected-files), `docs/reports/metrics.md`

## Context
The technical core is ready: the end-to-end suite catches 100/100 scenarios with 0 false
positives, with a detection p95 of 307 ms. What the project still needs is reach and ease of
trying it: few people know about it, and trying it is harder than it should be. The decisions
below set the order of the work and the language of the project.

## Decisions
1. **Order:** visibility, then ease of trying, then embedding in other tools, then standard
   candidacy. The standard comes after use. If adoption does not follow, standard work is
   postponed and the work returns to the product.
2. **Spec in `spec/` inside the repository:** CC-BY-4.0 license, version number, RFC template,
   implementation link. The condition for moving to a separate repository: the first external
   implementer or a second maintainer.
3. **Benchmark name ACEB** (Agent Credential Exposure Benchmark); the name ACAB was rejected
   because of its political connotation in English. Scope: 6 agents (Claude Code, Codex CLI,
   Cursor Agent, Gemini CLI, opencode, generic MCP) and 3 controls (human, script or bot,
   container). Until an independent holdout is run, the results carry the "self-run" label; the
   agent signatures in the product do not change.
4. **Ownership boundary:** the decoy manifest and the agent actor taxonomy are Koru's standard
   candidates. The event format is not invented (it is mapped to OCSF); rules are contributed to
   SigmaHQ, starting with 2-3 quality rules. The positioning sentence: "no open source project
   does this combination (in-server eBPF + deception + process lineage + Apache-2.0)
   together"; "nobody does it" is not said.
5. **English first, everything global (including GitHub):**
   - **Tier A (first):** the GitHub side (issues, templates, repository information) and public
     documents are English. A new public document is written in English.
   - **Tier B:** in-code texts (comments, CLI outputs, error messages) are English.
   - **Tier C (breaking change):** identifiers (crate names, folders such as `schemas/`,
     `packages/`, `tools/`, `distribution/`, `data/`, rule and file names) change only with a
     one-time migration plan; Cargo, CI, xtask rules, lab scripts and schema `$id`s are updated
     in the same commit.
6. **Metric discipline:** 307 ms is the detection MTTD (p95), 1.06 s is the notification latency
   (p95); they are not mixed up. "0 false positives" is for access detection; usage detection is
   a later feature.
7. **Three sensors, one core:** the scope expands with server (existing), desktop and web
   sensors; the common ground is the same decoy manifest, the same `koru.event/v1` schema, the
   same actor taxonomy and a single console. The desktop sensor is user space in its first
   stage (no kernel claim); the web sensor is not a WAF, it is a deception layer. The first
   desktop systems are macOS and Linux.

## Consequences
- The publication and contribution rules ([CONTRIBUTING.md](../../CONTRIBUTING.md#protected-files))
  do not change.
- Tier C does not start without a maintainer decision: an identifier change is a user-facing
  breaking change and requires a release note.
- The eBPF probes are GPL-2.0 (a Pulsar legacy); user space and the spec are
  Apache-2.0 and CC-BY-4.0. This is stated explicitly in the README and [NOTICE](../../NOTICE).
