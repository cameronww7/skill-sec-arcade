```
███████╗██╗  ██╗██╗██╗     ██╗         ███████╗███████╗ ██████╗
██╔════╝██║ ██╔╝██║██║     ██║         ██╔════╝██╔════╝██╔════╝
███████╗█████╔╝ ██║██║     ██║         ███████╗█████╗  ██║     
╚════██║██╔═██╗ ██║██║     ██║         ╚════██║██╔══╝  ██║     
███████║██║  ██╗██║███████╗███████╗    ███████║███████╗╚██████╗
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝

 █████╗ ██████╗  ██████╗ █████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝
███████║██████╔╝██║     ███████║██║  ██║█████╗  
██╔══██║██╔══██╗██║     ██╔══██║██║  ██║██╔══╝  
██║  ██║██║  ██║╚██████╗██║  ██║██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
```

*Accent: Marquee White. Every cabinet below runs its own color once you walk up to it.*

# 🕹️ skill-sec-arcade

A leveling-up arcade of [Claude Code](https://claude.com/claude-code) skills for AppSec and security engineering. Insert token, learn a skill, boss fight the vuln.

![Claude Code Plugin](https://img.shields.io/badge/claude--code-plugin-5A67D8)
![Skills](https://img.shields.io/badge/skills-11-brightgreen)
![Focus](https://img.shields.io/badge/focus-AppSec-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

This repo is a Claude Code **plugin**, and its own **marketplace**, so the whole cabinet installs in two commands:

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

No restart, no manual registration. Every skill under `skills/` gets picked up automatically.

## What's in the machine

| Cabinet | Operational Title | What it does | Insert token when... |
|---|---|---|---|
| [`cartridge-scanner`](skills/cartridge-scanner) | Repo inventory: languages, dependencies, IaC, and containers, then recommends scanning tools needed | Inventories a repo before any deep scanning starts: language/LOC breakdown (via `scc`), package manager and dependency counts, private/internal registry detection, IaC and container inventory, ending in a tailored, tool-agnostic rundown of what scanning capability the repo needs. | You want a size/dependency/IaC/container inventory, or you're asking "what security tools do I need for this repo." |
| [`dungeon-crawl-threat-map`](skills/dungeon-crawl-threat-map) | Threat modeler: architecture diagram plus STRIDE/OWASP walkthrough of the codebase | Reads a repo like an AppSec engineer on their first week: maps the architecture, draws an ASCII diagram, and threat models it with STRIDE, mapped to the OWASP Top 10 and Cheat Sheet Series. Teaching tone, not a scan report, built to be kept and reused. | You want a threat model, an attack-surface map, or a security-focused walkthrough of a codebase, not a validation of one specific finding. |
| [`mini-map`](skills/mini-map) | Threat model condenser: compresses a full report into a ~50-line context file | Condenses an existing `dungeon-crawl-threat-map` report into a hard-capped, ~50-line context file (overview, auth/SSO/session, hardening, trust boundaries, business logic invariants, known risk areas) other skills can load without reading the whole threat model. | You want a quick, reusable context file before reviewing a finding or planning a remediation, or another skill needs fast background on how this app is protected. |
| [`player-two-verdict`](skills/player-two-verdict) | Scanner finding investigator: confirms true/false positives with cited evidence from the repo | Independently investigates a pasted scanner finding (SAST/SCA/Secrets/IaC/DAST) against the real repo and returns a true positive, false positive, or needs-more-context verdict with cited evidence, instead of trusting the tool's severity rating. | You paste a Semgrep/Snyk/Trivy/etc. finding, a CVE/CWE, or ask "is this actually exploitable?" |
| [`tilt-check`](skills/tilt-check) | False-positive auditor: stress-tests an existing FP verdict before it gets closed | The inverse: takes a finding someone (human or AI) already marked False Positive and independently audits that verdict, trying to break the justification before agreeing to close it out. Always delegates the actual audit to a fresh, context-isolated subagent so the review can't be anchored by anything already discussed in this chat. | An FP/suppression writeup exists and you want a skeptical second opinion before it's trusted. |
| [`dead-weight-detector`](skills/dead-weight-detector) | Dependency health auditor: usage plus registry risk signals, recommends keep, inline, watch, or flag | Measures how much each direct OSS dependency is actually used in first-party code, cross-references that against live registry health signals (release recency, maintainers, downloads, known unpatched vulnerabilities), and recommends keep, inline it yourself, keep but watch, or flag for human judgment. The only skill in the arcade that needs live network access, for the registry health lookups. | You want to know if a dependency is worth keeping, or you're asking "should we drop this package and write it ourselves?" |
| [`trim-reaper`](skills/trim-reaper) | Dependency reduction engine: removes unused packages, replaces with stdlib, consolidates, applies one phase at a time | Reduces a repo's third-party dependencies with a security-first lens across 9 phases (baseline, remove-unused, stdlib replacement, small-utility replacement, consolidate overlapping libraries, reduce heavy trees, dev/prod scope, recommend-only larger replacements, final verification), applying every approved change itself with a build/test/lint check and automatic revert on failure. | You want to trim, prune, or audit dependencies and have the skill actually apply the approved changes, not just recommend them. |
| [`patch-for-the-high-score`](skills/patch-for-the-high-score) | Full remediation workflow: context-aware investigation, judgment call, and applied fix with PR | The full remediation workflow for a SAST/SCA/Secrets/IaC/DAST finding: loads app context from `mini-map`, investigates it to the same standard as `player-two-verdict`, judges an SCA patch-vs-upgrade tradeoff using `dead-weight-detector`'s health signals, gates on fix complexity, then plans, applies, diffs, and optionally PRs the fix. | You want a finding actually fixed, deliberately, with real app context and dependency health behind the call, not just triaged. (A container image finding routes to `cargo-hold-cleanup` instead.) |
| [`patch-boss-rush`](skills/patch-boss-rush) | Fast finding fixer: quick sanity check, fix plan, diff, and optional PR | A fast, fully self-contained remediation pass on one SAST/SCA/Secrets/IaC/DAST finding, no app-context loading, no dependency-health lookups, no delegation to any other skill. Own short sanity check, a fix plan, approval, diff, and an optional PR. | A finding looks simple and you want it fixed now, without the full context-gathering ceremony. (A container image finding routes to `cargo-hold-cleanup` instead.) |
| [`cargo-hold-cleanup`](skills/cargo-hold-cleanup) | Container finding remediator: fixes base-image CVEs and container config issues | Remediates container image findings specifically: resolves ownership to a base image OS package, build-installed binary, buildpack/builder, vendor image, injected sidecar, or image config layer, checks rebuild cadence and package necessity before proposing anything, then fixes it with a hard-required full-result-set regression check afterward. Hands off application dependency findings to the patch skills instead of remediating them here. | You have a container/base-image scan finding (Trivy/Grype/Snyk Container/Docker Scout) or a Dockerfile config finding like running as root, not a dependency-manifest finding. |
| [`cloud-player-perm-audit`](skills/cloud-player-perm-audit) | IAM overprovisioning reviewer: GRANTED minus USED per role, risk-ranked in plain language | Reviews one AWS account's IAM roles for granted-but-unused permissions using free, local, read-only data (IAM last-accessed reports, CloudTrail Event history), then runs cloudsplaining (required) plus optionally parliament/pmapper, and reports the excess grouped by risk tier with plain-language reasons and recommended actions. Review-only: never drafts a replacement policy, never applies anything to AWS. | You want an IAM/permissions audit, an overprovisioning review, or a blast-radius assessment for a role or team's roles. |

More cabinets get added as they're built, see [Adding a new skill](#adding-a-new-skill) below.

## Repo layout

```
skill-sec-arcade/
├── .claude-plugin/
│   ├── plugin.json                      ── plugin manifest (name, description, author)
│   └── marketplace.json                 ── catalog entry pointing "sec-arcade" -> ./
├── skills/
│   ├── cargo-hold-cleanup/              ── container image remediation: ownership resolution, fix, rescan
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── cartridge-scanner/               ── inventories a repo: languages, LOC, deps, IaC, containers
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── cloud-player-perm-audit/         ── IAM overprovisioning review: GRANTED - USED per role, risk-ranked
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── dead-weight-detector/            ── per-dependency usage + live registry health, keep vs. inline
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── dungeon-crawl-threat-map/        ── architecture diagram + STRIDE threat model
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── mini-map/                        ── condenses a threat model into a ~50-line context file
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── patch-boss-rush/                 ── fast, standalone fix for one finding, no other skill deps
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── patch-for-the-high-score/        ── full remediation workflow: analyze, plan, fix, diff, PR
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── player-two-verdict/              ── true/false-positive verdict on one pasted finding
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── tilt-check/                      ── skeptical re-audit of an existing False Positive verdict
│   │   ├── SKILL.md
│   │   └── README.md
│   └── trim-reaper/                     ── dependency reduction: remove unused, replace, consolidate, 9 phases
│       ├── SKILL.md
│       └── README.md
├── scripts/
│   ├── cartridge_scan.py                ── repo inventory helper, used by cartridge-scanner
│   ├── cloud_perm_audit.py              ── AWS IAM collect/analyze/normalize, used by cloud-player-perm-audit
│   ├── dead_weight_scan.py              ── usage + live health scan, used by dead-weight-detector
│   └── trim_reaper_scan.py              ── lifecycle-script, unpinned-version, candidate scans, used by trim-reaper
├── references/
│   ├── container-remediation-playbook.md ── container finding ownership table, templates, checklists
│   ├── iam-data-coverage-and-tools.md   ── IAM/CloudTrail data coverage + tool landscape lookup
│   ├── iam-excess-risk-tiers.md         ── IAM overprovisioning risk tiers and rubric
│   ├── language-attack-vectors.md       ── language/runtime -> common attack vector lookup
│   ├── owasp-cheat-sheet-series.md      ── full 120-sheet OWASP Cheat Sheet Series catalog
│   ├── owasp-top-ten-projects.md        ── full OWASP Top Ten family catalog (static reference)
│   ├── owasp-top10-cheatsheet-map.md    ── OWASP Web App Top 10:2025 -> Cheat Sheet Series lookup
│   ├── package-manager-commands.md      ── per-ecosystem install/remove/tree/why-installed commands, trim-reaper
│   ├── registry-health-signals.md       ── per-ecosystem registry health signal + OSV lookup
│   ├── security-scan-capability-map.md  ── ecosystem/file-type -> scanning capability lookup
│   ├── save-states.md                   ── shared "save this report to a file" convention
│   └── trim-reaper-phase-rules.md       ── trim-reaper's recommendation/report format, risk table, apply loop
├── templates/
│   └── SKILL.md.template                ── copy this to scaffold a new skill
├── LICENSE
└── README.md
```

New skill added? Update this tree and the table above.

- **`.claude-plugin/`**: the plugin manifest and marketplace catalog entry. This is what makes `/plugin install sec-arcade` work.
- **`skills/`**: one subfolder per skill. Claude scans every `skills/*/SKILL.md` at load time, matches the frontmatter `description` against what you're doing, and activates the skill automatically, no slash command needed. Currently eleven cabinets installed: [`cartridge-scanner`](skills/cartridge-scanner), [`dungeon-crawl-threat-map`](skills/dungeon-crawl-threat-map), [`mini-map`](skills/mini-map), [`player-two-verdict`](skills/player-two-verdict), [`tilt-check`](skills/tilt-check), [`dead-weight-detector`](skills/dead-weight-detector), [`trim-reaper`](skills/trim-reaper), [`patch-for-the-high-score`](skills/patch-for-the-high-score), [`patch-boss-rush`](skills/patch-boss-rush), [`cargo-hold-cleanup`](skills/cargo-hold-cleanup), and [`cloud-player-perm-audit`](skills/cloud-player-perm-audit) (see table above).
- **`scripts/`**: helper scripts a `SKILL.md` can shell out to. Currently holds `cartridge-scanner`'s repo inventory script, `dead-weight-detector`'s usage/health scan script, `trim-reaper`'s lifecycle-script/unpinned-version/candidate scan script, and `cloud-player-perm-audit`'s AWS IAM collect/analyze/normalize script (the one script here that shells out to a live AWS CLI and to locally-installed IAM tooling rather than reading repository files).
- **`references/`**: shared cheatsheets/checklists multiple skills can point at instead of duplicating content. Currently holds `cargo-hold-cleanup`'s container remediation playbook (ownership table, fix templates, no-fix decision order, verification checklist), `dungeon-crawl-threat-map`'s Web App Top 10 and language attack-vector lookups, the full OWASP Cheat Sheet Series catalog and the full OWASP Top Ten Projects catalog (the latter a static reference, not yet consumed by any skill), `cartridge-scanner`'s security scan capability map, `dead-weight-detector`'s registry health signal map, `trim-reaper`'s package-manager command lookup and phase-rules reference, `cloud-player-perm-audit`'s IAM data-coverage/tool-landscape lookup and risk-tier rubric, and the shared `save-states.md` convention used by every skill that offers to save its report to a file.
- **`templates/`**: `SKILL.md.template`, the starting point for scaffolding a new skill.

## Adding a new skill

```bash
cp templates/SKILL.md.template skills/<skill-name>/SKILL.md
```

Fill in the frontmatter:

```yaml
---
name: skill-name-here
description: What it does, and, critically, WHEN it should trigger.
---
```

The `description` is the only thing Claude reads to decide whether to reach for the skill, so front-load the trigger phrases (tool names, task shapes, things the user might literally type) rather than just summarizing the skill.

Optionally add a `README.md` next to it (see the triage reviewer's for the pattern: Overview → Prerequisites → Installation → Usage → example output → Limitations). `SKILL.md` is what Claude reads, `README.md` is what a human reads before installing it.

## License

[CC BY-SA 4.0](LICENSE): Attribution-ShareAlike 4.0 International. Fork the cabinet, remix the skills, just share alike and give credit.
