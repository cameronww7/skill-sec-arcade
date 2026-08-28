# 🕹️ skill-sec-arcade

A leveling-up arcade of [Claude Code](https://claude.com/claude-code) skills for AppSec and security engineering. Insert coin, learn a skill, boss fight the vuln.

![Claude Code Plugin](https://img.shields.io/badge/claude--code-plugin-5A67D8)
![Skills](https://img.shields.io/badge/skills-4-brightgreen)
![Focus](https://img.shields.io/badge/focus-AppSec-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

This repo is a Claude Code **plugin**, and its own **marketplace**, so the whole cabinet installs in two commands:

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

No restart, no manual registration. Every skill under `skills/` gets picked up automatically.

## What's in the machine

| Cabinet | What it does | Insert coin when... |
|---|---|---|
| [`player-two-verdict`](skills/player-two-verdict) | Independently investigates a pasted scanner finding (SAST/SCA/Secrets/IaC/DAST) against the real repo and returns a true/false-positive verdict with cited evidence, instead of trusting the tool's severity rating. | You paste a Semgrep/Snyk/Trivy/etc. finding, a CVE/CWE, or ask "is this actually exploitable?" |
| [`tilt-check`](skills/tilt-check) | The inverse: takes a finding someone (human or AI) already marked False Positive and independently audits that verdict, trying to break the justification before agreeing to close it out. | An FP/suppression writeup exists and you want a skeptical second opinion before it's trusted. |
| [`dungeon-crawl-threat-map`](skills/dungeon-crawl-threat-map) | Reads a repo like an AppSec engineer on their first week: maps the architecture, draws an ASCII diagram, and threat models it with STRIDE, mapped to the OWASP Top 10 and Cheat Sheet Series. Teaching tone, not a scan report, built to be kept and reused. | You want a threat model, an attack-surface map, or a security-focused walkthrough of a codebase, not a validation of one specific finding. |
| [`cartridge-scanner`](skills/cartridge-scanner) | Inventories a repo before any deep scanning starts: language/LOC breakdown (via `scc`), package manager and dependency counts, private/internal registry detection, IaC and container inventory, ending in a tailored, tool-agnostic rundown of what scanning capability the repo needs. | You want a size/dependency/IaC/container inventory, or you're asking "what security tools do I need for this repo." |

More cabinets get added as they're built, see [Adding a new skill](#adding-a-new-skill) below.

## Repo layout

```
skill-sec-arcade/
├── .claude-plugin/
│   ├── plugin.json                      ── plugin manifest (name, description, author)
│   └── marketplace.json                 ── catalog entry pointing "sec-arcade" -> ./
├── skills/
│   ├── cartridge-scanner/               ── inventories a repo: languages, LOC, deps, IaC, containers
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── dungeon-crawl-threat-map/        ── architecture diagram + STRIDE threat model
│   │   ├── SKILL.md
│   │   └── README.md
│   ├── player-two-verdict/              ── true/false-positive verdict on one pasted finding
│   │   ├── SKILL.md
│   │   └── README.md
│   └── tilt-check/                      ── skeptical re-audit of an existing False Positive verdict
│       ├── SKILL.md
│       └── README.md
├── scripts/
│   └── cartridge_scan.py                ── repo inventory helper, used by cartridge-scanner
├── references/
│   ├── language-attack-vectors.md       ── language/runtime -> common attack vector lookup
│   ├── owasp-top10-cheatsheet-map.md    ── OWASP Top 10:2025 -> Cheat Sheet Series lookup
│   └── security-scan-capability-map.md  ── ecosystem/file-type -> scanning capability lookup
├── templates/
│   └── SKILL.md.template                ── copy this to scaffold a new skill
├── LICENSE
└── README.md
```

New skill added? Update this tree and the table above.

- **`.claude-plugin/`**: the plugin manifest and marketplace catalog entry. This is what makes `/plugin install sec-arcade` work.
- **`skills/`**: one subfolder per skill. Claude scans every `skills/*/SKILL.md` at load time, matches the frontmatter `description` against what you're doing, and activates the skill automatically, no slash command needed. Currently four cabinets installed: [`player-two-verdict`](skills/player-two-verdict), [`tilt-check`](skills/tilt-check), [`dungeon-crawl-threat-map`](skills/dungeon-crawl-threat-map), and [`cartridge-scanner`](skills/cartridge-scanner) (see table above).
- **`scripts/`**: helper scripts a `SKILL.md` can shell out to. Currently holds `cartridge-scanner`'s repo inventory script.
- **`references/`**: shared cheatsheets/checklists multiple skills can point at instead of duplicating content. Currently holds `dungeon-crawl-threat-map`'s OWASP Top 10 and language attack-vector lookups, and `cartridge-scanner`'s security scan capability map.
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
