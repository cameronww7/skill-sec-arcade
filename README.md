# 🕹️ skill-sec-arcade

A leveling-up arcade of [Claude Code](https://claude.com/claude-code) skills for AppSec and security engineering. Insert coin, learn a skill, boss fight the vuln.

![Claude Code Plugin](https://img.shields.io/badge/claude--code-plugin-5A67D8)
![Skills](https://img.shields.io/badge/skills-1-brightgreen)
![Focus](https://img.shields.io/badge/focus-AppSec-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

This repo is a Claude Code **plugin** — and its own **marketplace** — so the whole cabinet installs in two commands:

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

No restart, no manual registration. Every skill under `skills/` gets picked up automatically.

## What's in the machine

| Cabinet | What it does | Insert coin when... |
|---|---|---|
| [`security-detection-second-triage-reviewer`](skills/security-detection-second-triage-reviewer) | Independently investigates a pasted scanner finding (SAST/SCA/Secrets/IaC/DAST) against the real repo and returns a true/false-positive verdict with cited evidence, instead of trusting the tool's severity rating. | You paste a Semgrep/Snyk/Trivy/etc. finding, a CVE/CWE, or ask "is this actually exploitable?" |

More cabinets get added as they're built — see [Adding a new skill](#adding-a-new-skill) below.

## Repo layout

```
skill-sec-arcade/
├── .claude-plugin/
│   ├── plugin.json        ── plugin manifest (name, description, author)
│   └── marketplace.json   ── catalog entry pointing "sec-arcade" -> ./
├── skills/
│   └── <skill-name>/
│       ├── SKILL.md       ── auto-discovered by Claude Code, one per skill
│       └── README.md      ── human-facing docs for that skill (optional)
├── scripts/                ── helper scripts a SKILL.md can shell out to
├── references/             ── shared cheatsheets/checklists skills can point at
├── templates/
│   └── SKILL.md.template  ── copy this to scaffold a new skill
├── LICENSE
└── README.md
```

- **`.claude-plugin/`** — the plugin manifest and marketplace catalog entry. This is what makes `/plugin install sec-arcade` work.
- **`skills/`** — one subfolder per skill. Claude scans every `skills/*/SKILL.md` at load time, matches the frontmatter `description` against what you're doing, and activates the skill automatically — no slash command needed. Currently one cabinet installed: [`security-detection-second-triage-reviewer`](skills/security-detection-second-triage-reviewer) (see table above).
- **`scripts/`** — helper scripts a `SKILL.md` can shell out to. Empty until a skill needs one.
- **`references/`** — shared cheatsheets/checklists multiple skills can point at instead of duplicating content. Empty until a skill needs one.
- **`templates/`** — `SKILL.md.template`, the starting point for scaffolding a new skill.

## Adding a new skill

```bash
cp templates/SKILL.md.template skills/<skill-name>/SKILL.md
```

Fill in the frontmatter:

```yaml
---
name: skill-name-here
description: What it does, and — critically — WHEN it should trigger.
---
```

The `description` is the only thing Claude reads to decide whether to reach for the skill, so front-load the trigger phrases (tool names, task shapes, things the user might literally type) rather than just summarizing the skill.

Optionally add a `README.md` next to it (see the triage reviewer's for the pattern: Overview → Prerequisites → Installation → Usage → example output → Limitations) — `SKILL.md` is what Claude reads, `README.md` is what a human reads before installing it.

## License

[CC BY-SA 4.0](LICENSE) — Attribution-ShareAlike 4.0 International. Fork the cabinet, remix the skills, just share alike and give credit.
