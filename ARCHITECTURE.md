# Architecture

This repository is a Claude Code plugin named `sec-arcade`: an arcade-themed collection of skills for AppSec and security engineering. It is simultaneously the plugin itself and its own marketplace — `.claude-plugin/plugin.json` defines the plugin, and `.claude-plugin/marketplace.json` lists it with a self-referential `source: "./"`.

## Top-level layout

- `skills/` — one directory per skill, each containing exactly `SKILL.md` (the skill's instructions, with YAML frontmatter defining `name` and a trigger-phrase-laden `description`) and `README.md` (human-facing docs). Skills hold no code or reference docs of their own; everything shared lives centrally at the repo root.
- `scripts/` — Python helpers shared across skills: `cartridge_scan.py`, `dead_weight_scan.py`, `abandoned_packages.py`. A skill invokes one of these via `${CLAUDE_PLUGIN_ROOT}/scripts/<name>.py` in its `SKILL.md` instructions. Currently three skills do this: `cartridge-scanner` (→ `cartridge_scan.py`), `dead-weight-detector` (→ `dead_weight_scan.py`), and `patch-for-the-high-score` (→ both, as part of its broader remediation workflow). These scripts are deliberately stdlib-only (see `CLAUDE.md`'s "Dependencies" section) so they can run safely against untrusted target repos without an install step.
- `references/` — shared markdown reference docs (OWASP mappings, attack-vector data, remediation playbooks, registry health-signal thresholds, etc.) consumed by multiple skills rather than duplicated per-skill. Seven of the nine skills use at least one of these; the two that don't (`player-two-verdict`, `tilt-check`) are self-contained investigation/triage skills that work directly off a pasted finding.
- `templates/` — `SKILL.md.template`, the scaffold new skills are authored from.

When adding a new skill, follow the existing `skills/*/SKILL.md` pattern (frontmatter + themed heading + "Why this skill exists" + numbered "Step N" sections, starting with a `Step 0: Prerequisite check` that verifies whatever that skill needs before its real work starts) rather than inventing a new shape.

## Why the plugin-only distribution model was chosen

`README.md` documents exactly one supported install path: `/plugin marketplace add ...` followed by `/plugin install sec-arcade`, a full-plugin install. Every one of the nine `SKILL.md` files references shared resources exclusively via `${CLAUDE_PLUGIN_ROOT}/scripts/...` and `${CLAUDE_PLUGIN_ROOT}/references/...`, an environment variable that Claude Code only populates when this repo is loaded as an installed plugin. Standalone per-skill copying (pulling a single `skills/<name>/` folder out to `~/.claude/skills/`) isn't a supported use case here: `${CLAUDE_PLUGIN_ROOT}` wouldn't resolve in that context regardless of where `scripts/` or `references/` physically live, so keeping them centralized at the repo root, rather than duplicated per-skill, matches the one distribution model this repo actually supports.
