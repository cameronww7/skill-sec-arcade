```
 _____ ____  ___ __  __ 
|_   _|  _ \|_ _|  \/  |
  | | | |_) || || |\/| |
  | | |  _ < | || |  | |
  |_| |_| \_\___|_|  |_|

 ____  _____    _    ____  _____ ____  
|  _ \| ____|  / \  |  _ \| ____|  _ \ 
| |_) |  _|   / _ \ | |_) |  _| | |_) |
|  _ <| |___ / ___ \|  __/| |___|  _ < 
|_| \_\_____/_/   \_\_|   |_____|_| \_\
```

*Accent: Pale Green. The color on the leaderboard screen right before it asks for your name.*

# ☠️ Trim Reaper

**Operational Title: Dependency Reduction Engine**
Removes confirmed-unused dependencies, replaces what the standard library already covers, consolidates overlapping libraries, shrinks heavy transitive trees, fixes dev/prod scope mistakes, and recommends larger replacements, one phase at a time, with a developer approving every change.

*A cabinet in the [sec-arcade](../../): insert token when a dependency's maintenance cost has stopped being worth it, and you're ready to actually do something about it, not just hear about it.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Phases](https://img.shields.io/badge/phases-9-brightgreen)
![Focus](https://img.shields.io/badge/focus-dependency_reduction-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that reduces a repo's third-party dependencies with a security-first lens, and applies every approved change itself, one package at a time, with a build/test/lint check after each. Built for the dependency that nobody's touched since the one PR that added it, the lockfile that's grown a transitive tree nobody can explain, and the `devDependency` quietly running in production.

## Overview

[`cartridge-scanner`](../cartridge-scanner) tells you what dependencies exist. [`dead-weight-detector`](../dead-weight-detector) tells you which ones look unhealthy or barely used. Neither one touches anything. This skill is the one that does: it finds a candidate, shows its evidence, waits for a developer to say which numbers to apply, applies them one at a time, verifies nothing broke, and reverts on its own if something did.

It runs as nine phases, numbered 0 through 8, one phase per invocation, never chained automatically:

| Phase | What it does |
|---|---|
| 0 | Baseline: branch, commands, runtime floor, existing dependency/install-script inventory |
| 1 | Remove confirmed-unused dependencies, searched across 9 separate evidence categories |
| 2 | Replace a dependency with the standard library, where every call site maps cleanly |
| 3 | Replace narrow, well-defined utility dependencies with a small first-party module |
| 4 | Consolidate overlapping libraries doing the same job |
| 5 | Reduce heavy transitive trees pulled in by one direct dependency |
| 6 | Separate development from production, fix manifest scope mistakes |
| 7 | Evaluate larger replacements, recommend only, nothing applied |
| 8 | Fresh-worktree verification, manifest/lockfile/docs/SBOM updates, final report |

## How it flows

```
    ┌──────────────────────────────────────────┐
    │ "Can we trim our dependencies?"          │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ Phase 0: Baseline                        │
    │ branch, commands, runtime floor,          │
    │ dependency + install-script inventory    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ Phases 1-6: find candidates, show        │
    │ evidence, wait for approval, apply one   │
    │ at a time, verify, revert on failure     │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ Phase 7: recommend-only                  │
    │ larger replacements, nothing applied     │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ Phase 8: fresh-worktree verification,    │
    │ manifest/lockfile/SBOM updates,          │
    │ final report                             │
    └──────────────────────────────────────────┘
```

Every phase stops and waits, `/trim-reaper next` picks up wherever the last run left off, `/trim-reaper status` shows progress without touching anything.

## Supported ecosystems

Same ten `cartridge-scanner` already covers: JavaScript (npm/yarn/pnpm), Python, Go, Java (Maven/Gradle/Ivy), Ruby, PHP, Rust, .NET (NuGet/Paket), Dart, and C/C++ (Conan/vcpkg). Per-ecosystem install/remove/tree/why-installed/production-only-install commands, and which unused-dependency-detection tool exists for each (several don't have one, that's stated plainly rather than guessed at), live in `references/package-manager-commands.md`.

Workspace/monorepo separation (evaluating each workspace on its own, since a package unused in one may be used in, or hoisted into, another) is genuine for JavaScript, Rust, and Go, the three ecosystems with a common multi-manifest-per-repo convention. Every other ecosystem is treated as one implicit workspace at the repo root.

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Python 3 on `$PATH` (every scan script here is stdlib-only, no install step)
- A clean git working tree, Phase 0 creates a dedicated `trim-reaper/<date>` branch and refuses to start on top of uncommitted work
- Run from inside the repository being analyzed

## Installation

This skill ships as part of the [`sec-arcade`](https://github.com/cameronww7/skill-sec-arcade) Claude Code plugin.

### Option 1: Install the whole arcade (recommended)

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

You get this skill plus every other skill added to the arcade over time.

### Option 2: Just this skill

```bash
# personal, applies in every project
git clone --depth 1 https://github.com/cameronww7/skill-sec-arcade.git /tmp/sec-arcade
cp -r /tmp/sec-arcade/skills/trim-reaper ~/.claude/skills/
mkdir -p ~/.claude/sec-arcade-standalone
cp -r /tmp/sec-arcade/scripts ~/.claude/sec-arcade-standalone/

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/trim-reaper .claude/skills/
```

`trim_reaper_scan.py` imports helper functions from both `cartridge_scan.py` and `dead_weight_scan.py` at the module level, so all three must stay in the same directory, copying the whole `scripts/` folder above (not individual files) keeps that intact. `SKILL.md` also references shared scripts and reference docs via `${CLAUDE_PLUGIN_ROOT}/...`, an environment variable Claude Code only sets automatically for a full plugin install. For this standalone copy to work, set it yourself before launching Claude Code, e.g. add `export CLAUDE_PLUGIN_ROOT=~/.claude/sec-arcade-standalone` to your shell profile. Installing the whole arcade (Option 1) handles all of this automatically.

## Usage

Open Claude Code inside the repo you want trimmed, then ask directly:

```
Can we trim our dependencies?
```

```
Audit our dependency tree and remove what's actually unused.
```

```
Do we really need lodash, or can we use the standard library?
```

Or run a specific phase directly:

```
/trim-reaper 1
```

```
/trim-reaper next
```

```
/trim-reaper status
```

### Example run (excerpt, Phase 1)

```
## Phase 1: Remove confirmed unused dependencies

| # | Package | Proposed action | Evidence | Risk rank | Transitive packages affected | Flags |
|---|---------|------------------|----------|-----------|-------------------------------|-------|
| 1 | left-pad | Remove | Zero references across all 9 search categories | High (unpinned, no install script) | 0 | - |

**This is a candidate list, not proof.** left-pad showed no source imports,
no dynamic-loading sites, no string references, no tool-config or script
mentions, and no Dockerfile/CI mentions anywhere in the repo.

Reply with which numbers to apply, "all", or "none".
```

```
> all

Removed left-pad via `npm uninstall left-pad`. Build passed, tests passed,
lint passed. Committed as trim-reaper(p1): remove left-pad: zero
references across all 9 search categories.
```

## Limitations

- Phase 1's candidate search is a heuristic text sweep, not a real parser or data-flow analysis. It can miss a genuinely obscure reference, a dynamic string built by concatenating pieces across several files, for example, and it is deliberately biased toward over-flagging a dynamic-loading risk rather than under-flagging it. A zero-reference result is evidence to review, never a removal order on its own.
- Lifecycle-script and build-hook detection can only see a dependency's own manifest when it's physically present on disk (a local `node_modules` checkout, a vendored crate). A dependency resolved only from a lockfile, nothing installed yet, can't be checked and is reported as unverifiable, never as clean.
- This skill does not evaluate CVEs or known vulnerabilities. That's [`patch-for-the-high-score`](../patch-for-the-high-score) or [`player-two-verdict`](../player-two-verdict); this skill's own security angle is supply-chain hygiene (install scripts, unpinned versions, maintenance health), not CVE data.
- Phase 7's larger-replacement comparisons and Phase 1's risk ranking call `dead_weight_scan.py health`, which makes live network calls to each ecosystem's public registry. Every other phase is fully offline.
- This skill never writes tests. New local modules from Phase 3 are flagged "needs tests" for a separate process, not written here.

## Next cabinet

[`cartridge-scanner`](../cartridge-scanner) and [`dead-weight-detector`](../dead-weight-detector) are the natural predecessors, one inventories what exists, the other recommends what's worth keeping. This skill is where that recommendation actually turns into a diff. When a Phase 7 recommendation turns out to need an actual CVE-driven patch-vs-upgrade decision, [`patch-for-the-high-score`](../patch-for-the-high-score) picks up from there.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
