```
 _____  _______ _______ _____    ________ _______ _______ _______ _______ _______ 
|     \|    ___|   _   |     \  |  |  |  |    ___|_     _|     __|   |   |_     _|
|  --  |    ___|       |  --  | |  |  |  |    ___|_|   |_|    |  |       | |   |  
|_____/|_______|___|___|_____/  |________|_______|_______|_______|___|___| |___|  

 _____  _______ _______ _______ ______ _______ _______ ______ 
|     \|    ___|_     _|    ___|      |_     _|       |   __ \
|  --  |    ___| |   | |    ___|   ---| |   | |   -   |      <
|_____/|_______| |___| |_______|______| |___| |_______|___|__|
```

*Accent: Anchor Grey. The color of ballast you're not sure is still worth carrying.*

# 🏋️ Dead Weight Detector

*A cabinet in the [sec-arcade](../../): insert token when you want to know if a dependency is actually pulling its weight, or just dead weight in the pack.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Ecosystems](https://img.shields.io/badge/ecosystems-9-brightgreen)
![Focus](https://img.shields.io/badge/focus-dependency_hygiene-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that measures how much each direct OSS dependency is actually used in first-party code, cross-references that against live maintenance-health signals from the package's own registry, and recommends keep, watch, or replace with first-party code. Built for the dependency that got added for one function call and never got a second thought since.

## Overview

A dependency is a permanent commitment: it has to be kept patched, it's a supply-chain trust surface, and if the upstream project goes quiet that risk just sits there. Most of the time nobody revisits that commitment after the initial one-line add. This skill does the revisiting.

It quantifies usage (files touched, call sites, distinct symbols referenced) for every direct dependency, then, for the ones that look thin, goes and checks whether the package itself is still healthy: when it last shipped, how many maintainers it has, how widely it's downloaded, and whether the version actually pinned has a known unpatched vulnerability. It combines that with a qualitative read on how hard the used surface would be to hand-roll, and lands on one of four verdicts.

Run it, get back:

- A full usage-tier table for every direct dependency across nine ecosystems (cheap, no network)
- A deep-dive workup for the low-usage candidates: real call sites, live registry health data, replacement-complexity judgment
- A **KEEP** / **CANDIDATE TO INLINE** / **KEEP BUT WATCH** / **NEEDS HUMAN JUDGMENT** verdict per deep-dived dependency
- Every health claim cited back to a named registry field, never a vague "looks unmaintained"

## How it flows

```
    ┌──────────────────────────────────────────┐
    │ "Should we drop this dependency?"        │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 1. Run dead_weight_scan.py usage         │
    │ local only, no network, all 9 ecosystems │
    │ -> files, call sites, usage tier per dep │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 2. Full usage-tier table                 │
    │ every direct dependency gets a row       │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 3. Triage the deep-dive set              │
    │ minimal/light tier, capped at 15,        │
    │ + anything the user named directly       │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 4-5. Read call sites + live health check │
    │ recency, maintainers, downloads,         │
    │ version-scoped OSV vulnerability check   │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 6. Judge replacement complexity          │
    │ trivial to hand-roll, or not worth it    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 7. Final verdict                         │
    │ KEEP / CANDIDATE TO INLINE /             │
    │ KEEP BUT WATCH / NEEDS HUMAN JUDGMENT    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 8-9. Write the report, offer to save     │
    └──────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Python 3 on `$PATH` (the helper script is stdlib-only, `urllib.request` handles the HTTP calls, no extra packages)
- **Outbound network access is required for the health-check phase.** This is the one skill in the plugin that isn't offline-safe, Step 1 (usage scanning) is fully local, but Step 5 makes real calls to npm, PyPI, crates.io, RubyGems, Packagist, Maven Central, NuGet, pub.dev, Go's module proxy, and OSV.dev, whichever apply per dependency
- Run from inside the repository being analyzed, both for the local usage scan and to resolve pinned versions from lockfiles for the health check

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
cp -r /tmp/sec-arcade/skills/dead-weight-detector ~/.claude/skills/
mkdir -p ~/.claude/sec-arcade-standalone
cp -r /tmp/sec-arcade/scripts ~/.claude/sec-arcade-standalone/

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/dead-weight-detector .claude/skills/
```

`dead_weight_scan.py` imports helper functions from `cartridge_scan.py` at the module level, so both must stay in the same directory, copying the whole `scripts/` folder above (not the individual files) keeps that intact. `SKILL.md` also references both scripts via `${CLAUDE_PLUGIN_ROOT}/scripts/...`, an environment variable Claude Code only sets automatically for a full plugin install. For this standalone copy to work, set it yourself before launching Claude Code, e.g. add `export CLAUDE_PLUGIN_ROOT=~/.claude/sec-arcade-standalone` to your shell profile. Installing the whole arcade (Option 1) handles all of this automatically.

## Usage

Open Claude Code inside the repo you want audited, then ask directly:

```
Is this dependency worth keeping, or should we inline it?
```

```
Audit our dependencies, what's barely used and what's not well maintained?
```

```
Should we drop lodash and write our own version of what we actually use?
```

The skill runs the local usage scan first, triages candidates, then makes live registry calls only for the ones that need a closer look.

### Example run (excerpt)

```
## Deep Dive

### left-pad (npm)

**Usage**: 1 file, 1 call site, tier minimal
**What it's used for**: src/format.js:3, pads a single numeric ID to
3 digits before display.
**Health**: recency 2015-03-24 (over 12mo) · maintainers 1 · downloads
1,240,000/mo · vulnerabilities none -> slowing
**Replacement complexity**: trivial, `String(n).padStart(3, '0')` is
a one-line stdlib replacement for the entire used surface.

**Verdict: CANDIDATE TO INLINE**
Single call site, and what it does is now a JavaScript stdlib method.
No reason to carry an external dependency, network install, and
supply-chain surface for this.
```

## Limitations

- Usage-site counting is regex-based, not AST-aware. It can overcount when a bound identifier's name also appears inside the import path/module string itself, and it can miss usage through re-exports, dynamic imports, or heavy indirection. Treat tiers as directional, verify borderline cases by reading the cited call sites.
- Ruby and PHP usage detection is explicitly weaker (`"usage_signal": "weak"`), dynamic dispatch and PSR-4 autoloading defeat static symbol matching for those two ecosystems.
- Health-signal coverage varies a lot by ecosystem, see `references/registry-health-signals.md`. Go, Java, and .NET have no clean maintainer-count or download API, those fields report `n/a` honestly rather than a guess.
- PyPI download counts come from `pypistats.org`, a third-party service, not PyPI itself. If it's down or rate-limited, that one field degrades to unavailable, the rest of the health check still runs.
- The vulnerability check only forces an At Risk tier when the pinned version could actually be resolved from a lockfile. Without a lockfile, OSV results are shown for awareness but don't drive the tier.
- Not a substitute for a real SCA tool for CVE tracking over time. This skill's OSV check is a point-in-time read during the deep dive, not continuous monitoring.

## Next cabinet

[`cartridge-scanner`](../cartridge-scanner) is the natural predecessor: it inventories what dependencies exist across a repo, this skill picks up from there and asks whether each one earns its place. When an SCA finding needs an actual patch-vs-upgrade decision, not just a health read, [`patch-for-the-high-score`](../patch-for-the-high-score) reuses this skill's health-check script to make that call.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
