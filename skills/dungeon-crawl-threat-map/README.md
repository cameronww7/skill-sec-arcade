```
______ _   _ _   _ _____  _____ _____ _   _   _____ ______  ___  _    _ _     
|  _  \ | | | \ | |  __ \|  ___|  _  | \ | | /  __ \| ___ \/ _ \| |  | | |    
| | | | | | |  \| | |  \/| |__ | | | |  \| | | /  \/| |_/ / /_\ \ |  | | |    
| | | | | | | . ` | | __ |  __|| | | | . ` | | |    |    /|  _  | |/\| | |    
| |/ /| |_| | |\  | |_\ \| |___\ \_/ / |\  | | \__/\| |\ \| | | \  /\  / |____
|___/  \___/\_| \_/\____/\____/ \___/\_| \_/  \____/\_| \_\_| |_/\/  \/\_____/

 _____ _   _ ______ _____  ___ _____  ___  ___  ___  ______ 
|_   _| | | || ___ \  ___|/ _ \_   _| |  \/  | / _ \ | ___ \
  | | | |_| || |_/ / |__ / /_\ \| |   | .  . |/ /_\ \| |_/ /
  | | |  _  ||    /|  __||  _  || |   | |\/| ||  _  ||  __/ 
  | | | | | || |\ \| |___| | | || |   | |  | || | | || |    
  \_/ \_| |_/\_| \_\____/\_| |_/\_/   \_|  |_/\_| |_/\_|    
```

*Accent: Dungeon Violet. Deep purple, the color of an unlit passage on the map screen.*

# 🗺️ Dungeon Crawl: Threat Map

*A cabinet in the [sec-arcade](../../): insert coin when you want to understand a codebase's shape, not just scan its lines.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Framework](https://img.shields.io/badge/framework-STRIDE-brightgreen)
![Focus](https://img.shields.io/badge/focus-threat_modeling-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that reads a repo the way a new AppSec engineer would on their first week: builds a mental model of what the system does and how its pieces talk to each other, then reasons about where that shape creates risk. It produces an ASCII architecture diagram, a plain-language walkthrough, and a STRIDE-driven threat breakdown mapped to the OWASP Top 10 and the OWASP Cheat Sheet Series, written to be kept, not skimmed once and discarded.

## Overview

A SAST or SCA tool finds instances of bad patterns: this line is injectable, this package has a CVE. That's a different job from understanding how a system is *shaped* and where that shape creates risk on its own, independent of any single bad line. A clean scan can still sit inside an architecture with no trust boundary between the public internet and an admin API.

This skill does that second job. It's explicitly **not** a SAST/SCA replacement and doesn't try to find every instance of every bad pattern. It's an architecture-level understanding exercise, written like a mentor teaching AppSec concepts, terms defined as they come up, every claim backed by a file:line citation or explicitly marked as architectural.

Point it at a repo, get back:

- An ASCII diagram of the components, data flows, and trust boundaries
- A plain-language "what this does" section anyone on the team can read
- A "Worth a Second Look" checklist: notable authentication gaps, risky cryptography, weak access control, and anything else that catches attention during recon, each a quick file:line nudge to go check it yourself
- A STRIDE threat breakdown per component and trust boundary, each rated with a plain Likelihood × Impact matrix
- OWASP Top 10 tags with the specific Cheat Sheet Series sheet to read for remediation
- Language-specific attack vector notes, only where the codebase actually has supporting code for them
- A prioritized action list, highest risk first
- A glossary of every term used, so it's readable by someone without a security background
- An offer to save the whole thing to a markdown file for reuse

## How it flows

```
    ┌──────────────────────────────────────────┐
    │ "Threat model this repo"                 │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 1. Recon                                 │
    │ language/framework, entry points,        │
    │ integrations, secrets handling           │
    │ (large monorepo? ask user to scope)      │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 2. Map the architecture                  │
    │ components, trust boundaries, data flows │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 3. Explain what it does                  │
    │ plain-language overview, before any      │
    │ threat talk                              │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 4. Worth a Second Look                   │
    │ fast checklist: auth gaps, risky crypto, │
    │ weak access control, other notables      │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 5-7. Threat model                        │
    │ STRIDE per component/boundary  ->        │
    │ OWASP Top 10 + Cheat Sheet tags ->       │
    │ language-specific vectors                │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 8. Rate each threat                      │
    │ Likelihood x Impact -> risk tier         │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 9. Write the report                      │
    │ diagram + overview + worth-a-look list + │
    │ threats + OWASP + actions + glossary     │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 10. Offer to save                        │
    │ keep inline, or write to THREAT_MODEL.md │
    └──────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Run from inside the repository being modeled. This skill needs real file access: it reads manifests, source, and config to build the architecture map.
- No additional dependencies, API keys, or configuration required

## Installation

This skill ships as part of the [`sec-arcade`](https://github.com/cameronww7/skill-sec-arcade) Claude Code plugin.

### Option 1: Install the whole arcade (recommended)

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

You get this skill plus every other skill added to the arcade over time.

### Option 2: Just this skill

Copy this folder into your personal or project skills directory:

```bash
# personal, applies in every project
git clone --depth 1 https://github.com/cameronww7/skill-sec-arcade.git /tmp/sec-arcade
cp -r /tmp/sec-arcade/skills/dungeon-crawl-threat-map ~/.claude/skills/
mkdir -p ~/.claude/sec-arcade-standalone
cp -r /tmp/sec-arcade/references ~/.claude/sec-arcade-standalone/

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/dungeon-crawl-threat-map .claude/skills/
```

Note: if installing standalone (not via the whole plugin), also copy `references/owasp-top10-cheatsheet-map.md`, `references/owasp-cheat-sheet-series.md`, and `references/language-attack-vectors.md` from the arcade repo, per the command above. `SKILL.md` points at them via `${CLAUDE_PLUGIN_ROOT}/references/...`, not a relative path, and that variable is only set automatically for a full plugin install. For this standalone copy to work, set it yourself before launching Claude Code, e.g. add `export CLAUDE_PLUGIN_ROOT=~/.claude/sec-arcade-standalone` to your shell profile.

Claude Code picks up skills from either location automatically, no restart or manual registration required.

## Usage

Open Claude Code inside the repo you want modeled, then ask directly:

```
Threat model this repo
```

```
Map the attack surface of this service
```

```
Walk me through the security risks in this codebase
```

For a large monorepo, the skill will ask you to scope to a specific service or directory before it starts, rather than guessing.

### Example excerpt

```
## Worth a Second Look

### Authentication
- 🔑 `src/routes/admin.js:61`, `router.post('/export', exportUsers)`: no
  auth middleware in this handler's chain, unlike every other `/admin/*`
  route in the file, which all call `requireAdmin` first.

### Cryptography
- 🔐 `src/utils/tokens.js:12`, `generateResetToken()`: builds the
  password-reset token from `Math.random()`, not a cryptographically
  secure source, the token is guessable.
```

```
## Threats (STRIDE)

### API -> Database boundary

- 🔴 **Tampering**: data crossing this boundary can be modified in
  transit or via an injectable query if it isn't parameterized.
  Evidence: `src/db/users.js:47`, `getUserByEmail()`: builds a SQL
  string via template literal interpolation of the `email` request
  parameter, no parameterization or escaping applied.
  Likelihood: High · Impact: High → 🔴 High risk
  OWASP: A05 Injection, see SQL Injection Prevention Cheat Sheet
```

## Limitations

- Not a SAST/SCA replacement. It doesn't enumerate every instance of a pattern the way a scanner does, it reasons about architecture-level risk. Run an actual scanner (and, for individual findings, [`player-two-verdict`](../player-two-verdict)) alongside this, not instead of it.
- A point-in-time snapshot. It reflects the code as it stands when run, not runtime behavior, deployed configuration, or infrastructure the repo doesn't describe.
- Depth scales with repo size. For a very large or unfamiliar codebase, scope it to one service at a time for a report that's actually useful rather than too dense to act on.

## Next cabinet

Once a threat model exists, [`mini-map`](../mini-map) condenses it into a ~50-line context file other skills can load quickly, no need to reload this whole report every time something needs a reminder of how this app is protected.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
