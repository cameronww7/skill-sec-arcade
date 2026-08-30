```
 ____   ___  ____ ____    ____  _   _ ____  _   _
| __ ) / _ \/ ___/ ___|  |  _ \| | | / ___|| | | |
|  _ \| | | \___ \___ \  | |_) | | | \___ \| |_| |
| |_) | |_| |___) |__) | |  _ <| |_| |___) |  _  |
|____/ \___/|____/____/  |_| \_\ \___/|____/|_| |_|
```

*Accent: Boss Bar Red. The color of a health bar with one hit left, move fast.*

# ⚡ Patch Boss Rush

*A cabinet in the [sec-arcade](../../): insert coin when a finding looks simple and you want it fixed now, no context-loading ceremony.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Workflow](https://img.shields.io/badge/workflow-check_%E2%86%92_plan_%E2%86%92_fix-brightgreen)
![Focus](https://img.shields.io/badge/focus-fast_remediation-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that fixes a single pasted security finding fast, with no dependency on any other skill in this plugin. No `.SEC-Arcade-save_states/MINI_MAP.md` requirement, no `dead_weight_scan.py` health lookup, no delegation to `player-two-verdict`'s investigation checklists. It does its own short, self-contained sanity check, plans a fix, applies it on your approval, and shows the diff.

## Overview

Not every finding is worth the full ceremony. A single obvious injection in one function, a secret that clearly needs rotating, a dependency with a one-line patched version, none of these need an app-context file loaded first. This skill is the fast lane: its own compact reachability check per finding type, then straight to a fix plan.

"Rush" describes how much ceremony one finding gets, not how many findings get processed at once, this still handles one finding per run, with its own approval, diff, and PR offer, same as its sibling.

Run it, get back:

- A quick classification (first-party / OSS dependency / secret) and a short, evidence-cited pass/fail check, plain confidence word instead of a five-level scale
- For secrets: the same urgent rotation callout as the sibling skill, first thing in the output
- A max-6-sentence fix plan, OWASP Cheat Sheet Series guidance cited when it genuinely applies
- The same complexity gate as the sibling skill: anything touching more than 2 files, a schema/API change, or an unclear blast radius stops and moves into plan mode instead of a quick apply
- An applied fix, a full diff, and an offer to open a PR

## How it flows

```
    ┌───────────────────────────────────────────┐
    │ Paste a finding: "just fix this" /        │
    │ "quick fix"                               │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 1. Parse & smoke test                     │
    │ own compact parsing, confirm repo/branch  │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 2. Classify                               │
    │ first-party / OSS dependency / secret     │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 3. Quick check                            │
    │ one short pass per type, own logic,       │
    │ secrets: rotate-now callout first         │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 4. Plan the fix                           │
    │ check OWASP cheat sheet map (advisory) -> │
    │ complexity gate: trivial -> quick plan,   │
    │ risky -> EnterPlanMode instead            │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 5-6. Apply, show diff, offer a PR         │
    │ only after explicit approval each step    │
    └───────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Run from inside the repository being fixed. This skill needs real file access and a working git tree.
- No `.SEC-Arcade-save_states/` artifacts required, this skill runs standalone.
- `gh` CLI installed and authenticated if you want the PR step to actually run.

## Installation

This skill ships as part of the [`sec-arcade`](https://github.com/cameronww7/skill-sec-arcade) Claude Code plugin.

### Option 1: Install the whole arcade (recommended)

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

### Option 2: Just this skill

```bash
git clone --depth 1 https://github.com/cameronww7/skill-sec-arcade.git /tmp/sec-arcade
cp -r /tmp/sec-arcade/skills/patch-boss-rush ~/.claude/skills/
```

Note: this skill only reads `references/owasp-cheat-sheet-series.md` as an optional advisory lookup, nothing else in the arcade. If installing standalone, copy that one file alongside it if you want the OWASP-guidance step to work.

## Usage

Open Claude Code inside the repo with the finding, then paste it with intent:

```
Just fix this: [paste SAST/SCA/Secrets/IaC/DAST output]
```

```
Quick fix, rush this one
```

### Example run (excerpt)

```
⚡ FIRST-PARTY - FIX NOW | Confidence: High

Summary: User-supplied email is concatenated directly into a SQL query
with no parameterization.

Evidence:
- `src/db/users.js:47`, `getUserByEmail()`: builds the query via
  template-literal interpolation of the `email` parameter.

Fix Plan (max 6 sentences, junior-engineer clear):
1. Replace the template-literal query with a parameterized query using
   the driver's placeholder syntax.
2. Pass `email` as a bound parameter instead of interpolating it.

Action: apply the parameterized query, then review the diff.
```

## Limitations

- No app context and no dependency health data behind its calls, by design. For a stale dependency where a patch-vs-upgrade tradeoff actually matters, or a fix that needs to respect business logic or auth flows a quick look won't surface, use [`patch-for-the-high-score`](../patch-for-the-high-score) instead.
- The Step 3 quick check is intentionally shallow, one hop, not a full call-graph trace. It can miss a false positive `player-two-verdict`'s deeper investigation would have caught.
- Same complexity gate as the sibling skill, but nothing else slows it down, still read the diff before approving.

## Next cabinet

For the deliberate, context-aware path, app context loaded, dependency staleness weighed, before deciding how to fix, see [`patch-for-the-high-score`](../patch-for-the-high-score).

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
