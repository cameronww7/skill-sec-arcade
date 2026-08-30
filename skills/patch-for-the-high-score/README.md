```
 _   _ _____ ____ _   _   ____   ____ ___  ____  _____
| | | |_   _/ ___| | | | / ___| / ___/ _ \|  _ \| ____|
| |_| | | || |  _| |_| | \___ \| |  | | | | |_) |  _|
|  _  | | || |_| |  _  |  ___) | |__| |_| |  _ <| |___
|_| |_| |_| \____|_| |_| |____/ \____\___/|_| \_\_____|
```

*Accent: High Score Gold. The color of the top of the leaderboard, earned, not handed out.*

# 🏆 Patch for the High Score

*A cabinet in the [sec-arcade](../../): insert coin when you want a finding actually fixed, deliberately, with real app context behind the call.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Workflow](https://img.shields.io/badge/workflow-analyze_%E2%86%92_plan_%E2%86%92_fix_%E2%86%92_PR-brightgreen)
![Focus](https://img.shields.io/badge/focus-remediation-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that takes a pasted security finding all the way from investigation to an applied, diffed fix, and optionally a PR. It reuses [`player-two-verdict`](../player-two-verdict)'s investigation methodology to decide if the finding is real, [`dead-weight-detector`](../dead-weight-detector)'s health-check script to judge whether an SCA fix should be a minimal patch or a fuller upgrade, and [`mini-map`](../mini-map)'s condensed app context to understand what a fix has to preserve. Nothing gets applied without your approval, nothing gets committed without you asking for a PR.

## Overview

Every other skill in this arcade stops at a verdict. This one closes the loop. Paste a finding, and it: loads app context, classifies the finding (first-party code, an OSS dependency, or a secret), investigates it to the same evidentiary standard `player-two-verdict` already holds findings to, and decides between false positive, fix now, or a rare, explicitly-justified defer.

For a genuine finding, it writes a plan short enough for a junior engineer to follow, checks the OWASP Cheat Sheet Series for relevant guidance, and gates on complexity: anything touching more than 2 files, requiring a schema/API change, or with an unclear blast radius stops and moves into Claude Code's plan mode instead of a quick apply. Everything else gets a plan, your approval, the fix, and a diff, never a commit you didn't ask for.

Run it, get back:

- A classification (first-party / OSS dependency / secret) and an evidence-cited verdict, same five-level confidence scale as `player-two-verdict`
- For secrets: an urgent rotation callout, first thing in the output, since this skill can't rotate a credential itself
- For SCA: a health-tier check via the same script `dead-weight-detector` uses, and an explicit minimal-patch-vs-full-upgrade choice when the package is stale, not a silent pick
- A max-6-sentence fix plan, with relevant OWASP Cheat Sheet Series guidance cited when it applies
- A stop into plan mode instead of a quick fix, for anything genuinely risky
- An applied fix, a full diff, and an offer to open a PR with a proposed branch name and title

## How it flows

```
    ┌───────────────────────────────────────────┐
    │ Paste a finding: "remediate this" /       │
    │ "fix this properly"                       │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 1. Setup & intake                         │
    │ parse finding, smoke test repo/branch,    │
    │ hard-require MINI_MAP.md (offer to        │
    │ generate it if missing)                   │
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
    │ 3. Analyze & decide                       │
    │ investigate like player-two-verdict ->    │
    │ FALSE POSITIVE / FIX NOW / DEFER          │
    │ secrets: rotate-now callout first         │
    │ SCA: dead_weight_scan.py health check ->  │
    │ patch vs. upgrade choice                  │
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
    │ 5. Apply & show diff                      │
    │ only after explicit approval, never       │
    │ committed automatically                   │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 6. Offer a PR                             │
    │ only on explicit yes: branch, commit,     │
    │ push, gh pr create                        │
    └───────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Run from inside the repository being fixed. This skill needs real file access and a working git tree.
- `.SEC-Arcade-save_states/MINI_MAP.md` in the target repo, or a willingness to generate one when prompted (which may in turn generate a threat model first).
- `gh` CLI installed and authenticated if you want the PR step to actually run, not just prepare a branch.

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
cp -r /tmp/sec-arcade/skills/patch-for-the-high-score ~/.claude/skills/
```

Note: standalone installs also need `player-two-verdict`, `mini-map`, `dead-weight-detector` (and its `scripts/dead_weight_scan.py`), and `references/{owasp-cheat-sheet-series,registry-health-signals,save-states}.md`, this skill relies on all of them. Installing the whole arcade (Option 1) avoids having to assemble that list by hand.

## Usage

Open Claude Code inside the repo with the finding, then paste it directly with intent:

```
Remediate this finding: [paste SAST/SCA/Secrets/IaC/DAST output]
```

```
Fix this properly, don't just tell me if it's real
```

### Example run (excerpt)

```
🛠️ FIRST-PARTY - FIX NOW | Confidence: High

Summary: User-supplied email is concatenated directly into a SQL query
with no parameterization, an attacker controlling that field can alter
the query.

Evidence:
- `src/db/users.js:47`, `getUserByEmail()`: builds the query via
  template-literal interpolation of the `email` parameter, no
  parameterization or escaping applied.

Fix Plan (max 6 sentences, junior-engineer clear):
1. Replace the template-literal query in `getUserByEmail()` with a
   parameterized query using the driver's placeholder syntax.
2. Pass `email` as a bound parameter instead of interpolating it into
   the string.
3. No other callers of this function need to change, the function
   signature stays the same.
4. See the SQL Injection Prevention Cheat Sheet for the parameterized
   query pattern this driver expects.

Action: apply the parameterized query, then review the diff.
```

## Limitations

- Requires `MINI_MAP.md` to exist first, by design, this is the slower, more thorough path. For a fast pass without that ceremony, use [`patch-boss-rush`](../patch-boss-rush).
- Processes one finding per run. Fixing code is more consequential than writing a verdict, batching would stack approvals and diffs in a way that's hard to review carefully.
- Never commits or pushes without an explicit "yes, open a PR." A "no" leaves the fix sitting uncommitted in your working tree.
- The complexity gate is a heuristic (file count, schema/API changes, blast radius clarity), not a guarantee. Anything it lets through the fast path is still worth reading the diff on before approving the next step.

## Next cabinet

For a faster, standalone pass on a probably-simple finding, without loading app context or dependency health data, see [`patch-boss-rush`](../patch-boss-rush).

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
