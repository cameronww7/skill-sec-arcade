```
 _____ ___ _   _____    ____ _   _ _____ ____ _  __
|_   _|_ _| | |_   _|  / ___| | | | ____/ ___| |/ /
  | |  | || |   | |   | |   | |_| |  _|| |   | ' / 
  | |  | || |___| |   | |___|  _  | |__| |___| . \ 
  |_| |___|_____|_|    \____|_| |_|_____\____|_|\_\
```

*Accent: Tilt Amber. The warning light that flashes when someone shakes the cabinet.*

# 🚨 Tilt Check

*A cabinet in the [sec-arcade](../../): insert token when someone, human or AI, has already called a finding a False Positive and you want a second, skeptical opinion before it gets suppressed for real.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Verdicts](https://img.shields.io/badge/verdicts-3-brightgreen)
![Focus](https://img.shields.io/badge/focus-FP_governance-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that independently re-investigates a finding that's already been marked a False Positive, to check whether that verdict actually holds up. It's the inverse of [`player-two-verdict`](../player-two-verdict): where that skill checks whether a scanner's "this is real" verdict is real, this skill checks whether a triage's "this isn't real" verdict is real.

## Overview

An AI agent (or a human, mid-backlog, at 4pm) triaging security findings can be wrong in a very specific way: it finds one plausible reason a finding looks safe, stops looking, and writes it up convincingly. A confident, well-cited False Positive writeup is not the same thing as a correct one, the citations can be genuine and the conclusion can still miss a second call site, a bypassable sanitizer, or a compensating control that only covers some of the routes.

This skill governs that process. It treats an existing FP verdict as a claim to be tested, not a fact to relay, audits every citation in the original justification, isolates the single load-bearing claim the verdict actually depends on, and tries directly to break it: unchecked call paths, sanitizer bypasses, indirect attacker influence, controls that don't cover every route, "already rotated" claims with no timestamp behind them.

Before any of that, it isolates itself. If the original FP verdict came from earlier in the same conversation, e.g. the triage skill just ran and then you asked for a second opinion, that conversation already contains the reasoning being challenged, and a re-check run inside it would just be that same reasoning agreeing with itself. So the actual audit always runs in a fresh, unforked subagent that starts with nothing but the raw finding, the FP claim, and repo access, no memory of what this session already believes about it.

Paste an existing FP verdict, get back:

- A governance verdict: Upheld, Overturned, or Insufficient Evidence
- A confidence level (five-tier scale)
- An audit of whether the original citations actually say what was claimed
- The specific load-bearing claim the original verdict depended on, and whether it survived
- What the original review missed, if anything
- A clear next action, including what to check next if the evidence genuinely isn't enough to close it out

## How it flows

```
    ┌──────────────────────────────────────────┐
    │ Paste an EXISTING False Positive         │
    │ verdict + its justification              │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 1. Isolate the review                    │
    │ spawn a FRESH subagent, zero shared      │
    │ history with this conversation, not      │
    │ a fork of it                             │
    │                                          │
    │ give it only: raw finding + FP           │
    │ verdict + justification, repo            │
    │ access, and steps 2-6 below              │
    │                                          │
    │ no environment for a subagent? say       │
    │ so, don't fake independence              │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 2. Parse the claim                       │
    │ original finding, FP verdict,            │
    │ cited evidence, stated reasoning         │
    │                                          │
    │ not actually FP -> stop, nothing         │
    │ adversarial to do here                   │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 3. One verdict, or many?                 │
    │                                          │
    │ same reasoning  -> audit the             │
    │ reasoning once, list every instance      │
    │                                          │
    │ unrelated       -> audit each,           │
    │ capped at 3-4 findings per run           │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 4. Attack the claim                      │
    │ a. Audit every citation: does it         │
    │    say what was claimed?                 │
    │ b. Find the load-bearing claim,          │
    │    attack it directly: bypass,           │
    │    other call path, indirect             │
    │    control, stale rotation claim         │
    │ c. Steelman the true positive            │
    │                                          │
    │ Goal: break the FP verdict before        │
    │ agreeing with it                         │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 5. Determine confidence                  │
    │ Very High -> High -> Medium ->           │
    │ Low -> Very Low                          │
    │ (in THIS audit's own call)               │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 6. Write the governance verdict          │
    │ UPHELD / OVERTURNED /                    │
    │ INSUFFICIENT EVIDENCE                    │
    │   -> treated as unresolved,              │
    │      never rubber-stamped                │
    │ + citation audit, gap, action            │
    │                                          │
    │ relayed back verbatim, not edited        │
    │ or softened by the parent                │
    └──────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Run from inside the repository the finding belongs to. This skill needs real file access to independently verify citations and search for call paths the original review might have missed.
- Subagent/task delegation available in your environment. The actual audit always runs in a fresh, non-forked subagent with no shared history, so the result isn't anchored to whatever this conversation already believes about the finding. Without that, the skill will say so rather than quietly running the "independent" check in a contaminated context.
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
cp -r /tmp/sec-arcade/skills/tilt-check ~/.claude/skills/

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/tilt-check .claude/skills/
```

Claude Code picks up skills from either location automatically, no restart or manual registration required.

## Usage

Open Claude Code inside the repo the finding came from, then paste the completed False Positive writeup, suppression justification, or ticket comment as-is.

```
Verdict: False Positive
Finding: Missing CSRF middleware on payment POST route (src/routes/payment.js:42)
Justification: Route uses bearer token auth, not cookies, so CSRF
doesn't apply. Confirmed in src/middleware/auth.js:18.
```

Or trigger it explicitly:

```
Double-check this false positive call: [paste]
```

```
Audit this triage result before we suppress it: [paste]
```

The skill works silently and returns a single structured governance block.

### Example run

```
🟢 UPHELD | Confidence: High

Summary: The original False Positive call was right. This route only
takes a manually-attached bearer token, never a browser-attached
cookie, so there's no CSRF risk here, and that holds for every route
in the file, not just the one the original review checked.

Original verdict: False Positive, CSRF doesn't apply because auth
is bearer-token based, not session/cookie based.

Load-bearing claim: This route has no ambient credential (cookie
or session) that a forged cross-site request could ride on.

Citation audit:
- `src/middleware/auth.js:18` (cited as: validates a signed bearer
  token, rejects if absent): HOLDS UP: `requireApiAuth()` reads the
  `Authorization` header and rejects the request when it's missing

Independent evidence:
- `src/routes/payment.js:5-42`: all five routes in this file call
  `router.use(requireApiAuth)`, none register a session-based auth
  path as a fallback
- `src/app.js`: no `express-session` or cookie-session middleware
  is registered anywhere in the app

Justification:
- `src/middleware/auth.js:18` confirms the only credential this
  route accepts is a bearer token, which the browser never attaches
  automatically the way it does a session cookie
- `src/routes/payment.js:5-42` shows this holds for every route in
  the file, not just the one line the original review cited
- `src/app.js` rules out a session fallback existing anywhere else
  in the app that could still be exposed to CSRF
- the load-bearing claim holds under a broader check than the
  original review ran

Action: Upheld, suppress as originally justified. No further work.
```

## What this skill does and doesn't replace

- It doesn't re-run first-pass triage. If you paste a raw, unverdicted scanner finding, that's [`player-two-verdict`](../player-two-verdict)'s job.
- It doesn't confirm True Positive verdicts. It exists specifically to pressure-test dismissals; a finding already marked True Positive doesn't need this skill.
- It doesn't defer to "insufficient evidence, so the FP stands." Insufficient evidence means the suppression isn't earned yet, the output routes those to further review instead of silently upholding them.

## Multiple findings

Findings sharing one suppression rationale (same reasoning applied across several instances) are audited once and reported as a single verdict with every instance listed. Unrelated findings are capped at 3-4 per run to avoid cross-contaminating evidence between independent audits in the same context window. Larger batches get flagged so you can split them up.

## Limitations

- Requires repo access. It can't independently verify a citation it can't go read.
- Confidence tracks the strength of this skill's own audit, not the original reviewer's stated confidence, a Very High confidence FP claim with unchecked call paths can still get overturned.
- Not a replacement for judgment on genuinely ambiguous cases. It's built to catch the specific failure mode of a confident, plausible, but incomplete dismissal, not to relitigate every closed finding forever.

## Next cabinet

[`player-two-verdict`](../player-two-verdict) is the inverse of this skill: it's the one producing the first-pass FP verdicts this skill exists to double-check.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
