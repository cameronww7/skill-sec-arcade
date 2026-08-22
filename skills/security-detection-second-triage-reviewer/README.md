# 🔍 Security Detection Second Triage Reviewer

*A cabinet in the [sec-arcade](../../) — insert coin when you paste a Semgrep/Snyk/Trivy/etc. finding, a CVE/CWE, or ask "is this actually exploitable?"*

A Claude Code skill that independently investigates security scanner findings — SAST, SCA, Secrets, IaC, and DAST — to determine whether they're true or false positives. It treats every scanner verdict as a claim to test, not a fact to relay, using actual repo access to trace reachability, sanitization, and exploitability instead of trusting the tool's severity rating.

## Overview

Security scanners generate a lot of noise. A SAST tool flags a sink without checking if input is sanitized upstream. An SCA tool flags a vulnerable package without checking if the vulnerable function is ever called. The severity rating on the finding is a generic CVSS score, not an assessment of what it actually means in your codebase.

This skill does what a senior AppSec engineer does when a finding lands on their desk: goes and checks. It reads the actual code, traces the call graph, checks the lockfile, checks git history, and comes back with a verdict you can act on, written in plain language, with every claim backed by a file and line number you can go verify yourself.

Paste a finding, get back:

- A clear verdict: true positive, false positive, or needs more context
- A confidence level (five-tier scale, not just high/medium/low)
- The specific evidence that led to that verdict, cited by file and line
- Severity correction when the tool's rating doesn't match reality
- Package health flags for SCA findings (staleness, deprecated, abandoned)
- A copy-paste suppression justification if it's a false positive

## How it flows

```
                     ┌──────────────────────────┐
                     │  Paste a scanner finding  │
                     │  (SAST/SCA/Secrets/       │
                     │  IaC/DAST)                │
                     └────────────┬──────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │  1. Parse the input        │
                     │  tool, rule, CWE/CVE,       │
                     │  file:line or package,      │
                     │  severity                   │
                     └────────────┬──────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │  2. One finding, or many?  │
                     └──────┬────────────┬────────┘
                same root cause│         │unrelated
                               ▼         ▼ (cap 3-4/run)
                     ┌──────────────┐ ┌──────────────┐
                     │ investigate  │ │ investigate  │
                     │ the pattern  │ │ each finding  │
                     │ once, list   │ │ separately,   │
                     │ every        │ │ capped to     │
                     │ instance     │ │ avoid         │
                     │              │ │ cross-talk    │
                     └──────┬───────┘ └──────┬───────┘
                            │                │
                            └───────┬────────┘
                                    ▼
                     ┌──────────────────────────┐
                     │  3. Investigate by type    │
                     │  SAST    → trace input,     │
                     │            check sanitizer  │
                     │  SCA     → trace call graph,│
                     │            check lockfile   │
                     │  Secrets → live vs fixture, │
                     │            check history    │
                     │  IaC     → applied config,  │
                     │            blast radius     │
                     │  DAST    → endpoint→handler │
                     │                              │
                     │  Goal: find a reason it's   │
                     │  WRONG before accepting     │
                     │  it's right                 │
                     └────────────┬──────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │  4. Confidence              │
                     │  Very High ──▶ Very Low     │
                     └────────────┬──────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │  5. Verdict block           │
                     │  ✅ TRUE POSITIVE           │
                     │  ❌ FALSE POSITIVE          │
                     │  🟡 NEEDS MORE CONTEXT      │
                     │  + evidence, severity,      │
                     │    action                   │
                     └──────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Run from inside the repository the finding belongs to. This skill needs real file access: it reads source, greps for call sites, and checks lockfiles and manifests. It does not work as a standalone chat skill with no codebase attached.
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
cp -r /tmp/sec-arcade/skills/security-detection-second-triage-reviewer ~/.claude/skills/

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/security-detection-second-triage-reviewer .claude/skills/
```

Claude Code picks up skills from either location automatically, no restart or manual registration required.

## Usage

Open Claude Code inside the repo the finding came from, then paste the finding as you received it from your scanner. No specific format required.

```
SAST - Semgrep
Rule: javascript.express.security.audit.express-check-csurf-middleware-usage
Severity: HIGH
File: src/routes/payment.js:42
```

Or trigger it explicitly:

```
Triage this finding: [paste]
```

```
Is this a real vulnerability or a false positive: [paste]
```

The skill works silently, no narration of intermediate steps, and returns a single structured verdict block.

### Example output

```
❌ FALSE POSITIVE | Confidence: High

What the tool found: Missing CSRF middleware on the payment POST route.

What I checked: src/routes/payment.js:42 sits behind requireApiAuth
middleware (src/middleware/auth.js:18), which validates a signed
bearer token on every request. This route has no session or cookie
based auth, so CSRF doesn't apply, there's no ambient credential
for a forged request to ride on.

Why: CSRF is a session-riding attack. This endpoint only accepts
a bearer token the browser doesn't attach automatically, so the
attack class doesn't apply here regardless of missing middleware.

Suppression Justification: This route uses bearer token
authentication, not cookies or sessions, so CSRF protection doesn't
apply. The token must be explicitly attached by the client and
isn't sent automatically by the browser like a session cookie
would be. Confirmed in src/middleware/auth.js:18. Suppressing as
not applicable to this endpoint's auth model.

Action: Suppress with the justification above. No code change needed.
```

## Supported finding types

| Type | What it checks |
|---|---|
| SAST | Input source, sanitization, reachability, compensating controls |
| SCA | Lockfile resolution, call graph reachability, direct vs transitive, package staleness and maintenance status |
| Secrets | Live vs placeholder, git history exposure, rotation status, credential scope |
| IaC | Applied config vs template, overrides, blast radius |
| DAST | Endpoint-to-handler tracing, reduced confidence ceiling due to no runtime visibility |

## Multiple findings

Findings sharing one root cause (same CWE, rule, or package across several locations) are investigated once and reported as a single verdict with every instance listed. Unrelated findings are capped at 3-4 per run to avoid cross-contaminating evidence between separate investigations in the same context window. Larger batches get flagged so you can split them up.

## Limitations

- Requires repo access. It won't produce a meaningful verdict from a finding alone with no codebase to check it against.
- DAST findings carry a lower confidence ceiling by design. There's no live traffic or runtime behavior to inspect, only the handler code the endpoint maps to.
- Best-guess verdicts are given even at Low or Very Low confidence rather than withheld. Always check the confidence level before treating a verdict as final.
- Not a replacement for judgment on genuinely ambiguous findings. It's meant to remove the obvious noise and hand you a well-reasoned starting point, not a rubber stamp in either direction.

## See also

[`security-detection-false-positive-governor`](../security-detection-false-positive-governor) is the inverse of this skill: once a finding here comes back False Positive, that skill independently re-audits the verdict before it gets trusted.

## License

[CC BY-SA 4.0](../../LICENSE), same as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
