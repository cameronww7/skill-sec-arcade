```
  ____ _     ___  _   _ ____    ____  _        _ __   _______ ____  
 / ___| |   / _ \| | | |  _ \  |  _ \| |      / \\ \ / / ____|  _ \ 
| |   | |  | | | | | | | | | | | |_) | |     / _ \\ V /|  _| | |_) |
| |___| |__| |_| | |_| | |_| | |  __/| |___ / ___ \| | | |___|  _ < 
 \____|_____\___/ \___/|____/  |_|   |_____/_/   \_\_| |_____|_| \_\

 ____  _____ ____  __  __      _   _   _ ____ ___ _____ 
|  _ \| ____|  _ \|  \/  |    / \ | | | |  _ \_ _|_   _|
| |_) |  _| | |_) | |\/| |   / _ \| | | | | | | |  | |  
|  __/| |___|  _ <| |  | |  / ___ \ |_| | |_| | |  | |  
|_|   |_____|_| \_\_|  |_| /_/   \_\___/|____/___| |_|
```

*Accent: Keycard Amber. The color of a badge that opens more doors than its holder actually walks through.*

# 🔑 Cloud Player Perm Audit

**Operational Title: IAM Overprovisioning Reviewer**
Reviews an AWS account's IAM roles for granted-but-unused permissions using free, local, read-only data, then explains and ranks the excess in plain language.

*A cabinet in the [sec-arcade](../../): insert token when you want to know how much blast radius a stolen role's credentials would actually have.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Scope](https://img.shields.io/badge/scope-single_account-brightgreen)
![Focus](https://img.shields.io/badge/focus-least_privilege-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that computes GRANTED minus USED for every scoped IAM role in one AWS account, using IAM last-accessed reports and CloudTrail Event history (both free, both read-only), then runs cloudsplaining (required) and optionally parliament/pmapper against the result, and explains the excess for someone who isn't an IAM expert. Built for the role that got `s3:*` three years ago for one bucket read and never got revisited.

## Overview

An IAM role's policy says what it's *allowed* to do. What it actually calls is usually a much smaller list. The gap does nothing for the app that owns the role, it's pure, unreviewed attack surface sitting there for whoever steals that role's credentials.

This skill measures that gap per role: which services were never touched at all in the observation window, which specific actions were never used (where the data supports that level of detail), and which permissions simply can't be verified either way from free data sources, and says so honestly rather than guessing. It cross-references the excess against cloudsplaining's risk categories (privilege escalation, data exfiltration, credentials exposure, resource exposure, service wildcards) so a reader can tell "unused but harmless" apart from "unused and dangerous."

Run it, get back:

- Every scoped role, grouped by risk tier (Critical first), including the clean ones
- For each role: which services/actions are excess, which are unverifiable (and why), and which cloudsplaining risk categories land specifically on that role's excess
- A plain-language reason and recommended action per role, never a drafted policy
- The observation window and every known limitation stated up front, before any role-level finding

This is a **review-only** skill. It never generates a replacement policy, never calls Policy Sentry, and never writes or changes anything in AWS.

## How it flows

```
    ┌──────────────────────────────────────────┐
    │ "Review our IAM roles for overprovisioning" │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 0. Preflight                              │
    │ config valid? credentials work? right     │
    │ profile? tools installed? stop if not.    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 1. Collect (read-only AWS calls)          │
    │ IAM export, last-accessed, CloudTrail,    │
    │ role metadata -> raw files, small manifest│
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 2. Analyze (local tools, no AWS calls)    │
    │ cloudsplaining (required), parliament +   │
    │ pmapper (optional)                        │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 3. Normalize (pure python, no AWS calls)  │
    │ GRANTED - USED = EXCESS, per role         │
    │ redaction applied if model_location=hosted│
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 4. Interpret (AI)                         │
    │ risk tier + plain-language reason +       │
    │ recommended action per role               │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 5. Offer to save                          │
    └──────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured.
- Python 3.10-3.12 on `$PATH` (`cloud_perm_audit.py` is stdlib-only, no `pip install` needed for the script itself).
- **AWS CLI v2**, configured with a profile for a designated **read-only** IAM role. This skill shells out to `aws`, it never uses boto3. The profile needs these read-only permissions: `iam:GetAccountAuthorizationDetails`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`, `iam:ListRoleTags`, `iam:GetRole`, `cloudtrail:LookupEvents`, `sts:GetCallerIdentity`. The AWS-managed `SecurityAudit` policy covers all of these.
- **Cloudsplaining**, pip-installed at a pinned version (`pip install cloudsplaining==0.9.1` or whatever version your config pins). Required, this skill cannot run without it.
- **Parliament and/or PMapper**, only if you set `enable_parliament`/`enable_pmapper` to `true` in config. Both optional. PMapper's PyPI package is `principalmapper` (the CLI binary is `pmapper`); its last release was January 2022, see Limitations below.
- A config file (JSON, not YAML, see Usage below) in the directory you run this from.
- **A hosted-model warning, not a requirement to change anything**: "free and local" describes the scanning tools and data sources, not necessarily the AI step that reads and explains `findings.json`. If Claude Code is running on a hosted model, that file leaves your machine; this skill forces redaction on by default (`model_location` defaults to `"hosted"` unless explicitly set to `"local"`) so account IDs and ARNs never leave in the clear. To keep everything on the machine end to end, you need a local model.

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
cp -r /tmp/sec-arcade/skills/cloud-player-perm-audit ~/.claude/skills/
mkdir -p ~/.claude/sec-arcade-standalone
cp /tmp/sec-arcade/scripts/cloud_perm_audit.py ~/.claude/sec-arcade-standalone/
export CLAUDE_PLUGIN_ROOT=~/.claude/sec-arcade-standalone
```

`SKILL.md` references the script via `${CLAUDE_PLUGIN_ROOT}/scripts/...`, an environment variable Claude Code only sets automatically for a full plugin install. Installing the whole arcade (Option 1) handles this for you.

## Usage

Create a config file, e.g. `cloud-player-perm-audit.config.json`, in the directory you'll run Claude Code from:

```json
{
  "aws_profile": "readonly-iam-auditor",
  "scope": {"type": "role_prefix", "role_prefix": "payments-"},
  "observation_window_days": 90,
  "model_location": "hosted",
  "profile_arn_allowlist": ["arn:aws:sts::*:assumed-role/readonly-iam-auditor/*"],
  "pinned_tool_versions": {"cloudsplaining": "0.9.1"},
  "enable_parliament": false,
  "enable_pmapper": false
}
```

Then ask directly:

```
Review our payments-team IAM roles for overprovisioning
```

```
Is this role safe? What could an attacker do with it if its credentials leaked?
```

```
Audit our IAM roles, what's unused and what's actually risky about it?
```

If no config file exists yet, the skill will offer to walk you through creating one.

### Example run (excerpt)

```
## Critical

### payments-ci-deployer
- Excess includes iam:CreatePolicyVersion and iam:PassRole (excess_services
  includes iam), a known privilege-escalation combination (risk_flags
  includes PrivilegeEscalation).
- Trust policy allows assumption from another AWS account
  (trust_policy_summary.assumable_by_other_account is true).
- Recommended action: remove access to the iam service entirely, it was
  never used in this run's 90-day observation window. Separately, review
  whether cross-account assumption from ACCOUNT_EXTERNAL_1 is still needed.
```

## Limitations

- **Observation window vs. last-accessed lookback.** CloudTrail Event history (free) covers 90 days by default, configurable via `observation_window_days`. IAM last-accessed data itself can look back up to 400 days regardless. These are two different numbers, both are stated in every report.
- **Data-plane blind spot.** S3 object reads, DynamoDB item operations, and Lambda invocations aren't visible in free CloudTrail management-event history. This skill quarantines those specific actions into `unknown_usage` and never recommends removing them based on usage data alone.
- **Action-level detail only exists for some services.** Others (most of them) only get a service-level "was this touched at all" verdict; their individual actions are reported as unknown, not excess, when the whole service was actually used.
- **Identity policies only.** Service Control Policies and permission boundaries aren't evaluated. Real effective access may be lower than what's reported as granted.
- **Allow statements only.** Explicit Deny statements and `NotAction` clauses aren't evaluated; computed "granted" permissions may be broader than what a role can actually do.
- **Single account per run.** Cross-account trust relationships are visible in the output, but the other account isn't scanned.
- **Review-only.** This skill never drafts a replacement policy and never applies anything to AWS. Every recommendation is advisory text a human reviews and acts on through their own normal change process.
- **PMapper is stale** (last release January 2022) and may miss newer AWS services or escalation techniques; it's optional for this reason. Its query output is plain text, included verbatim in the report, not parsed into structured findings.

## Next cabinet

None yet, this is this skill's first version. A natural follow-up would be a remediation skill that takes this report's excess findings and proposes (never applies) a tightened policy, e.g. via Policy Sentry, but that's explicitly out of scope for this skill by design: it reviews and reports, it doesn't write policy.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
