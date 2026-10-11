---
name: cloud-player-perm-audit
description: Reviews one AWS account's IAM roles for overprovisioning (granted permissions that are never actually used) using free, local, read-only AWS data (IAM last-accessed reports, CloudTrail Event history, the account authorization export) plus cloudsplaining (required) and optionally parliament/pmapper, then explains and ranks the excess in plain language for someone who isn't an IAM expert. Trigger this for "IAM audit," "review our IAM roles," "overprovisioned role," "least privilege review," "blast radius," "unused IAM permissions," "which roles have more access than they use," or "is this role safe." This is a review-and-report skill only: it never drafts a replacement policy, never calls Policy Sentry, and never applies anything to AWS. For reviewing one pasted finding instead of a whole account, see `player-two-verdict` instead.
---

# Cloud Player Perm Audit

## Why this skill exists

An IAM role's policy is a list of everything it's *allowed* to do. What it actually *does* is usually a much smaller list. The gap between the two, granted minus used, is permission an attacker gets for free if that role's credentials are ever stolen, with no benefit to the app that owns it. That gap is this skill's whole subject.

The calculation itself (GRANTED minus USED equals EXCESS) is mechanical and belongs entirely to `${CLAUDE_PLUGIN_ROOT}/scripts/cloud_perm_audit.py`, never to this skill's own judgment. What's genuinely hard, and what this skill actually adds, is explaining that excess honestly to someone who isn't an IAM expert: which of it is dangerous, which of it is a safe cleanup, and which of it simply can't be verified from free data sources and must be said so plainly rather than guessed at.

## When to use this

- The user wants an IAM/permissions audit, an overprovisioning review, or a blast-radius assessment for a role or a team's roles.
- The user asks "is this role safe," "does this role have more access than it needs," or "what would happen if this role's credentials leaked."

This is **not** the right skill for:
- Writing or generating a replacement/least-privilege policy document. This skill reports findings; it never drafts or applies a policy.
- Reviewing a single already-pasted finding from another tool, use `player-two-verdict` for that instead.
- Scanning more than one AWS account in a single run. Run this once per account.

## Step 0: Prerequisite check

This skill needs a JSON config file, conventionally `cloud-player-perm-audit.config.json` in the directory the skill was invoked from. If it isn't there, show the user this shape and offer, via `AskUserQuestion`, to fill in `aws_profile`, `scope`, and `model_location` (ask these three specifically, they're the ones with no safe default) and write the file before continuing:

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

`scope` can instead be `{"type": "tag", "tag_key": "team", "tag_value": "payments"}`. `model_location` must be `"local"` or `"hosted"`; anything else, including leaving it out, is treated as `"hosted"` and forces redaction on, that's the safe default, never loosen it on the user's behalf.

Once a config file exists, run:

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/cloud_perm_audit.py preflight <config_path>
```

Read its full JSON output. If `"ok"` is `false`, **stop immediately** and tell the user plainly which check(s) in `"checks"` failed and why, quoting their `"detail"` fields. A partial scan that looks complete is worse than no scan; never continue past a failed preflight. A `"skipped"` status (for example, `parliament_installed` when `enable_parliament` is `false`) is not a failure and never blocks the run.

## Step 1: Collect

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/cloud_perm_audit.py collect <config_path>
```

Read the full manifest this prints. It does **not** contain the raw collected data, only a summary, the real IAM export, last-accessed reports, and CloudTrail events are written to the `"run_directory"` path this manifest names, for the next two steps to read. Tell the user the `"scoped_role_count"` and `"observation_window_days"` before continuing, and surface any `"collection_errors"` plainly rather than silently dropping them, a role whose last-accessed job timed out will show up as fully excess in Step 3, not as an error, so the user should know why upfront.

## Step 2: Analyze

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/cloud_perm_audit.py analyze <run_directory> <config_path>
```

Uses the `"run_directory"` from Step 1's manifest. Read the full output. State which tools actually ran: cloudsplaining always should (if `"tools_run"."cloudsplaining"."ran"` is `false`, say so and explain that every role's risk flags will come back unavailable, not clean, in Step 3). State plainly whether parliament/pmapper ran, were skipped because they're disabled in config, or were skipped because they're not installed, per `${CLAUDE_PLUGIN_ROOT}/references/iam-data-coverage-and-tools.md`'s tool table.

## Step 3: Normalize

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/cloud_perm_audit.py normalize <run_directory> <config_path>
```

**Read this entire JSON output. This is `findings.json`, and every claim made in Step 4 must cite a specific field from it.** Confirm `"redaction_applied"` matches what `"model_location"` implies (`true` whenever `"model_location"` is `"hosted"`, which is the default) before writing anything about this data. This is the only script output in this whole skill meant for you to read in full, every other step's output is a short manifest.

## Step 4: Interpret and write the report

Using `${CLAUDE_PLUGIN_ROOT}/references/iam-excess-risk-tiers.md`'s tiers, risk factors, and hard rules, assign each role in `findings.json["roles"]` a tier, write one or two plain-language reasons (each citing a specific field), and a plain-language recommended action, **never a drafted policy**. Group the report by tier, Critical first, not as a flat per-role list.

Put the observation window and the full `findings.json["limitations"]` list **first, before any role-level findings.** This is the single most important trust-preserving part of the whole report: a reader who skips this and acts on a recommendation without understanding the observation window and the data-plane blind spot is how this skill could cause real harm, by removing something that turns out to be load-bearing. Name every role, including ones with no excess (Clean tier), so an all-clean account is visibly reviewed rather than silently skipped.

This skill never calls AWS past Step 3, and never writes, proposes, or applies a policy anywhere. Say so plainly in the report's own text, not just in this instruction.

## Step 5: Offer to save

After the full report has been shown inline, follow the save prompt defined in `${CLAUDE_PLUGIN_ROOT}/references/save-states.md`. Canonical file: `.SEC-Arcade-save_states/CLOUD_PLAYER_PERM_AUDIT.md`. Frame the save as worth re-running periodically: a role's usage pattern drifts over time, and a clean verdict today doesn't mean clean in six months.

Do **not** run the config file itself through this save prompt, it's a setup-once file the user manages directly, not a report.

## Reference material

- `${CLAUDE_PLUGIN_ROOT}/scripts/cloud_perm_audit.py`: does every mechanical step (preflight, collect, analyze, normalize), used in Steps 0-3.
- `${CLAUDE_PLUGIN_ROOT}/references/iam-data-coverage-and-tools.md`: which data source covers what, the data-plane blind spot, the tool landscape and what was dropped, used in Steps 2 and 4.
- `${CLAUDE_PLUGIN_ROOT}/references/iam-excess-risk-tiers.md`: the risk tiers, risk factors, and hard rules Step 4's report is built from.
- `${CLAUDE_PLUGIN_ROOT}/references/save-states.md`: the shared save-to-file convention, used in Step 5.
