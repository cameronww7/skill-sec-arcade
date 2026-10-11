# IAM Excess Risk Tiers

The risk rubric `cloud-player-perm-audit`'s Step 4 uses to turn one role's `findings.json` record into a tier, a plain-language reason, and a recommended action. The scripts already computed GRANTED, USED, EXCESS, and UNKNOWN; this file is what the AI interpretation step reasons over to rank and explain that excess, it does not recompute any of it.

## Hard rules

These apply to every sentence written about every role, no exceptions:

- **Cite a field.** Every claim must name the specific `findings.json` field or role it's based on (e.g. "`excess_services` includes `kms`", "`trust_policy_summary.assumable_by_wildcard_principal` is `true`"), not a vague impression.
- **`null` means unknown, not clean.** A `null`/missing value is reported as unknown. It is never treated as evidence of safety, and never silently omitted either, say it's unknown.
- **This skill never calls AWS.** Nothing past Step 3 touches AWS in any way. Every judgment here is reasoning over already-collected, already-computed data.
- **Advisory text only.** The output is a tier, a reason, and a recommended action in plain language. This skill never drafts a replacement policy and never applies anything.
- **Unknown usage is never a removal basis.** A permission in `unknown_usage` is, by definition, one this skill could not verify as used or unused. It is never the sole basis for a "remove this" recommendation; at most it's worth naming as "unverifiable, needs a human check," distinct from a confirmed `excess_actions`/`excess_services` entry.

## Risk-raising factors

| Factor | `findings.json` field |
|---|---|
| Excess includes an escalation or exfiltration pattern | `risk_flags` contains `PrivilegeEscalation`, `DataExfiltration`, or `CredentialsExposure` |
| Role is assumable from outside this account | `trust_policy_summary.assumable_by_other_account` is `true` |
| Role is assumable by any principal (unscoped) | `trust_policy_summary.assumable_by_wildcard_principal` is `true` |
| Role federates via OIDC without a repo-scoped condition | `trust_policy_summary.oidc_missing_repo_condition` is `true` |
| Role is attached to internet-facing or CI compute | `compute_attachment` includes a service principal like `ec2.amazonaws.com`, `ecs-tasks.amazonaws.com`, `eks.amazonaws.com`, or `lambda.amazonaws.com`, combined with other risk-raising factors; compute attachment alone is not a risk-raising signal, workload exposure context (not available in `findings.json`) is what actually determines whether this matters |
| Environment is production | `tags.env` is `prod` (or an equivalent production-sounding value; tag keys/values are freeform, read what's actually there) |
| Large excess on an actively-used role | Non-trivial `excess_services`/`excess_actions` AND a recent `last_used_date`, an easy, low-risk win to tighten |
| Role hasn't been used at all | `last_used_date` is null or older than the observation window, a delete candidate worth flagging distinctly from a tightening candidate |

## Risk-lowering factors

| Factor | `findings.json` field |
|---|---|
| Excess is read/list-only on a low-value service | `excess_actions`/`excess_services` entries are read-pattern actions (`Get*`, `List*`, `Describe*`) with no corresponding `risk_flags` entry |
| Role is assumable only by one scoped service principal | `trust_policy_summary.assumable_service_principals` has exactly one entry, and every other `assumable_by_*` flag is `false` |
| Environment is non-production | `tags.env` is `sandbox`, `dev`, `test`, or similar |
| No internet-facing or CI compute attachment | `compute_attachment` is empty, or limited to an internal batch-job-style service principal |

## Tiers

Apply top to bottom, first match wins, same convention as `dead-weight-detector`'s decision list:

1. **Critical** — `risk_flags` contains `PrivilegeEscalation`, `DataExfiltration`, or `CredentialsExposure`, AND at least one risk-raising trust/exposure factor is also true (cross-account, wildcard, unscoped OIDC).
2. **High** — `risk_flags` contains `PrivilegeEscalation`, `DataExfiltration`, or `CredentialsExposure`, with no additional risk-raising trust factor, OR a risk-raising trust factor is true on its own with a non-trivial `excess_services`/`excess_actions` set (even without a cloudsplaining flag).
3. **Medium** — Non-trivial excess exists, `risk_flags` is empty or contains only `InfrastructureModification`/`ServiceWildcard`, and no risk-raising trust factor applies.
4. **Low** — Excess exists but is entirely read/list-pattern actions on a low-value service with no risk-raising trust factor and no `risk_flags`.
5. **Watch (unused role)** — `last_used_date` is null or outside the observation window. Report this distinctly from a tier based on excess size; the recommended action is "confirm this role is still needed, consider deleting" rather than "tighten its permissions."
6. **Clean** — `excess_services` and `excess_actions` are both empty, and `risk_flags` is empty or `null`. Still name the role in the report (so an all-clean account is visibly reviewed, not silently skipped), but it does not need a deep-dive writeup.

A role can reasonably sit in more than one narrative bucket (e.g. unused AND would be Critical if it were active); state both facts rather than forcing a single label when they both matter.

## Writing the reason and recommended action

- **Reason**: one or two plain-language sentences, each citing a specific field. Example: "This role's excess includes `iam:CreatePolicyVersion` and `iam:PassRole` (`excess_services` includes `iam`), a known privilege-escalation combination (`risk_flags` includes `PrivilegeEscalation`), and the role can be assumed from another AWS account (`trust_policy_summary.assumable_by_other_account` is `true`, account `ACCOUNT_EXTERNAL_1`)."
- **Recommended action**: plain language, never a drafted policy. Examples: "Remove access to the `iam` service entirely, it's granted but was never used in this run's observation window." / "This role hasn't been used in over 90 days; confirm with its owner (`tags.owner`) whether it's still needed before deleting it." / "The trust policy's GitHub OIDC federation has no repository condition; scope it to the specific repo(s) that should be allowed to assume this role."
- When a permission sits in `unknown_usage` rather than `excess_actions`/`excess_services`, say so explicitly rather than folding it into a removal recommendation: "This role's `s3:GetObject`/`s3:PutObject` usage could not be verified either way (data-plane calls aren't visible in this skill's free data sources); don't remove these based on this report alone."

## Report structure

Group the report by tier (Critical first), not as a flat per-role list. State the observation window and the full `limitations` list from `findings.json` **before any role-level findings**, this is the single most important trust-preserving element in the whole report: a reader who skips the limitations and acts on a recommendation without understanding the observation window or the data-plane blind spot is the main way this skill could cause real harm (removing something that turns out to be needed).
