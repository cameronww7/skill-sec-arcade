# IAM Data Coverage and Tools

Lookup for `cloud-player-perm-audit`'s data sources and the tools its `collect`/`analyze` script modes shell out to. The theme throughout: coverage here is genuinely uneven, some signals are precise, others only prove "this service was touched," and some permissions can't be verified as unused at all from free data sources. Report every gap honestly as `unknown`, never guess a verdict from a gap.

## Two different lookback windows, never conflate them

| Source | Free lookback | Notes |
|---|---|---|
| CloudTrail Event history (`lookup-events`) | 90 days of management events | No trail setup required, no cost. This is what `collect_cloudtrail_events()` queries, bounded by `observation_window_days` in config (default 90). |
| IAM last-accessed (`generate/get-service-last-accessed-details`) | Up to 400 days | A separate mechanism (IAM Access Advisor), not CloudTrail. Its own internal lookback is roughly 400 days regardless of what `observation_window_days` is set to. |

`findings.json`'s `observation_window_days` field states what this run's CloudTrail query actually covered. It does not change how far back last-accessed itself looks. State both facts in the report if a reader might assume they're the same number.

## Action-level vs. service-level last-accessed coverage

`generate-service-last-accessed-details --granularity ACTION_LEVEL` returns per-action tracking (`TrackedActionsLastAccessed`) only for a subset of AWS services. AWS expands this list over time; treat the list below as indicative, not exhaustive, and never assume a service not listed here lacks action-level tracking without checking the actual response.

Representative services with action-level tracking as of this writing: S3, IAM, KMS, RDS, EC2, ECS, EKS, Lambda, SSM, SQS, SNS, Secrets Manager.

For everything else, a service's last-accessed entry carries only `LastAuthenticated` (was this service touched at all, and when) with no `TrackedActionsLastAccessed` breakdown. `compute_used_services_and_actions()` in `cloud_perm_audit.py` detects this directly from the response shape (an empty or absent `TrackedActionsLastAccessed` list) rather than consulting a static list, so this script's actual behavior always reflects what AWS returned that run, not a hardcoded assumption.

**CloudTrail fills part of the gap.** For a service with service-level-only last-accessed data, CloudTrail's own event history can still supply specific action names (matched via each event's `EventSource`/`EventName`, see `match_cloudtrail_events_to_roles()`). This upgrades that service to effective action-level coverage for whichever specific actions CloudTrail actually observed, even though last-accessed alone couldn't provide that detail. A service CloudTrail never saw anything for keeps its service-level-only verdict.

## The data-plane blind spot

CloudTrail's free, no-trail Event history only covers **management events** (control-plane API calls: creating a bucket, changing a policy, starting an instance). **Data events** (the high-volume, by-the-record operations like S3 object reads/writes, DynamoDB item operations, and Lambda function invocations) require a paid CloudTrail data-event trail that this skill deliberately does not set up, per its "everything free" design.

`cloud_perm_audit.py`'s `DATA_PLANE_ACTIONS_BY_SERVICE` constant is a fixed quarantine list of specific actions this skill never counts as excess, regardless of what usage data suggests, because free data sources can't reliably prove them unused:

| Service | Quarantined actions |
|---|---|
| S3 | `GetObject`, `PutObject`, `DeleteObject`, `GetObjectVersion`, `HeadObject` |
| DynamoDB | `GetItem`, `PutItem`, `DeleteItem`, `Query`, `Scan`, `UpdateItem`, `BatchGetItem`, `BatchWriteItem` |
| Lambda | `InvokeFunction`, `InvokeAsync` |

These actions always land in `unknown_usage`, never in `excess_actions`, even if IAM last-accessed's action-level tracking (which does cover S3 at the action level) suggests they were never used. This is a deliberately conservative choice: a false "unused, remove it" verdict on a data-plane action that's actually load-bearing is a worse failure mode than an overly cautious `unknown`.

## Identity policies only, no SCPs or permission boundaries

`get-account-authorization-details` returns each role's own inline and attached managed policies. It says nothing about Service Control Policies (SCPs) at the AWS Organizations level, or permission boundaries attached to the role. Both can further restrict what a role can actually do beyond what its own identity policies grant.

Everything this skill reports as "granted" reflects identity policies only. A role's real effective access, after SCPs and permission boundaries are applied, may be narrower than what `findings.json` shows. This skill does not call `organizations:DescribePolicy` or evaluate permission boundaries; that's out of scope for this version.

## Allow statements only

This skill's granted-permission computation (`merge_policy_document_into_granted()`) only evaluates `"Effect": "Allow"` statements. Explicit `"Effect": "Deny"` statements and `NotAction` clauses are never evaluated. A role's computed "granted" set may therefore be broader than what the role can actually do once an explicit Deny is applied elsewhere in the same or another attached policy.

## Tool landscape

| Tool | Role in this skill | Required? | License | Last checked | Notes |
|---|---|---|---|---|---|
| AWS CLI v2 | All data collection (`collect` mode) | Yes | Apache 2.0 | Current | AWS-maintained. This skill shells out to it via `subprocess`, never via boto3. |
| Cloudsplaining | Risk pattern detection: data exfiltration, infrastructure modification, resource exposure, privilege escalation, credentials exposure, service wildcards (`analyze` mode) | Yes | MIT | 0.9.1 | Actively maintained (Salesforce). Its `scan` command requires its `--output` directory to already exist, and needs an authorization-details file with every field real `get-account-authorization-details` output carries (including each managed policy's `PolicyId`), confirmed directly against a real install while building this skill. |
| Parliament | Policy linting: malformed actions, resource/action mismatches | Optional (`enable_parliament` in config) | BSD-3 | 1.6.4 | Low-cadence but maintained. Its `--json` output is account-wide; this skill reports a total finding count (`parliament_findings_total` in `findings.json`), not a per-role attribution, since its JSON output doesn't reliably carry a per-role ARN field. |
| PMapper (`principalmapper` on PyPI, `pmapper` CLI binary) | Multi-hop privilege escalation path detection: can this role become admin through other roles, not just its own policy | Optional (`enable_pmapper` in config) | AGPLv3 | 1.1.5 (Jan 2022) | Stale: no release since January 2022, may miss newer AWS services and escalation techniques. Its query output is plain text, not JSON; this skill stores it verbatim (`pmapper_escalation_paths_raw_text` in `findings.json`) rather than attempting to parse a structure out of it. AGPL licensing is not a redistribution concern here: this skill only shells out to a locally-installed `pmapper` binary, it never bundles or redistributes PMapper's own code. |

## Explicitly dropped, and why

- **IAM Access Analyzer unused access**: billed per role/user analyzed (roughly $0.20/role/month), and it runs as an AWS-side analysis rather than something that runs on the laptop. IAM last-accessed data plus CloudTrail Event history cover the same ground for free.
- **IAM Access Analyzer custom policy checks**: billed per API request. Not needed for this skill's review-only scope.
- **Policy Sentry**: generates replacement policies from an actions list. Out of scope for this skill, which reviews and reports, it never generates or proposes a replacement policy document.

## Cost

Every data source and tool this skill actually uses is free: IAM API calls carry no charge, CloudTrail Event history gives 90 days of free management events with no trail setup, and every tool listed above is open source and runs locally. The one real cost center is **token usage if the AI interpretation step (Step 4) runs on a hosted model**: `findings.json`'s size is proportional to the number of scoped roles, which is why scoping (config's `scope` field, applied before any expensive per-role call) and redaction (always forced on for a hosted model, see this skill's SKILL.md Step 3) both matter for keeping that bounded.
