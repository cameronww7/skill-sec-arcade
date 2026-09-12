```
 ██████╗ █████╗ ██████╗  ██████╗  ██████╗
██╔════╝██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗
██║     ███████║██████╔╝██║  ███╗██║   ██║
██║     ██╔══██║██╔══██╗██║   ██║██║   ██║
╚██████╗██║  ██║██║  ██║╚██████╔╝╚██████╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝
```

*Accent: Cargo Hold Teal. The color of a shipping manifest, checked before anything leaves port.*

# 📦 Cargo Hold Cleanup

*A cabinet in the [sec-arcade](../../): insert token when a container image finding needs fixing, base image, build-installed binary, or config, not a dependency manifest.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Workflow](https://img.shields.io/badge/workflow-resolve_%E2%86%92_triage_%E2%86%92_fix_%E2%86%92_rescan-brightgreen)
![Focus](https://img.shields.io/badge/focus-container_remediation-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that fixes container image findings, base image OS package CVEs, build-installed binary CVEs, buildpack/Jib/ko builder findings, vendor image issues, injected sidecar findings, and image config problems like running as root. It does not fix application dependency findings, those get handed off to [`patch-for-the-high-score`](../patch-for-the-high-score) or [`patch-boss-rush`](../patch-boss-rush), because a container scan and an SCA scan can flag the same CVE for entirely different reasons and need entirely different fixes.

## Overview

A container finding is not a dependency finding wearing a different hat. There's no manifest or lockfile to bump when the CVE lives in the base image, the fix target is a `FROM` line or a `RUN` step. A finding with no fix available has its own decision tree: remove the package if it's not needed, swap the base image, assess reachability, apply a compensating control, or draft a time-boxed exception, in that order, not a shrug. A "running as root" finding isn't a CVE at all.

This skill runs ownership resolution first: every finding lands in exactly one layer (base image OS package, app dependency, build-installed binary, buildpack/builder, vendor image, injected sidecar, or image config), and that layer decides everything downstream. Before proposing any fix, it checks whether the image is even current (a rebuild-and-rescan often clears a finding with zero code change) and whether the vulnerable package is actually needed in the shipped image at all. Then it produces the fix, gates on complexity the same way the other remediation skills do, and treats a base image bump's regression check as a hard requirement, not a suggestion, because bumping a base image routinely trades one CVE for several new ones.

Run it, get back:

- A resolved layer (base image / app dependency / build-installed binary / buildpack / vendor / sidecar / config), stated up front so the routing is verifiable
- An immediate handoff to `patch-for-the-high-score`/`patch-boss-rush` if the finding actually resolves to an application dependency instead of the image
- A rebuild-and-rescan-first call when the image under test is stale, before any edit is proposed
- A pinned, digest-referenced base image bump, or an inline pinned upgrade when no patched tag exists yet, never an unpinned `apt-get upgrade`
- A build-installed binary fix that bumps the checksum along with the version, not one without the other
- For no-fix-available findings, the full decision order: remove, swap base, assess reachability, compensating control, time-boxed exception with every required field populated
- Proactive breakage warnings before a distro switch, not after you've already rebuilt and broken the entrypoint
- An applied fix, a full diff, a required full-result-set regression check, and an offer to open a PR

## How it flows

```
    ┌───────────────────────────────────────────┐
    │ Paste a finding: a Trivy/Grype/Snyk       │
    │ Container/Docker Scout result             │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 1. Parse the input                        │
    │ scanner/CVE/package/fixedIn/introduced-   │
    │ Through, from JSON, SARIF, or console text│
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 2. Ownership resolution                   │
    │ classify against the playbook's layer     │
    │ table -> app dependency? hand off & stop  │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 3. Pre-triage checks                      │
    │ rebuild cadence -> stale? stop here.      │
    │ presence & necessity -> can it be removed?│
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 4. Remediation or no-fix path             │
    │ fix available -> template by layer        │
    │ no fix -> remove/swap/reachability/       │
    │ compensating control/time-boxed exception │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 5. Plan & complexity gate                 │
    │ trivial -> quick plan, distro switch or   │
    │ breakage-class change -> EnterPlanMode    │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 6-7. Apply, diff, required regression     │
    │ check (full result set, not just the      │
    │ target CVE)                               │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 8. Offer a PR                             │
    │ only on explicit yes                      │
    └───────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Run from inside the repository being fixed, or with vendor/registry context supplied if there's no local Dockerfile at all
- `gh` CLI installed and authenticated if you want the PR step to actually run

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
cp -r /tmp/sec-arcade/skills/cargo-hold-cleanup ~/.claude/skills/
```

Note: standalone installs also need `references/container-remediation-playbook.md` and `references/owasp-cheat-sheet-series.md`, and, if the app-dependency handoff path is expected to work, `patch-for-the-high-score` and/or `patch-boss-rush` alongside it. Installing the whole arcade (Option 1) avoids assembling that list by hand.

## Usage

Open Claude Code inside the repo with the finding, then paste it directly:

```
Fix this container finding: [paste Trivy/Grype/Snyk Container/Docker Scout output]
```

```
Why is this Dockerfile flagged for running as root, and can you fix it?
```

### Example run (excerpt)

```
📦 BASE IMAGE OS PACKAGE - FIX NOW

Resolved layer: introducedThrough bottoms out at debian:12, no manifest
in the path, package manager is apt.

Summary: The base image ships an OpenSSL build with a known
out-of-bounds write. Debian has already published a patched package
version.

Evidence:
- Snyk finding SNYK-DEBIAN12-OPENSSL3-1234567, openssl 3.0.11-1~deb12u1,
  fixed in 3.0.11-1~deb12u2
- Dockerfile:1, FROM debian:12-slim, no digest pin

Fix target: FROM line, Dockerfile:1

Proposed change:
- FROM debian:12-slim
+ FROM debian:12-slim@sha256:<new-digest>

Breakage risks: none expected, patch-level base image update only.

Fix Plan (max 6 sentences, junior-engineer clear):
1. Pin the base image to the digest that includes the patched openssl
   package.
2. No other Dockerfile changes needed, this is a base image refresh,
   not a distro switch.

Action: apply the digest pin, then rebuild and rescan the full image.
```

## Limitations

- Handles one container finding per run, same reasoning as the other remediation skills, batching would stack approvals and diffs in a way that's hard to review carefully.
- Does not fix application dependency findings that happen to surface from a container scan, those hand off to `patch-for-the-high-score`/`patch-boss-rush` by design.
- Does not touch Kubernetes manifest security policy beyond recommending the admission-policy equivalent of a Dockerfile config fix, and does not touch registry configuration at all.
- The rebuild-cadence and presence/necessity checks depend on registry metadata being reachable. Without it, state that plainly rather than guessing at a build date.
- Never commits or pushes without an explicit "yes, open a PR." A "no" leaves the fix sitting uncommitted in your working tree.

## Next cabinet

For an application dependency finding, or a finding that isn't container-specific at all, see [`patch-for-the-high-score`](../patch-for-the-high-score) (deliberate, context-loaded) or [`patch-boss-rush`](../patch-boss-rush) (fast, standalone).

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
