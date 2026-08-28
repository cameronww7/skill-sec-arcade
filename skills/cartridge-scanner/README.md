# 🕹️ Cartridge Scanner

*A cabinet in the [sec-arcade](../../): insert coin when you want a language/dependency/IaC/container inventory of a repo, before any deep scanning starts.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Data Points](https://img.shields.io/badge/data_points-language_%7C_deps_%7C_iac_%7C_containers-brightgreen)
![Focus](https://img.shields.io/badge/focus-appsec_recon-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that inventories a repo the way an AppSec engineer would on day one: what languages and how much code (via [`scc`](https://github.com/boyter/scc)), what package managers and roughly how many dependencies, whether any of those dependencies come from a private/internal registry, what Infrastructure-as-Code is in play, and what's containerized. It ends with a tailored rundown of what scanning *capability* the repo needs, no tool or vendor names, just gaps and what kind of tool fills them.

## Overview

You can't point a security tool at a codebase you haven't characterized. A Java SAST ruleset does nothing for a repo that's mostly Python. An SCA scan that can't reach an internal package registry will often fail silently, skip the unresolvable dependency, no error, and hand back a clean-looking result that isn't actually clean. This skill exists to catch both problems before they happen, by reading the repo first.

Run it, get back:

- A language and lines-of-code breakdown, dominant language(s) and polyglot risk called out
- A package manager inventory across nine ecosystems (npm/yarn/pnpm, Python, Go, Java, Ruby, PHP, Rust, .NET, Dart), with approximate declared and resolved dependency counts
- Explicit detection of private/internal package registries per ecosystem, and why that matters for SCA coverage
- An Infrastructure-as-Code inventory (Terraform, CloudFormation, Kubernetes/Helm, Ansible, Pulumi, Serverless, CDK)
- A container inventory (Dockerfiles with base images, compose files)
- Notable signals: missing lockfiles, duplicate package managers, committed vendor directories
- A scanning coverage recommendation section, framed as capability gaps, not a shopping list

## How it flows

```
    ┌───────────────────────────────────────────┐
    │ "Scan this repo" / "what tools do I need" │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 1. Run cartridge_scan.py                  │
    │ scc (or fallback) + manifest/lockfile     │
    │ parsing + registry/container/IaC scan     │
    │ -> one JSON blob                          │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 2-3. Language/size breakdown              │
    │ + first-party vs. third-party framing     │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 4-5. Package manager inventory            │
    │ declared/resolved deps (approx)           │
    │ + private registry callout                │
    │   (SCA tools often fail silently here)    │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 6-7. IaC inventory + container inventory  │
    │ only sections that actually have hits     │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 8. Notable signals                        │
    │ missing lockfiles, duplicate package      │
    │ managers, committed vendor dirs           │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 9. Scanning coverage recommendations      │
    │ capability gaps from security-scan-       │
    │ capability-map.md, no tool/vendor names   │
    └───────────────────────────────────────────┘
                          │
                          ▼
    ┌───────────────────────────────────────────┐
    │ 10-11. Write the report, offer to save    │
    └───────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Python 3 on `$PATH` (the helper script is stdlib-only, no extra packages)
- [`scc`](https://github.com/boyter/scc) on `$PATH` for full language/LOC data (comment/blank/complexity breakdown). Not required, the script falls back to a rough file/line count if `scc` is missing, but the report will say so and recommend installing it.
- Run from inside the repository being scanned. This skill needs real file access.

## Installation

This skill ships as part of the [`sec-arcade`](https://github.com/cameronww7/skill-sec-arcade) Claude Code plugin.

### Option 1: Install the whole arcade (recommended)

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

You get this skill plus every other skill added to the arcade over time.

### Option 2: Just this skill

```bash
# personal, applies in every project
git clone --depth 1 https://github.com/cameronww7/skill-sec-arcade.git /tmp/sec-arcade
cp -r /tmp/sec-arcade/skills/cartridge-scanner ~/.claude/skills/
cp -r /tmp/sec-arcade/scripts ~/.claude/skills/cartridge-scanner-scripts   # or adjust ${CLAUDE_PLUGIN_ROOT} paths in SKILL.md

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/cartridge-scanner .claude/skills/
```

Installing the whole arcade (Option 1) is simpler, `${CLAUDE_PLUGIN_ROOT}` resolves correctly without any path adjustment.

## Usage

Open Claude Code inside the repo you want inventoried, then ask directly:

```
Scan this repo and tell me what security tooling I need
```

```
Give me a language and dependency inventory of this codebase
```

```
What package managers does this repo use, and are any of them pointed at a private registry?
```

The skill runs `scripts/cartridge_scan.py`, reads the resulting JSON, and writes a structured markdown report.

### Example run (excerpt)

```
# Cartridge Scan: payments-service

## Summary

A polyglot repo, ~40k lines of first-party TypeScript backing an Express
API, with a smaller Python data pipeline. scc was available, so the
LOC figures below include comment/blank/complexity detail.

## Package Manager Inventory

| Ecosystem | Manifest | Lockfile | Declared Deps | Resolved Deps (approx) |
|---|---|---|---|---|
| npm | package.json | package-lock.json | 34 | 212 |
| python | requirements.txt | (none) | 9 | n/a |

## Private Registries

- **npm**: `artifactory.internal.example.com`, found in `package.json`
  (publishConfig.registry). SCA tools frequently can't resolve packages
  behind an internal registry and many fail silently rather than
  erroring, confirm your SCA tool has network access and auth to this
  host before trusting its npm results.

## Scanning Coverage Recommendations

**SCA**: No confirmed dependency-vulnerability coverage for the npm
tree (212 resolved packages) or the Python requirements (9 declared,
no lockfile so no resolved count). The npm recommendation only holds
if the tool can reach and authenticate to the internal Artifactory
host above.
```

## Limitations

- All dependency counts are static approximations from parsing manifests/lockfiles, not a real dependency resolution. Treat them as a lower bound; run an SBOM tool for ground truth.
- Private registry detection is host-based (anything not matching the ecosystem's known public default gets flagged), it can't identify which specific product (Artifactory, Nexus, GitHub Packages, etc.) is running there, only that something non-default is.
- Without `scc` installed, language stats are a rough file/line count only, no comment/blank/complexity breakdown, and a smaller set of recognized file extensions.
- This is an inventory and capability-gap report, not a vulnerability scan. It doesn't find CVEs, misconfigurations, or code-level bugs, it tells you what kind of tool would.

## Next cabinet

[`dungeon-crawl-threat-map`](../dungeon-crawl-threat-map) is the natural next step once you know what's in the repo: it builds the architecture-level threat model and STRIDE breakdown this skill's inventory feeds into.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
