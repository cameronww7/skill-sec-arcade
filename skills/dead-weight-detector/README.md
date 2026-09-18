```
 _____  _______ _______ _____    ________ _______ _______ _______ _______ _______ 
|     \|    ___|   _   |     \  |  |  |  |    ___|_     _|     __|   |   |_     _|
|  --  |    ___|       |  --  | |  |  |  |    ___|_|   |_|    |  |       | |   |  
|_____/|_______|___|___|_____/  |________|_______|_______|_______|___|___| |___|  

 _____  _______ _______ _______ ______ _______ _______ ______ 
|     \|    ___|_     _|    ___|      |_     _|       |   __ \
|  --  |    ___| |   | |    ___|   ---| |   | |   -   |      <
|_____/|_______| |___| |_______|______| |___| |_______|___|__|
```

*Accent: Anchor Grey. The color of ballast you're not sure is still worth carrying.*

# 🏋️ Dead Weight Detector

*A cabinet in the [sec-arcade](../../): insert token when you want to know if a dependency is actually pulling its weight, or just dead weight in the pack.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Ecosystems](https://img.shields.io/badge/ecosystems-10-brightgreen)
![Focus](https://img.shields.io/badge/focus-dependency_hygiene-critical)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that measures how much each direct OSS dependency is actually used in first-party code, cross-references that against live maintenance-health signals from the package's own registry, and recommends keep, watch, or replace with first-party code. Built for the dependency that got added for one function call and never got a second thought since.

## Overview

A dependency is a permanent commitment: it has to be kept patched, it's a supply-chain trust surface, and if the upstream project goes quiet that risk just sits there. Most of the time nobody revisits that commitment after the initial one-line add. This skill does the revisiting.

It quantifies usage (files touched, call sites, distinct symbols referenced) for every direct dependency, then, for the ones that look thin, goes and checks whether the package itself is still healthy: when it last shipped, how many maintainers it has, how widely it's downloaded, and whether the version actually pinned has a known unpatched vulnerability. It combines that with a qualitative read on how hard the used surface would be to hand-roll, and lands on one of four verdicts.

Run it, get back:

- A full usage-tier table for every direct dependency across ten ecosystems (cheap, no network)
- A deep-dive workup for the low-usage candidates: real call sites, live registry health data, replacement-complexity judgment
- A **KEEP** / **CANDIDATE TO INLINE** / **KEEP BUT WATCH** / **NEEDS HUMAN JUDGMENT** verdict per deep-dived dependency
- Every health claim cited back to a named registry field, never a vague "looks unmaintained"

## Supported ecosystems

| Ecosystem | Manifest | Lock file |
|-----------|----------|-----------|
| JavaScript (npm/yarn/pnpm) | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python (PyPI) | `requirements.txt`, `pyproject.toml` (PEP 621 + Poetry), `Pipfile`, `setup.py`, `setup.cfg` | `poetry.lock`, `uv.lock`, `Pipfile.lock` (requirements.txt pins are read directly) |
| Go | `go.mod` | -- (version pinned directly in the manifest) |
| Java (Maven, Gradle, Ivy) | `pom.xml`, `build.gradle` / `build.gradle.kts`, `ivy.xml` | -- (version pinned directly in the manifest) |
| Ruby (RubyGems) | `Gemfile` | `Gemfile.lock` |
| PHP (Composer) | `composer.json` | `composer.lock` |
| Rust (crates.io) | `Cargo.toml` | `Cargo.lock` |
| .NET (NuGet, Paket) | `*.csproj`, `paket.dependencies` | `packages.lock.json`, `paket.lock` |
| Dart (pub.dev) | `pubspec.yaml` | `pubspec.lock` |
| C/C++ (Conan, vcpkg) | `conanfile.txt`, `conanfile.py`, `vcpkg.json` | `conan.lock` (Conan 2.x shape; richer detail, including v1 lockfiles, if [`syft`](https://github.com/anchore/syft) is installed) |

`setup.py` extraction only resolves a literal `install_requires` list (via `ast.literal_eval`, this tool never executes code from a scanned repo); a dynamically-computed value (a variable, a call to a helper that reads `requirements.txt`) can't be resolved statically and is silently skipped, not guessed.

Not read: Ruby's `*.gemspec`, and (for C/C++) anything declared only through raw CMake (`find_package()`, `FetchContent_Declare()`) or a system package manager (apt, brew, etc.) without a Conan/vcpkg manifest, those don't name a package+version in one consistent, greppable place without actually running the build. `cartridge-scanner` surfaces `find_package()`/`FetchContent_Declare()`/`.gitmodules` hits as a separate, clearly-labeled unversioned signal, but this skill's usage/health scan doesn't act on them, see its own docs. A project relying only on those unread manifest forms won't show up in the scan for that ecosystem.

## How it flows

```
    ┌──────────────────────────────────────────┐
    │ "Should we drop this dependency?"        │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 1. Run dead_weight_scan.py usage         │
    │ local only, no network, all 10 ecosystems│
    │ -> files, call sites, usage tier per dep │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 2. Full usage-tier table                 │
    │ every direct dependency gets a row       │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 3. Triage the deep-dive set              │
    │ minimal/light tier, capped at 15,        │
    │ + anything the user named directly       │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 4-5. Read call sites + live health check │
    │ recency, maintainers, downloads,         │
    │ version-scoped OSV vulnerability check   │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 6. Judge replacement complexity          │
    │ trivial to hand-roll, or not worth it    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 7. Final verdict                         │
    │ KEEP / CANDIDATE TO INLINE /             │
    │ KEEP BUT WATCH / NEEDS HUMAN JUDGMENT    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 8-9. Write the report, offer to save     │
    └──────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Python 3 on `$PATH` (the helper script is stdlib-only, `urllib.request` handles the HTTP calls, no extra packages). This skill's own scan (`dead_weight_scan.py`) never shells out to `syft`, that's `cartridge-scanner`-only, used purely to enrich the Conan declared/resolved counts in its inventory
- **Outbound network access is required for the health-check phase.** This is the one skill in the plugin that isn't offline-safe, Step 1 (usage scanning) is fully local, but Step 5 makes real calls to npm, PyPI, crates.io, RubyGems, Packagist, Maven Central, NuGet, pub.dev, Go's module proxy, and OSV.dev, whichever apply per dependency. C/C++ has no registry-side call at all (neither ConanCenter nor vcpkg expose a public metadata API), only the OSV.dev vulnerability check runs for that ecosystem
- Run from inside the repository being analyzed, both for the local usage scan and to resolve pinned versions from lockfiles for the health check

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
cp -r /tmp/sec-arcade/skills/dead-weight-detector ~/.claude/skills/
mkdir -p ~/.claude/sec-arcade-standalone
cp -r /tmp/sec-arcade/scripts ~/.claude/sec-arcade-standalone/

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/dead-weight-detector .claude/skills/
```

`dead_weight_scan.py` imports helper functions from `cartridge_scan.py` at the module level, so both must stay in the same directory, copying the whole `scripts/` folder above (not the individual files) keeps that intact. `SKILL.md` also references both scripts via `${CLAUDE_PLUGIN_ROOT}/scripts/...`, an environment variable Claude Code only sets automatically for a full plugin install. For this standalone copy to work, set it yourself before launching Claude Code, e.g. add `export CLAUDE_PLUGIN_ROOT=~/.claude/sec-arcade-standalone` to your shell profile. Installing the whole arcade (Option 1) handles all of this automatically.

## Usage

Open Claude Code inside the repo you want audited, then ask directly:

```
Is this dependency worth keeping, or should we inline it?
```

```
Audit our dependencies, what's barely used and what's not well maintained?
```

```
Should we drop lodash and write our own version of what we actually use?
```

The skill runs the local usage scan first, triages candidates, then makes live registry calls only for the ones that need a closer look.

### Example run (excerpt)

```
## Deep Dive

### left-pad (npm)
- Usage: 1 file, 1 call site, tier minimal
- What it's used for: src/format.js:3, pads a single numeric ID to
  3 digits before display.
- Status: Slowing - recency 2015-03-24 (over 12mo), 1 maintainer,
  1,240,000 downloads/mo
- Replacement complexity: trivial, `String(n).padStart(3, '0')` is a
  one-line stdlib replacement for the entire used surface.
- Verdict: CANDIDATE TO INLINE
- Next action: replace with `String.prototype.padStart`, no reason to
  carry an external dependency, network install, and supply-chain
  surface for this.
```

## Limitations

- Usage-site counting is regex-based, not AST-aware. It can overcount when a bound identifier's name also appears inside the import path/module string itself, and it can miss usage through re-exports, dynamic imports, or heavy indirection. Treat tiers as directional, verify borderline cases by reading the cited call sites.
- Ruby, PHP, and C/C++ usage detection is explicitly weaker (`"usage_signal": "weak"`). Dynamic dispatch and PSR-4 autoloading defeat static symbol matching for Ruby/PHP; C/C++'s `#include` doesn't bind a symbol at all, and mapping a header path to a package name (e.g. `#include <fmt/format.h>` -> `fmt`) is an author convention, not a registry-enforced rule.
- Health-signal coverage varies a lot by ecosystem, see `references/registry-health-signals.md`. Go, Java, and .NET have no clean maintainer-count or download API, those fields report `n/a` honestly rather than a guess.
- PyPI download counts come from `pypistats.org`, a third-party service, not PyPI itself. If it's down or rate-limited, that one field degrades to unavailable, the rest of the health check still runs.
- Archived-repository detection only works for GitHub-hosted packages, and only when the registry's own metadata names a repository URL at all. GitLab, Bitbucket, self-hosted, or unlisted repositories report Unknown rather than a guess, see `references/registry-health-signals.md`'s GitHub-archived section for exactly which ecosystems this covers.
- This skill does not check for known vulnerabilities (CVEs). It deliberately doesn't report on that, use `patch-for-the-high-score` for a finding that already needs a patch-vs-upgrade decision.
- Not a substitute for a real SCA tool for CVE tracking over time. This skill's OSV check is a point-in-time read during the deep dive, not continuous monitoring.

## Next cabinet

[`cartridge-scanner`](../cartridge-scanner) is the natural predecessor: it inventories what dependencies exist across a repo, this skill picks up from there and asks whether each one earns its place. When an SCA finding needs an actual patch-vs-upgrade decision, not just a health read, [`patch-for-the-high-score`](../patch-for-the-high-score) reuses this skill's health-check script to make that call.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
