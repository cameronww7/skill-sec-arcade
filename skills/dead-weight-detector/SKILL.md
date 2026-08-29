---
name: dead-weight-detector
description: Analyze how much each direct OSS dependency is actually used in first-party code, cross-reference that against live maintenance-health signals from the package's own registry (release recency, maintainer count, download volume, known unpatched vulnerabilities), and recommend keep vs. replace with first-party code. Trigger this whenever the user asks "is this dependency worth keeping," "should we drop this package," "audit our dependencies," "which OSS packages are barely used," "should we inline this instead of using a dependency," "is X well maintained," or wants a dependency health check. Requires live network access for the health-check phase, unlike this plugin's other skills.
---

# Dead Weight Detector

## Why this skill exists

A dependency usually gets added for a good reason: a one-line import, one function call, problem solved. Nobody revisits that choice later. Each dependency added this way is a small, permanent liability: it has to be kept patched, it's a supply-chain trust surface, and if the upstream project goes quiet that risk just sits there, unreviewed, indefinitely.

[`cartridge-scanner`](../cartridge-scanner) already answers *what* dependencies exist and roughly how many. This skill goes one level deeper, per dependency: how much of it is actually used in first-party code, and is the package itself still a going concern? Then it renders a judgment: keep it, watch it, or replace it with first-party code that's fully under this team's control. Same evidence-gathered-mechanically, verdict-reasoned-qualitatively spirit as [`player-two-verdict`](../player-two-verdict) and [`tilt-check`](../tilt-check), not a score nobody can argue with.

## When to use this

- The user wants to know if a specific dependency, or the dependency set as a whole, is worth keeping.
- The user is deciding whether to inline a small piece of functionality instead of adding or keeping a dependency for it.
- The user wants a maintenance-health check on their dependencies: is anything effectively abandoned, single-maintainer, or carrying a known unpatched vulnerability in the version actually pinned.
- The user names a specific package and asks "should we drop this."

If the user just wants an inventory (what exists, how many, what package managers), that's `cartridge-scanner`'s job, run it first if that inventory doesn't already exist in the conversation.

## Step 1: Run the local usage scan

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/dead_weight_scan.py usage <path>
```

Fully local, no network. Returns every direct dependency across all nine ecosystems `cartridge-scanner` covers (npm/yarn/pnpm, Python, Go, Java, Ruby, PHP, Rust, .NET, Dart), each with `files_importing`, `call_site_count`, `distinct_symbols_used`, and a computed `usage_tier` (`minimal` / `light` / `moderate` / `heavy`).

These tiers are a starting heuristic, not a precise measurement. Two known sources of noise, say so if a specific result looks off rather than trusting the number blindly:

- **Regex-based symbol counting can overcount** when a bound identifier's name also appears inside the import path/module string itself (e.g. a package literally named the same as its own path segment). Read the actual call sites in Step 4 before trusting a borderline number.
- **Ruby and PHP get a weaker signal** (`"usage_signal": "weak"` in the output). Dynamic dispatch and PSR-4 autoloading defeat static symbol matching, so their `call_site_count` is really just a `require`/`use` occurrence count, not real usage depth. Treat these two ecosystems' results as a starting point for manual review, not a verdict input on their own.

## Step 2: Full usage-tier table

Every direct dependency gets one row here, this is cheap (no network) and complete, it's the transparency layer even for dependencies that never get a full deep-dive below. Group by ecosystem, sort lowest-usage first within each group so the reader sees the interesting rows immediately.

## Step 3: Triage the deep-dive set

Select dependencies for the full workup (Steps 4-7):

- Any dependency at `minimal` or `light` usage tier, capped at **15 per run**. If more than 15 qualify, take the 15 with the lowest `call_site_count` and say plainly that the rest were left at the table-only level, same pattern as `player-two-verdict`'s finding cap.
- Any package the user explicitly named, regardless of its usage tier, this forces inclusion even for a `heavy`-tier dependency if that's specifically what they asked about.

Dependencies at `moderate`/`heavy` usage tier that weren't named by the user get one line in the table and nothing more, don't spend a health-check network call justifying something that's obviously earning its keep.

## Step 4: Read the actual call sites

For each triaged candidate, open the files from Step 1's `files_importing` list and read the real call sites, enough to describe in one or two plain-language sentences what the dependency is actually being used for. This is what makes Step 6's judgment call credible instead of a guess from the package name alone.

## Step 5: Run the live health check

Only for the names triaged in Step 3, this is what keeps network calls bounded:

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/dead_weight_scan.py health <ecosystem> <repo_path> <name> [<name> ...]
```

`<repo_path>` is used to resolve each name's pinned version from the local lockfile, so the vulnerability check is scoped to what's actually installed. Read `${CLAUDE_PLUGIN_ROOT}/references/registry-health-signals.md` for exactly which fields are available per ecosystem and the tier thresholds, don't restate that table, cite it. Report `"n/a"` fields honestly as unavailable for that ecosystem, never imply a number that wasn't returned.

If `vulnerabilities.version_scoped` is `false`, the listed vulnerability IDs are the package's entire historical advisory list, not confirmation the pinned version is affected. Say this explicitly if any show up unscoped, and don't let them alone justify an At Risk framing in your own writeup (the script already won't compute that as the tier, but the raw IDs still get surfaced, contextualize them correctly).

## Step 6: Judge replacement complexity

This is the actual value this skill adds over a mechanical script: is what's being used trivial to hand-roll, or genuinely risky to reimplement? Calibration anchors:

- **Usually trivial to inline**: a single string-padding/formatting helper, a basic debounce/throttle, a small array/object utility (chunk, unique, flatten), a simple retry loop, a one-off validation regex wrapper.
- **Usually not worth reinventing**, even at low usage: anything cryptographic (hashing, signing, random token generation), timezone/calendar math, HTML/URL/SQL sanitization or escaping, parsers for a real format (JSON is fine to trust the stdlib for, a custom binary or config format usually isn't), anything implementing a security control (auth, CSRF, rate limiting).

State which bucket the used surface falls into and why, in one or two sentences, don't just assert it.

## Step 7: Final verdict

One of four, always evidence-cited back to Steps 1-6:

- **KEEP**: `moderate`/`heavy` usage, or `healthy` health tier regardless of usage tier (a well-maintained, widely-used dependency used lightly is still fine, e.g. a small well-known utility with no real risk in carrying it).
- **CANDIDATE TO INLINE**: `minimal`/`light` usage tier AND the used surface was judged trivial to hand-roll in Step 6.
- **KEEP BUT WATCH**: usage tier is fine on its own, but health tier came back `slowing` or `at_risk`. Not urgent, but flag it and recommend planning ahead rather than waiting for a forced migration.
- **NEEDS HUMAN JUDGMENT**: signals conflict (e.g. trivial-to-inline usage but the health check came back `healthy` and widely relied upon elsewhere too), or health data came back `unknown`. Don't force a verdict the evidence doesn't support, say what's missing and what would resolve it.

## Step 8: Write the report

### Voice

- No em dashes.
- Table-first for the full inventory (Step 2), narrative verdict blocks only for the triaged deep-dive set.
- Every usage claim traces to a `file:line`-style citation from Step 4. Every health claim traces to a named field from Step 5's output (`recency`, `maintainers`, `downloads`, `vulnerabilities`), not a vague "looks unmaintained."
- State plainly whenever a signal came back `n/a` or `unknown`, don't paper over a gap with a confident-sounding sentence.

### Format

```
# Dead Weight Report: [repo/directory name]

## Full Dependency Inventory

### [ecosystem]
| Dependency | Files | Call Sites | Usage Tier |
|---|---|---|---|
[one row per direct dependency, lowest usage first]
[repeat per ecosystem present]

## Deep Dive

### [dependency name] ([ecosystem])

**Usage**: [files_importing] files, [call_site_count] call sites, tier [minimal/light/moderate/heavy]
**What it's used for**: [1-2 sentences from Step 4, cited by file:line]
**Health**: recency [date or n/a] · maintainers [count or n/a] · downloads [count or n/a] · vulnerabilities [none / IDs, scoped or unscoped] -> [health tier]
**Replacement complexity**: [trivial / not worth reinventing], [why, 1 sentence]

**Verdict: [KEEP / CANDIDATE TO INLINE / KEEP BUT WATCH / NEEDS HUMAN JUDGMENT]**
[1-2 sentence justification tying the above together]

[repeat per triaged dependency]

## Summary

[one line per verdict category: counts and the standout names, so the
reader can act without re-reading the whole report]
```

If more than 15 dependencies qualified for the deep dive, note the cap and which ones were left at table-only level, per Step 3.

## Step 9: Offer to save

After producing the report, follow the save prompt defined in `${CLAUDE_PLUGIN_ROOT}/references/save-states.md`. Frame it as something worth re-running periodically, dependency health drifts, a `KEEP` today can become `KEEP BUT WATCH` in six months without any code change on this side.

## Reference material

- `${CLAUDE_PLUGIN_ROOT}/scripts/dead_weight_scan.py`: does the mechanical work, local usage-site scanning (Step 1) and live registry health lookups (Step 5). Reuses `cartridge_scan.py`'s file-discovery helpers but does not modify that script or its output.
- `${CLAUDE_PLUGIN_ROOT}/references/registry-health-signals.md`: which health signal is available per ecosystem and where it comes from, the OSV.dev ecosystem-name mapping, and the exact health-tier thresholds, used in Step 5.
- `${CLAUDE_PLUGIN_ROOT}/references/save-states.md`: the shared save-to-file convention, used in Step 9.
