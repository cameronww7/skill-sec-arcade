# Trim Reaper Phase Rules

Static reference for [`trim-reaper`](../skills/trim-reaper). The recommendation-table format, the final-report format, the apply-verify-revert loop's failure handling, and the full security risk-ordering table, all restated here instead of in `SKILL.md` so every phase section there can cite one line and move on.

## Recommendation table format

Every phase that proposes changes (Phases 1-7) shows its candidates as one numbered table before asking for approval:

| # | Package | Proposed action | Evidence | Risk rank | Transitive packages affected | Flags |
|---|---|---|---|---|---|---|
| 1 | `left-pad` | Remove | Zero references across all 9 search categories (see evidence below table) | High (unpinned, no install script) | 0 | - |
| 2 | `moment` | Replace with `Intl.DateTimeFormat` (stdlib) | 14 call sites, all formatting only, no timezone math; Node 18+ runtime floor confirmed | Medium (archived upstream) | 3 | needs tests |

Evidence that doesn't fit in the table cell (the full per-category search_results breakdown, the call-site inventory, the tree diff) goes directly below the table, one block per candidate, not crammed into the Evidence column.

The developer replies with which numbers to apply, `all`, or `none`. Phase 7 never shows this prompt at all, it recommends only.

## Risk ranking (full table)

Within any phase's candidate list, order riskiest-first using these factors, each one pushing a candidate up the list independently (a candidate with more than one factor present ranks above a candidate with only one):

| Risk factor | Why it matters | Source |
|---|---|---|
| Has an install/lifecycle script | Runs arbitrary code at install time, the single highest-leverage supply-chain risk a dependency can carry | `trim_reaper_scan.py lifecycle-scripts` |
| Sourced from git/URL or a non-default registry | Bypasses the ecosystem's normal publish/review path entirely | `trim_reaper_scan.py unpinned-versions` (`git_or_url` pin_class) and `cartridge_scan.py`'s `private_registries[]` |
| Unpinned version (caret/tilde/range/wildcard) | A routine install can silently pull a different, unreviewed release | `trim_reaper_scan.py unpinned-versions` |
| Unmaintained or archived upstream | No one is left to ship a fix if something is found later | `dead_weight_scan.py health` |
| Single maintainer | One person leaving, losing access, or having an account compromised can take the whole package down with it | `dead_weight_scan.py health` |

## Apply-verify-revert loop (failure handling detail)

Applies to every item approved in Phases 1-6:

1. Apply exactly one approved item through the package manager (never by hand-editing a lockfile).
2. Run the build/test/lint commands recorded in Phase 0's baseline.
3. Compare against the baseline's own pass/fail state, not against a zero-failures ideal, a pre-existing failure the developer already chose to tolerate in Phase 0 is not a new failure.
4. If nothing new failed: commit (`trim-reaper(p<N>): <action> <package>: <reason>`), record it in the Applied Changes log, move to the next approved item.
5. If something new failed: revert just that one item (the package manager's own revert, e.g. reinstalling the removed package, not a git revert of other items), record it in the Reverted Items log with the failure that caused it, and continue with the next approved item, don't stop the whole phase over one reversion.
6. Never batch multiple items into one commit, even if a developer approved several at once, each gets applied, verified, and committed (or reverted) on its own before the next one starts.

## Final report format (Phase 8)

Seven required sections, in this order:

1. **Direct and transitive dependencies removed** - counts plus the actual package names, not just totals.
2. **Production scope changes** - every dependency moved between manifest sections (e.g. `dependencies` to `devDependencies`), reported separately from removals per the spec's own rule.
3. **Local code added** - every module written in Phase 3, each one tagged "needs tests" exactly as it was flagged when added.
4. **Dependencies retained and why** - every dependency a phase considered and chose not to touch, with the one-line reason (used elsewhere in a monorepo, stdlib replacement would need a higher runtime floor, etc).
5. **Deferred and reverted items** - pulled directly from the state file's own Deferred Items and Reverted Items logs, not re-derived.
6. **Checks that could not be completed, with reasons** - e.g. "no tests existed, verification was install+build only," "lifecycle-script detection for transitive dependencies is unverifiable without a local install," stated plainly, not omitted.
7. **Security section** - attack-surface delta (direct + transitive packages removed, install scripts eliminated), and supply-chain hygiene flags on every dependency still retained (unpinned versions, non-default registries, single maintainers) so a clean run doesn't imply a fully clean dependency tree.
