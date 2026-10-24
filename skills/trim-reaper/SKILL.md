---
name: trim-reaper
description: Reduces third-party dependencies with a security-first lens: finds confirmed-unused packages, standard-library and small-utility replacements, overlapping-library consolidation, heavy transitive trees, and dev/prod scope mistakes, then applies each approved change one at a time with build/test verification and tidies up the leftovers. Trigger this for "trim our dependencies," "prune unused packages," "reduce our dependency footprint," "audit and remove dead dependencies," "shrink node_modules / the dependency tree," "do we really need this package," "consolidate our HTTP clients/date libs/validators," "move this to devDependencies," or "replace this with the standard library." Runs one phase (0-8) per invocation, via /trim-reaper <phase>, /trim-reaper next, or /trim-reaper status, and always stops for developer sign-off before applying anything. Does not evaluate CVEs or vulnerability data (that's patch-for-the-high-score / player-two-verdict), and does not just report health without applying (that's dead-weight-detector).
---

# Trim Reaper

## Why this skill exists

Every dependency, and every replacement for one, has to earn its ongoing maintenance cost. [`cartridge-scanner`](../cartridge-scanner) can tell you what dependencies exist. [`dead-weight-detector`](../dead-weight-detector) can tell you which ones look unhealthy or barely used. Neither one removes, replaces, or tidies anything, they stop at the recommendation. This skill is the one that actually does the work, one phase at a time, with a developer reviewing and approving every single change before it lands.

The security framing matters as much as the cleanup framing: fewer dependencies means fewer install scripts that can run arbitrary code, fewer unpinned versions that can silently pull something different tomorrow, and a smaller, better-understood attack surface overall. A phase that removes ten packages but can't say which of them had install scripts hasn't actually told you how much risk went away.

## When to use this

- The user wants to trim, prune, audit, or reduce a repo's third-party dependencies.
- The user is asking whether a specific package is still needed, or whether several packages doing the same job could be consolidated into one.
- The user wants to move a dependency between `dependencies` and `devDependencies` (or the equivalent in another ecosystem), or otherwise fix a dev/prod scoping mistake.

This is **not** the right skill for:
- Evaluating CVEs or known vulnerabilities in a dependency, that's [`patch-for-the-high-score`](../patch-for-the-high-score) or [`player-two-verdict`](../player-two-verdict) instead. This skill's security angle is supply-chain hygiene (install scripts, unpinned versions, maintenance health), never CVE data.
- Just wanting a health/usage report with no changes applied, that's [`dead-weight-detector`](../dead-weight-detector).
- Just wanting a repo inventory (what dependencies exist, what ecosystems are in play), that's [`cartridge-scanner`](../cartridge-scanner).

## Invocation and phase control

This skill runs as a real slash command: `/trim-reaper <0-8>`, `/trim-reaper next`, or `/trim-reaper status`.

- `/trim-reaper <N>` runs phase `N` specifically, even out of order, as long as Phase 0 has already run (every later phase needs Phase 0's baseline).
- `/trim-reaper next` reads the state file (see "State file and the save prompt" below), finds the lowest-numbered phase not marked `done`, and resumes it. If that phase has partial progress (some candidates already applied from a prior run), re-show only the remaining un-actioned candidates, don't re-ask about ones already resolved.
- `/trim-reaper status` reads the state file and prints its Phase Progress table and logs verbatim, no scan, no changes.
- **Exactly one phase runs per invocation.** Never chain into the next phase automatically, even if the current one finished with zero candidates or nothing to apply. Stop and wait for the next explicit invocation.

## Step 0: Prerequisite check

Before any phase runs:

1. Confirm `python3` is on PATH and the target is a git repository.
2. Run `git status`. If the working tree isn't clean, stop and tell the user plainly, don't start a branch on top of uncommitted work.
3. Check whether `.SEC-Arcade-save_states/TRIM_REAPER_STATE.md` already exists in the target repo.
   - If it doesn't: this is a fresh run. Create branch `trim-reaper/<YYYY-MM-DD>` and proceed to whichever phase was requested (Phase 0 if nothing else makes sense yet).
   - If it does: this is a resume. Read it, confirm the branch it names is still the current branch (if the developer switched branches since the last run, stop and ask rather than committing to the wrong one), and proceed from there.
4. On a fresh run only, ask the developer once, via `AskUserQuestion`, to confirm that approving a numbered item in any phase also authorizes this skill to commit that one change immediately (branch `trim-reaper/<date>`, message `trim-reaper(p<N>): <action> <package>: <reason>`), rather than re-confirming before every individual commit. This is a one-time, whole-run authorization, not a blanket one, it only ever applies to changes the developer has already approved by number in that phase's own prompt.

## Step 1: The apply-verify-revert loop (shared by Phases 1-6)

Every phase from here that applies anything uses this exact loop, defined once here:

1. Apply exactly one approved item through the package manager (commands from `${CLAUDE_PLUGIN_ROOT}/references/package-manager-commands.md`), never by hand-editing a lockfile.
2. Run the build/test/lint commands recorded in Phase 0's baseline.
3. If nothing new failed (compared against Phase 0's own tolerated baseline, not a zero-failures ideal): commit and record it in the state file's Applied Changes log.
4. If something new failed: revert just that one item, record it in the Reverted Items log with the failure, and continue with the next approved item. One reversion never stops the rest of the phase.

Full detail on this loop and the failure-handling rule lives in `${CLAUDE_PLUGIN_ROOT}/references/trim-reaper-phase-rules.md`; every phase section below just says "use the apply-verify-revert loop" instead of repeating it.

## Step 2: Phase 0 - Baseline

Runs once per trim-reaper run, before any other phase.

1. Identify install/build/test/lint/typecheck commands from package scripts, Makefile, CI workflows, and README. Confirm them with the developer before trusting them as the baseline.
2. Record the runtime floor (minimum language/runtime version this project supports) from manifests, version files, CI matrix, or Docker base images. Phases 2 and 3 cannot use an API newer than this floor.
3. Run the baseline (install, build, test, lint). If it fails, stop and ask whether to proceed anyway. If the developer proceeds, record the existing failures in the state file, later phases are measured against this baseline, not against zero failures.
4. If no tests exist, say so plainly and record that every later phase's verification is install+build (and lint, if present) only.
5. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/cartridge_scan.py <path>` (or reuse its output if `cartridge-scanner` already ran this session). Record direct/transitive dependency counts from `package_managers[]`.
6. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/trim_reaper_scan.py lifecycle-scripts <path>`. Record every package with a lifecycle script, and state the `coverage_limitation` field's text plainly, don't imply a clean result means no install scripts exist anywhere in the tree.
7. Build the non-code reference map from cartridge_scan.py's own `containers.dockerfiles[]` and `iac{}` fields, this is what Phase 1's search draws on for the Dockerfiles/CI evidence category, and what Phase 8 checks before touching any of those files.
8. Write all of this to the state file (see "State file and the save prompt").

## Step 3: Phase 1 - Remove confirmed unused dependencies

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/trim_reaper_scan.py candidates <path>`. Read its full `workspaces[]` output.
2. **A `"zero_references_found": true` result is a candidate, never proof.** Say this explicitly at the point of the approval prompt itself, not just once earlier in the conversation. Show the per-category `search_results` breakdown for every candidate so the developer can judge the evidence themselves.
3. Monorepos: a package unused in one workspace entry may be used in another, or reached through hoisting. Cross-check a workspace's own zero-reference candidates against every other workspace's dependency list before treating it as unused anywhere.
4. A candidate with a non-null `type_definition_pair` (a `@types/<name>` package) must be evaluated together with its pair, never independently, removing one without the other orphans the half left behind.
5. Rank candidates by risk per `${CLAUDE_PLUGIN_ROOT}/references/trim-reaper-phase-rules.md`'s risk table (install scripts, unpinned/git-sourced versions from `trim_reaper_scan.py unpinned-versions`, and maintenance health from `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/dead_weight_scan.py health <ecosystem> <path> <name> [<name> ...]`, called on this phase's own candidates), riskiest first.
6. Show the numbered recommendation table (`${CLAUDE_PLUGIN_ROOT}/references/trim-reaper-phase-rules.md`'s format). Wait for the developer's reply.
7. For each approved item: remove it through the package manager (never a transitive package directly, let the package manager prune orphaned transitives on its own), then run the apply-verify-revert loop.
8. Report which transitive packages were pruned as a result.

## Step 4: Phase 2 - Use the standard library

1. For each dependency the developer wants evaluated, inventory exactly which of its functions are actually called at every call site.
2. Recommend replacement only if **every** call maps to a standard/platform API available at Phase 0's recorded runtime floor. List behavior differences per replacement: error types, defaults, timeouts, encoding, ordering, sync vs. async.
3. If a replacement would need a higher runtime floor than Phase 0 recorded, defer it and state the floor it actually needs, don't silently drop it from the report.
4. Show the recommendation table, wait for approval, apply via the loop in Step 1.

## Step 5: Phase 3 - Replace simple functionality

1. Candidates are narrow, well-defined, near-pure utilities. Judge by correctness and ongoing maintenance burden, not line count.
2. Write the replacement from the call sites' actual observed needs, never by copying the dependency's own source. If any code genuinely is adapted from it, keep its license notice.
3. Put new local modules in one location following the repo's own existing conventions, not a new structure invented for this.
4. Defer a candidate once its edge cases keep growing, or the work starts to mean reproducing a real spec or standard, that's a sign it belongs in Phase 7 instead.
5. Every new module gets flagged `needs tests` in the state file and the phase report; this skill never writes tests itself.
6. Show the recommendation table, wait for approval, apply via the loop in Step 1.

## Step 6: Phase 4 - Consolidate overlapping libraries

1. Group direct dependencies doing the same job (HTTP clients, date libraries, utility belts, validation, logging, CLI parsing, config).
2. For each group, pick the library to retain based on existing usage breadth, maintenance health, transitive weight, how much of the group's current call sites it already covers, coupling, and license. State why it won over the alternative(s) in the group, one line per factor.
3. Only use documented, supported APIs of the retained library. Don't make a module depend on it if that module didn't depend on either option before, consolidation migrates existing usage, it doesn't spread new usage.
4. Show the recommendation table, wait for approval, apply via the loop in Step 1.

## Step 7: Phase 5 - Reduce heavy dependency trees

1. For each direct production dependency, measure how many transitive packages exist only because of it.
2. In order, consider: disabling an unused optional feature/extra, switching to a documented minimal package from the same project, using an alternative already elsewhere in the tree, or moving the candidate to Phase 2, 3, or 7 instead.
3. Never remove or exclude a transitive package that a retained dependency still needs. Only use an exclusion/override when the pulling library's own documentation lists it as supported.
4. Show the dependency tree diff before and after each proposed change (via the ecosystem's tree command from `${CLAUDE_PLUGIN_ROOT}/references/package-manager-commands.md`).
5. Show the recommendation table, wait for approval, apply via the loop in Step 1.

## Step 8: Phase 6 - Separate development from production

1. Classify every direct dependency as runtime, build, test, lint/format, types, or local-tooling, and check it against its actual manifest scope.
2. Watch specifically for: a start script invoking a dev-scoped package directly (`trim_reaper_scan.py candidates`' `scripts_and_makefiles` category surfaces this), a published library whose own emitted type definitions reference a type package, a Docker build that compiles after an already production-only install, and a genuinely runtime package wrongly scoped as dev.
3. Verify every proposed rescoping with a clean production-only install (the command from `${CLAUDE_PLUGIN_ROOT}/references/package-manager-commands.md`) and, if a start command exists, by actually starting the app.
4. Report scope changes as their own section, separate from Phase 1's removals, per the spec's own rule.
5. Show the recommendation table, wait for approval, apply via the loop in Step 1.

## Step 9: Phase 7 - Evaluate larger replacements (recommend only)

**This phase never applies anything.** No numbered-reply approval prompt, no apply-verify-revert loop.

1. Candidates are items deferred from Phases 2 through 5, plus any dependency `dead_weight_scan.py health` flagged as poorly maintained.
2. For each candidate, compare implementation effort, code added, security, correctness risk, performance, and ongoing maintenance, one line of evidence per factor, and give a plain retain-or-replace recommendation.
3. Show the comparison table. There is nothing to wait for approval on, this phase's output is the report itself.

## Step 10: Phase 8 - Verify the final result

1. In a fresh worktree, do a frozen install from the lockfiles (never regenerate them), run the build, run the existing tests, and do a production-only install.
2. Update manifests, lockfiles, docs, and license/NOTICE files to match everything applied across Phases 1-6.
3. Update tool config and Dependabot/Renovate rules for anything removed or rescoped.
4. If the repo already has an SBOM, regenerate it with whatever generator/format produced it (read the existing file's own metadata/header to identify the command, re-run that, don't switch tools or formats). If the repo has no SBOM, don't create one.
5. Ask before changing CI workflows, Dockerfiles, deployment manifests, or the public API of a published package, this rule applies in every phase, but Phase 8 is where it's most likely to come up since it's touching final housekeeping files.
6. Produce the final report, exactly the seven sections in `${CLAUDE_PLUGIN_ROOT}/references/trim-reaper-phase-rules.md`'s final-report format, in that order.

## Tidying (leftovers only)

Every phase that removes or replaces a dependency also cleans up what that specific change leaves behind: dead imports, an orphaned wrapper file, a tool-config entry for a now-removed plugin, a stale override/resolution, a Dependabot/Renovate rule naming a package that no longer exists, a README/CONTRIBUTING mention of it. Tidying never reaches beyond what this skill itself removed or replaced in this run, it is not a general cleanup pass.

## Security ranking and do-not-replace list

Candidates in every phase are ranked riskiest-first using the factors in `${CLAUDE_PLUGIN_ROOT}/references/trim-reaper-phase-rules.md`'s risk table: an install/lifecycle script, a git/URL or non-default-registry source, an unpinned version, unmaintained/archived upstream status, and a single maintainer. Flag these same hygiene issues on dependencies a phase chooses to **retain**, too, not only on ones proposed for removal, a clean run report should never imply the whole retained tree is itself clean.

**Never replace any of the following with local code**, no matter how simple a specific call site looks. Moving to the standard library or to a different, better-maintained library is fine, writing your own is not:

- Cryptography and secure randomness
- Password hashing
- TLS and certificate validation
- Authentication and authorization (JWT, OAuth, SAML, sessions)
- HTML/Markdown/SVG sanitization and output encoding
- XML parsing
- YAML or other object-constructing loaders
- Deserialization of untrusted input
- URL parsing used for a security decision
- Archive extraction
- Regex validation of untrusted input
- Date/time/timezone handling
- Unicode and internationalization
- Database drivers and ORMs

## State file and the save prompt

Progress lives in `.SEC-Arcade-save_states/TRIM_REAPER_STATE.md`, in the **target** repo, with these fields: target repo path, branch name, baseline commit sha, run-started/last-updated dates, a Baseline block (commands, runtime floor and its source, pre-existing tolerated failures, whether tests exist, dependency counts, packages with lifecycle scripts, the non-code reference map), a Phase Progress table (phase, status, candidate count, applied count, deferred count, reverted count, last run date), and three running logs: Applied Changes, Deferred Items, Reverted Items.

After every phase's full report is shown inline, follow `${CLAUDE_PLUGIN_ROOT}/references/save-states.md`'s save/commit/local-only/don't-save prompt, every phase re-earns this decision on its own, a developer might want Phase 1's outcome kept and decline to save Phase 7's notes. Choosing "save and commit" writes the state file but does **not** create its own separate git commit for it, only the per-package commits from the apply-verify-revert loop land in this branch's git history. If the developer chooses "don't save" on some phase, `/trim-reaper status` and `/trim-reaper next` still work correctly off of git history alone, the state file is a bookkeeping convenience, not the sole record of what was actually applied.

A phase with zero candidates still gets marked `done, 0 candidates` in the Phase Progress table (not skipped entirely), so `/trim-reaper status` never shows a finished phase as perpetually pending.

## Voice and format

No em dashes. Lead with tables wherever the spec calls for one (recommendation tables, risk tables, the dependency tree diff), reserve prose for the reasoning a table cell can't hold. Every number should be traceable back to a specific script output field, not asserted from memory.

## Reference material

- `${CLAUDE_PLUGIN_ROOT}/scripts/cartridge_scan.py`: repo/ecosystem inventory, used in Step 2 (Phase 0).
- `${CLAUDE_PLUGIN_ROOT}/scripts/trim_reaper_scan.py`: lifecycle-script detection, unpinned-version classification, and the unused-dependency candidate search, used in Steps 2 and 3 (Phases 0 and 1).
- `${CLAUDE_PLUGIN_ROOT}/scripts/dead_weight_scan.py`: maintenance-health lookups (`health` mode), used in Step 3 (Phase 1's risk ranking) and Step 9 (Phase 7's comparison table).
- `${CLAUDE_PLUGIN_ROOT}/references/package-manager-commands.md`: per-ecosystem install/remove/tree/why-installed/production-only-install commands and unused-dependency tools, used in Steps 1, 3, 7, and 8.
- `${CLAUDE_PLUGIN_ROOT}/references/trim-reaper-phase-rules.md`: the recommendation-table format, the full risk table, the apply-verify-revert loop's failure-handling detail, and the final-report format, used throughout Steps 1-10.
- `${CLAUDE_PLUGIN_ROOT}/references/save-states.md`: the shared save-to-file convention, used after every phase.
