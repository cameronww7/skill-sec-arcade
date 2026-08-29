# Save States: the shared "save this report" convention

Any skill that produces a full report (not a short verdict) offers to save it once the report has been shown in full, never before, the user needs to see the report to decide whether it's worth keeping. This doc is the single definition of that mechanism; a skill's own `SKILL.md` should just point here instead of re-explaining it.

## Where reports go

Reports are written into the **target repo being analyzed** (the repo the skill was pointed at), not into this plugin's own repo. The shared folder is:

```
.SEC-Arcade-save_states/
```

created at the root of the target repo the first time anything gets saved into it. Each skill keeps its own fixed, canonical filename inside that folder, one file per skill, overwritten on every save:

| Skill | File |
|---|---|
| `cartridge-scanner` | `.SEC-Arcade-save_states/CARTRIDGE_SCAN.md` |
| `dungeon-crawl-threat-map` | `.SEC-Arcade-save_states/THREAT_MODEL.md` |
| `dead-weight-detector` | `.SEC-Arcade-save_states/DEAD_WEIGHT_REPORT.md` |
| `mini-map` | `.SEC-Arcade-save_states/MINI_MAP.md` |

A fixed filename, not a timestamped one, is deliberate: overwriting the same path is what lets the user (or a future skill run) `git diff` it against the previous run and see exactly what drifted, new dependencies, a private registry that showed up, a usage tier that changed.

This folder is also meant to be a stable place other skills can check for prior context before doing their own work, for example a future skill could look for `.SEC-Arcade-save_states/CARTRIDGE_SCAN.md` before re-deriving a repo inventory from scratch. Standardizing the location now is what makes that reuse possible later.

## The prompt

After the full report has been produced and shown inline, ask with `AskUserQuestion`, a single question, three options:

1. **Save and commit** — write the report to its canonical path under `.SEC-Arcade-save_states/`. Don't touch `.gitignore`.
2. **Save, local only** — write the same file, then make sure that exact file path has an entry in the target repo's `.gitignore`. Create `.gitignore` if the target repo doesn't have one. If it exists, append the entry only if it isn't already present, don't duplicate it on repeat runs. Ignore the specific file path (e.g. `.SEC-Arcade-save_states/CARTRIDGE_SCAN.md`), not the whole folder, since another skill's report living in the same folder might be one the user wants committed.
3. **Don't save** — inline only, nothing written, `.gitignore` untouched.

Whether a report is worth committing is a per-run call, not a fixed project policy, that's why this is a live prompt every time rather than something decided once in a config file.

## The file content

Whatever gets written must be byte-for-byte the same report already shown in the conversation. Don't summarize, trim, or reformat it for the file version.

## Exception: `mini-map`

`mini-map` writes `MINI_MAP.md` directly, with no `AskUserQuestion` prompt. It's the one deliberate exception to the convention above: every other file in this table is a full report a human decides whether to keep, `MINI_MAP.md` is a condensed context file written for other skills to load automatically, prompting on every run would just be friction against its own purpose.
