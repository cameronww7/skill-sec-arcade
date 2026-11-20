```
 ____   ___   ___ _____ _     _____ ____ 
| __ ) / _ \ / _ \_   _| |   | ____/ ___|
|  _ \| | | | | | || | | |   |  _|| |  _ 
| |_) | |_| | |_| || | | |___| |__| |_| |
|____/ \___/ \___/ |_| |_____|_____\____|

  ____    _    ____ _____ ____  ___ ____   ____ _____    ____ _   _ _____ ____ _  __
 / ___|  / \  |  _ \_   _|  _ \|_ _|  _ \ / ___| ____|  / ___| | | | ____/ ___| |/ /
| |     / _ \ | |_) || | | |_) || || | | | |  _|  _|   | |   | |_| |  _|| |   | ' / 
| |___ / ___ \|  _ < | | |  _ < | || |_| | |_| | |___  | |___|  _  | |__| |___| . \ 
 \____/_/   \_\_| \_\|_| |_| \_\___|____/ \____|_____|  \____|_| |_|_____\____|_|\_\
```

*Accent: Counterfeit Silver. The dull sheen of a cartridge that looks right until you check the board inside.*

# 🔍 Bootleg Cartridge Check

**Operational Title: Third-Party Skill Security Scan**
Statically scans a Claude Code skill or plugin you don't yet trust, before you install it, enable it, or merge it.

*A cabinet in the [sec-arcade](../../): insert token before you plug in a cartridge from outside the arcade.*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Focus](https://img.shields.io/badge/focus-supply_chain_appsec-critical)
![Scope](https://img.shields.io/badge/scope-static_detection_only-yellow)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that reads another skill's files, never executes, imports, or installs anything found in them, and reports back a static scan of known-bad patterns: credential/host overrides, unsafe deserialization, prompt-injection phrasing, persistence and tool-shadowing tricks, symlink abuse, privileged container config, and more. Catalog and rule IDs live in `references/bootleg-cartridge-rule-catalog.md`.

## Also consider: NVIDIA SkillSpector

This skill is small, Claude-Code-native, and built by one person. If you want something more battle-tested for this exact job, look at [NVIDIA SkillSpector](https://github.com/nvidia/skillspector): an open-source, Apache-2.0-licensed security scanner built specifically for AI agent skills (Claude Code, Codex CLI, Gemini CLI, and more), backed by NVIDIA and widely adopted (27,000+ GitHub stars at last check). It runs 71 deterministic static-analysis patterns across 17 categories (prompt injection, data exfiltration, privilege escalation, supply chain, MCP least-privilege and tool-poisoning checks, and more), with an optional LLM semantic pass layered on top, live dependency-CVE lookups against OSV.dev, and terminal/JSON/Markdown/SARIF output with a 0-100 risk score, built for exactly the "gate installs in CI" use case this repo's own architecture notes call out as the right place to run this kind of check. It's also the primary research source behind this skill's own checklist (tagged **NV** in `bootleg-cartridge-rule-catalog.md`). If you only have budget for one scanner, it deserves serious consideration over what's in this repo.

## Overview

A real game cartridge is a sealed, known-good artifact. A bootleg one can look identical while carrying something you didn't ask for. A Claude Code skill has the same problem: it's prose and scripts that an agent follows with real Bash/file/credential access, and a malicious or compromised one can carry exactly the attacks this skill's rule catalog documents.

This skill is the inspection you run before trusting a cartridge from outside your own arcade. It is deliberately **static-only**: a stdlib Python rule engine does all the reading, decoding, and pattern matching, and the calling skill reports on the engine's already-extracted findings rather than freely reading the target's own adversarial text to form a judgment. That tradeoff is explained in `SKILL.md` and in the rule catalog's "Known limitations" section: this is best-effort detection at scan time, not a certification.

Run it, get back:

- A Critical/High/Medium/Low findings table, each row citing a rule ID, confidence, source citation, and `file:line`
- An explicit coverage-gap list: binaries, password-protected archives, oversized files, symlinks, anything that couldn't be safely read as text
- Every URL referenced in the target, extracted only, never fetched
- One verdict: BLOCK, REVIEW, or ALLOW
- A fixed disclaimer every report carries, so a clean result is never mistaken for a safety guarantee

## How it flows

```
    ┌──────────────────────────────────────────┐
    │ "Scan this skill before I install it"    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 0. Prerequisite check                     │
    │ python3 on PATH? target looks like a      │
    │ skill? confirm read-only with the user    │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 1. Quarantine                             │
    │ target path stays read-only for the       │
    │ whole run, never a working directory      │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 2. Run bootleg_cartridge_scan.py          │
    │ read-only, no network, never executes     │
    │ anything in the target -> one JSON blob   │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 3. Build the report from that JSON       │
    │ never by re-reading the target's raw      │
    │ files to form a judgment                  │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 4-5. Coverage gaps + URLs found           │
    │ binaries/archives/symlinks called out,    │
    │ URLs listed, never fetched                │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 6. Verdict: BLOCK / REVIEW / ALLOW        │
    │ + fixed disclaimer, every run             │
    └──────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │ 7. Offer to save                          │
    └──────────────────────────────────────────┘
```

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Python 3 on `$PATH` (the scanner script is stdlib-only, no extra packages, so it can run against untrusted content with no install step)
- A path to the skill/plugin directory you want scanned. It does not need to be installed, loaded, or even on this machine's Claude Code search path, this skill only ever reads it.

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
cp -r /tmp/sec-arcade/skills/bootleg-cartridge-check ~/.claude/skills/
mkdir -p ~/.claude/sec-arcade-standalone/scripts ~/.claude/sec-arcade-standalone/references
cp /tmp/sec-arcade/scripts/bootleg_cartridge_scan.py ~/.claude/sec-arcade-standalone/scripts/
cp /tmp/sec-arcade/references/bootleg-cartridge-rule-catalog.md /tmp/sec-arcade/references/save-states.md \
  ~/.claude/sec-arcade-standalone/references/

# project-level, this repo only
mkdir -p .claude/skills
cp -r /tmp/sec-arcade/skills/bootleg-cartridge-check .claude/skills/
```

`SKILL.md` references its script and reference docs via `${CLAUDE_PLUGIN_ROOT}/scripts/...` and `${CLAUDE_PLUGIN_ROOT}/references/...`, an environment variable Claude Code only sets automatically for a full plugin install. For this standalone copy to work, set it yourself before launching Claude Code, e.g. add `export CLAUDE_PLUGIN_ROOT=~/.claude/sec-arcade-standalone` to your shell profile. Installing the whole arcade (Option 1) handles this automatically.

## Usage

```
Scan this skill for security issues before I install it: /path/to/some-skill
```

```
Is this plugin safe? Check it with bootleg-cartridge-check.
```

The skill runs `scripts/bootleg_cartridge_scan.py` against the path, reads the resulting JSON, and writes a structured markdown report with a BLOCK/REVIEW/ALLOW verdict.

### Example run (excerpt)

```
# Bootleg Cartridge Check: suspicious-skill/

## Verdict: BLOCK

A Critical finding: ANTHROPIC_BASE_URL in settings.json points at a
non-Anthropic host, a credential-exfiltration pattern.

## Findings

### Critical
| Rule | File:Line | Confidence | Source | Description |
|---|---|---|---|---|
| BC-C01 | settings.json | High | Cisco | ANTHROPIC_BASE_URL points at a
non-Anthropic host (CVE-2026-21852 family). |
| BC-C03 | docs/vid.mp4 | High | Cisco | Symlink named `vid.mp4`
secretly targets `.mcp.json` (SymJack). |

## Coverage Gaps
| File | Reason |
|---|---|
| docs/archive.7z | archive format not supported for inspection in
this version |
```

## Limitations

- **Static only.** No semantic/LLM review step in this version, by design: this repo has no sandboxed execution path, and running an LLM judge in the same session that holds Bash/file/credential access is the exact placement the underlying research flags as weakest. See `references/bootleg-cartridge-rule-catalog.md`'s "Deferred" section for what that tradeoff costs in recall.
- A reworded attack that avoids every documented phrasing will not be caught. This is a known-pattern scanner, not a general-purpose intent classifier.
- The known-malicious domain/IP list is a small seed list, not a maintained threat-intel feed.
- A clean result ("ALLOW") means no known indicator was found in this pass. It is not a safety guarantee, and it does not survive the target's own contents changing later. Re-scan on every content change.

## Next cabinet

[`cartridge-peek`](../cartridge-peek) is the no-script sibling: the same checklist, read directly instead of regexed, no Python dependency at all, for when a quick read-through is enough or Python isn't available. It can also catch categories this skill's static rules have to defer entirely.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
