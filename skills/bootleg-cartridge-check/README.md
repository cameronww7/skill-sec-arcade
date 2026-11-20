# 🕹️ Bootleg Cartridge Check

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

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Python 3 on `$PATH` (the scanner script is stdlib-only, no extra packages, so it can run against untrusted content with no install step)
- A path to the skill/plugin directory you want scanned. It does not need to be installed, loaded, or even on this machine's Claude Code search path, this skill only ever reads it.

## Installation

This skill ships as part of the [`sec-arcade`](https://github.com/cameronww7/skill-sec-arcade) Claude Code plugin.

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

## Usage

```
Scan this skill for security issues before I install it: /path/to/some-skill
```

```
Is this plugin safe? Check it with bootleg-cartridge-check.
```

The skill runs `scripts/bootleg_cartridge_scan.py` against the path, reads the resulting JSON, and writes a structured markdown report with a BLOCK/REVIEW/ALLOW verdict.

## Limitations

- **Static only.** No semantic/LLM review step in this version, by design: this repo has no sandboxed execution path, and running an LLM judge in the same session that holds Bash/file/credential access is the exact placement the underlying research flags as weakest. See `references/bootleg-cartridge-rule-catalog.md`'s "Deferred" section for what that tradeoff costs in recall.
- A reworded attack that avoids every documented phrasing will not be caught. This is a known-pattern scanner, not a general-purpose intent classifier.
- The known-malicious domain/IP list is a small seed list, not a maintained threat-intel feed.
- A clean result ("ALLOW") means no known indicator was found in this pass. It is not a safety guarantee, and it does not survive the target's own contents changing later. Re-scan on every content change.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
