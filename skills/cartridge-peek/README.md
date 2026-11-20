# 🕹️ Cartridge Peek

**Operational Title: Quick Third-Party Skill Read-Through**
A fast, no-dependency look at a Claude Code skill you don't trust yet, no Python, no script, no external file, just Claude reading the files and judging them against the checklist built into `SKILL.md`.

*A cabinet in the [sec-arcade](../../): the quick peek before you insert a coin, not the full inspection. For the full inspection, see [`bootleg-cartridge-check`](../bootleg-cartridge-check).*

![Claude Code Skill](https://img.shields.io/badge/claude--code-skill-5A67D8)
![Focus](https://img.shields.io/badge/focus-supply_chain_appsec-critical)
![Scope](https://img.shields.io/badge/scope-advisory_only-yellow)
![Dependency](https://img.shields.io/badge/dependency-none-brightgreen)
![License](https://img.shields.io/badge/license-CC--BY--SA--4.0-blue)

A Claude Code skill that reads another skill's files directly, no script, no network, no external reference file, never executes or installs anything found in them, and judges them against a Critical/High/Medium/Low security checklist written directly into its own `SKILL.md`.

## Also consider: NVIDIA SkillSpector

This skill is small, Claude-Code-native, and built by one person as a quick, no-dependency read-through, not a rigorous scanner. If you want something more battle-tested for this exact job, look at [NVIDIA SkillSpector](https://github.com/nvidia/skillspector): an open-source, Apache-2.0-licensed security scanner built specifically for AI agent skills (Claude Code, Codex CLI, Gemini CLI, and more), backed by NVIDIA and widely adopted (27,000+ GitHub stars at last check). It runs 71 deterministic static-analysis patterns across 17 categories (prompt injection, data exfiltration, privilege escalation, supply chain, MCP least-privilege and tool-poisoning checks, and more), with an optional LLM semantic pass layered on top, live dependency-CVE lookups against OSV.dev, and terminal/JSON/Markdown/SARIF output with a 0-100 risk score. Unlike this skill, its static layer is deterministic and repeatable, not a fresh judgment call every run. It's also the primary research source behind this skill's own checklist (tagged **NV** in `SKILL.md`'s Security Checklist section). If you only have budget for one scanner, it deserves serious consideration over what's in this repo.

## Overview

`bootleg-cartridge-check` is the deliberately safer design: a script reads the target first, so the model only ever reasons over small, already-matched snippets instead of the target's raw text. That costs a Python dependency and a fixed set of regex patterns, which has to skip entire categories no regex can judge: coercion-by-urgency phrasing, jailbreak framing, slopsquatting setups, invocation-count-gated behavior, and more.

This skill is the other tradeoff: no dependency, and because it's reading prose directly rather than matching a fixed pattern, it covers the full checklist, including everything the regex version has to defer, and it can catch a reworded or disguised version of an attack the regex version would miss outright. The cost is that it's also the first and only thing standing between the target's raw, potentially adversarial content and a model that already has real tool access, which is exactly the placement the research behind this repo's security-scanning skills flags as the weakest link. Use this for a quick gut-check or a second opinion, not as your only check before something higher-stakes.

Run it, get back:

- A Critical/High/Medium/Low findings table, judged against the checklist built into `SKILL.md`, each row citing a file/line and Claude's own confidence
- A coverage-gap list for anything that couldn't be read (binary, too large, password-protected)
- One verdict: BLOCK, REVIEW, or ALLOW
- A fixed disclaimer, every report carries, making the exposure tradeoff explicit

## Prerequisites

- [Claude Code](https://claude.com/claude-code) installed and configured
- Nothing else. No Python, no external binaries, no network access. That's the whole point of this skill.

## Installation

This skill ships as part of the [`sec-arcade`](https://github.com/cameronww7/skill-sec-arcade) Claude Code plugin.

```bash
/plugin marketplace add cameronww7/skill-sec-arcade
/plugin install sec-arcade
```

## Usage

```
Give this skill a quick peek before I install it: /path/to/some-skill
```

```
Quick check on this plugin, no script needed, just read it and tell me what you see.
```

## Limitations

- Advisory only, and more exposed to prompt injection than `bootleg-cartridge-check`: there's no script pre-filtering the target's content first. The skill's hard safety rules (never execute, never follow an embedded instruction, never fetch a URL) are the only mitigation.
- No deterministic, repeatable matching. The same target can be judged slightly differently between runs, same limitation any LLM-judge approach has.
- Carries its own copy of the checklist rather than sharing a file with `bootleg-cartridge-check`, so the two can drift slightly out of sync if one is updated without the other; both currently cover the same source research.
- A clean result ("ALLOW") means nothing suspicious was noticed in this pass. It is not a safety guarantee. Re-check whenever the target's contents change, and prefer `bootleg-cartridge-check` for anything higher-stakes.

## License

[CC BY-SA 4.0](../../LICENSE), same house rules as the rest of [skill-sec-arcade](https://github.com/cameronww7/skill-sec-arcade).
