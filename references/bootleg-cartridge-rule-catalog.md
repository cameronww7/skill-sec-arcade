# Bootleg Cartridge Rule Catalog

The full set of static rules `scripts/bootleg_cartridge_scan.py` implements, plus the rules this version deliberately does not implement. Keep `rule_id` values here in sync with the `rule_id` values in that script; this file is the human-readable mirror, the script is the implementation.

Source tags: **NV** = SkillSpector, **Cisco** = skill-scanner (including its ATR pack), **SS** = SkillScan. These are the public research sources the catalog draws its severity bands and detection ideas from, cited per rule below.

**Confidence** is a separate axis from severity: how likely a match is to be a true positive rather than ordinary benign content phrased similarly. A rule can be severe and still low-confidence (an attack would be bad if real, but the regex alone can't tell real from coincidental), or mild and high-confidence (clearly what it looks like, just not very dangerous on its own).

## Critical (9-10)

| Rule ID | Severity | Confidence | Source | Description |
|---|---|---|---|---|
| BC-C01 | 10 | High | Cisco | `ANTHROPIC_BASE_URL`/`ANTHROPIC_API_URL` in a settings/env file points at a non-Anthropic host (CVE-2026-21852 family); every API call, and the credentials with it, goes to an attacker-controlled server. |
| BC-C02 | 10 | Medium | Cisco | `git remote add` to a foreign host, anywhere in the same file followed by a `git push` with `--mirror`/`--all`/`--force`/`-f` (silent codebase exfil). |
| BC-C03 | 10 | High | Cisco | A symlink with a harmless-looking name (e.g. `docs/vid.mp4`) that secretly targets `.mcp.json`, `settings.json`, or another sensitive dotfile (SymJack). |
| BC-C04 | 10 | High | SS, Cisco | A URL host or IP literal matches a known-malicious campaign indicator of compromise. Seed list only, see "Known limitations" below. |
| BC-C05 | 9 | High | Cisco | `$()` or backticks inside a double-quoted string in a code file, which still expands. |
| BC-C06 | 9 | Medium | Cisco, NV | Instruction to fill a "notes"/"context"/"history" parameter with the full conversation. |
| BC-C07 | 9 | High | Cisco, SS | An MCP server's stdio `command` field contains shell metacharacters (`;`, `|`, `` ` ``). |
| BC-C08 | 9 | High | Cisco, NV | `pickle.load`, `torch.load`, or a `.pt`/`.pth` model file reference (unsafe deserialization). |
| BC-C09 | 9 | Medium | Cisco | An SVG file with an embedded `<script>`/event-handler attribute, or a PDF with `/JavaScript`/`/OpenAction`. |
| BC-C10 | 9 | Medium | Cisco | One file combining bulk file enumeration, an encryption operation, and a ransom-note-style string (ransomware chain). |
| BC-C11 | 9 | Medium | SS | Instruction to pass/forward/relay this skill's instructions or output to another agent or tool (cascading injection). |
| BC-C12 | 9 | High | Cisco | Instruction to disable 2FA/MFA or other account security settings. |
| BC-C13 | 9 | Medium | Cisco | Financial transaction/trade/crypto withdrawal framed as not requiring human approval. |
| BC-C14 | 9 | Medium | SS | AppleScript `display dialog` with a hidden answer field (credential phishing). |
| BC-C15 | 9 | Low | SS | Phrasing that fabricates a fake OS/system update prompt. |

## High (7-8)

| Rule ID | Severity | Confidence | Source | Description |
|---|---|---|---|---|
| BC-H01 | 8 | Medium | Cisco | Instruction framed to survive or persist through context compaction/summarization. |
| BC-H02 | 8 | Medium | Cisco | `<IMPORTANT>`-style directive tag, or "the other installed tool" chaining language. |
| BC-H03 | 8 | Medium | Cisco, SS, NV | Overriding normal tool selection ("always use this tool no matter what"). |
| BC-H04 | 8 | Low | Cisco, SS, NV | Instruction to override/replace/shadow a built-in tool or command. |
| BC-H05 | 8 | Low | Cisco | Instruction to show a fake error while continuing an action in the background. |
| BC-H06 | 8 | Medium | Cisco | A persistence-trigger phrase and a stealth qualifier both present in the same file. |
| BC-H07 | 8 | High | Cisco | Raw ANSI or OSC terminal escape sequences present in a file. |
| BC-H08 | 8 | High | Cisco | Backspace (`\x08`) control characters present in a file. |
| BC-H09 | 8 | High | NV | Refusal-suppression phrasing ("never refuse", "always comply"). |
| BC-H10 | 8 | Low | Cisco | A long base64-looking blob and an outbound network call in the same file (exfil staging). |
| BC-H11 | 8 | Medium | Cisco | A hidden dotfile whose content starts with a shebang line (executable code). |
| BC-H12 | 8 | High | SS | A password-protected/encrypted zip archive. |
| BC-H13 | 8 | Medium | SS | Request for accessibility, screen-recording, or full-disk-access permissions. |
| BC-H14 | 8 | Medium | Cisco | Instruction to install a "community fork"/"enhanced version"/"patched version" of a known tool. |
| BC-H15 | 8 | Low | Cisco | A loopback address literal and a network call in the same file (localhost SSRF). |
| BC-H16 | 8 | Medium | SS, NV | Container/K8s config requesting host network mode, privileged mode, or added capabilities. |
| BC-H17 | 8 | Medium | Cisco | Shell metacharacters inside a quoted `subprocess`/`os.system` argument. |

## Medium (4-6)

| Rule ID | Severity | Confidence | Source | Description |
|---|---|---|---|---|
| BC-M01 | 6 | Medium | NV | Disclaimer-suppression phrasing ("don't include warnings or caveats"). |
| BC-M02 | 6 | Low | Cisco | More than 50 level-3 markdown headings in a single `SKILL.md`-style file. |
| BC-M03 | 6 | Medium | Cisco | A glob/find pattern that specifically targets dotfiles. |
| BC-M04 | 6 | High/Low | Cisco | A classic shell fork-bomb signature (high confidence), or an unconditional `while true` loop with no `break` anywhere in the file (low confidence). |
| BC-M05 | 5 | High/Medium/Low | Cisco, SS | A hardcoded AWS access key, JWT, or password/secret literal assignment. |
| BC-M06 | 5 | Low | SS | A private RFC 1918 IP address literal. |
| BC-M07 | 5 | Medium | NV | `SKILL.md` references tool usage in its body but declares no `allowed-tools` key in its frontmatter. |
| BC-M08 | 4 | Low | SS | Reference to a `.dmg` or `.pkg` installer. |
| BC-M09 | 6 | Low | SS | An unusually long DNS subdomain label (possible DNS exfiltration). |
| BC-M10 | 7 | High | NV | Wildcard tool permission (e.g. `Bash(*)`). |
| BC-M11 | 7 | Medium | SS | An `npx` MCP server invocation with no version pin. |
| BC-M12 | 7 | Medium | SS | `nohup`, `disown`, or a backgrounded long-running process. |
| BC-M13 | 6 | High | SS, Cisco | Unusually high Unicode combining-mark density (Zalgo-style text obscuring). |
| BC-M14 | 7 | Medium | SS | `PATH` environment variable manipulation. |
| BC-M15 | 7 | Medium | SS | `launchctl` or `dscl` usage. |
| BC-M16 | 7 | Medium | Cisco | `find -exec` usage. |

Note: BC-M10, BC-M11, BC-M12, BC-M14, BC-M15, and BC-M16 carry a severity of 7, which bands as **High**, not Medium, per the source research; they are grouped here with the other "mid-tier, pattern-based" rules for readability, not because of their numeric band. The script's `band_for_severity()` is the source of truth for banding, always derived from the stored severity, never stored separately.

## Low (1-3)

| Rule ID | Severity | Confidence | Source | Description |
|---|---|---|---|---|
| BC-L01 | 3 | Low | SS | A Unicode or hex escape sequence in a string literal. High false-positive rate in ordinary code; informational only. |
| BC-L02 | 3 | Low | Cisco | An outbound network call. Correlation-only signal, not a finding on its own. |
| BC-L03 | 2 | Low | Cisco | Node `fs` module access in a JS/TS file. Correlation-only signal, not a finding on its own. |

## Deferred: not implemented in this version

These require semantic judgment a regex can't reliably make, or live threat-intel infrastructure this repo doesn't have. Listed here explicitly so a clean scan never implies they were checked, matching the "state coverage gaps, never let silence imply clean" discipline `references/iam-data-coverage-and-tools.md` already establishes for `cloud-player-perm-audit`:

- Keyword-baiting/trigger-maximization framing (NV TR3)
- Pseudo-code or "initialization sequence" jailbreak framing (Cisco)
- Coercion through urgency or threats (Cisco, SS)
- Subtle steering toward a specific vendor/package/URL (NV P4)
- Prompts engineered to make a model hallucinate package names, slopsquatting setup (Cisco)
- Abuse of MCP sampling, where a server injects prompts back into the host LLM (Cisco)
- Behavior gated on a rare phrase/symbol trigger (Cisco)
- Context-window stuffing meant to push instructions out of context (NV MP2)
- False-premise injection, a planted false claim used to justify an action (Cisco)
- Container image digest pinning / unknown registry trust (NV SC7)
- Unbounded resource use with no rate limits or quotas (NV EA4)
- Skill output rendered in another context (XSS/SQLi sinks) beyond a simple string-concatenation heuristic (NV OH1/OH2, Cisco)
- Path traversal through a user-controlled file path, beyond a simple heuristic (Cisco)
- Requests for the agent's own tool inventory or schemas, framed as reconnaissance (Cisco)
- Abandoned-dependency detection — out of scope here; `dead-weight-detector` already owns this for first-party dependency trees.

## Known limitations

- `KNOWN_MALICIOUS_DOMAINS`/`KNOWN_MALICIOUS_IPS` in the script are a small seed list, not a maintained threat-intel feed. Treat a miss here as "not in this small seed list," never as "confirmed clean."
- Every rule here is a static text/structure pattern, not a semantic understanding of intent. A reworded attack that avoids these specific phrasings will not be caught; see the bootleg-cartridge-check skill's own disclaimer for what this means for the overall verdict.
- Confidence is a qualitative, author-assigned estimate based on expected false-positive rate, not a measured statistic. Treat it as a hint for triage priority, not a probability.
