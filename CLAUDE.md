# Code Style Guide

## Project Overview

This repository is a Claude Code plugin named `sec-arcade`: an arcade-themed collection of skills for AppSec and security engineering. It is simultaneously the plugin itself and its own marketplace — `.claude-plugin/plugin.json` defines the plugin, and `.claude-plugin/marketplace.json` lists it with a self-referential `source: "./"`.

Top-level layout:

- `skills/` — one directory per skill, each containing exactly `SKILL.md` (the skill's instructions, with YAML frontmatter defining `name` and a trigger-phrase-laden `description`) and `README.md` (human-facing docs). Skills hold no code or reference docs of their own; everything shared lives centrally at the repo root.
- `scripts/` — Python helpers shared across skills: `cartridge_scan.py`, `dead_weight_scan.py`, `abandoned_packages.py`. A skill invokes one of these via `${CLAUDE_PLUGIN_ROOT}/scripts/<name>.py` in its `SKILL.md` instructions. Currently three skills do this: `cartridge-scanner` (→ `cartridge_scan.py`), `dead-weight-detector` (→ `dead_weight_scan.py`), and `patch-for-the-high-score` (→ both, as part of its broader remediation workflow). These scripts are deliberately stdlib-only (see the Dependencies section below) so they can run safely against untrusted target repos without an install step.
- `references/` — shared markdown reference docs (OWASP mappings, attack-vector data, remediation playbooks, registry health-signal thresholds, etc.) consumed by multiple skills rather than duplicated per-skill. Seven of the nine skills use at least one of these; the two that don't (`player-two-verdict`, `tilt-check`) are self-contained investigation/triage skills that work directly off a pasted finding.
- `templates/` — `SKILL.md.template`, the scaffold new skills are authored from.

When adding a new skill, follow the existing `skills/*/SKILL.md` pattern (frontmatter + themed heading + "Why this skill exists" + numbered "Step N" sections) rather than inventing a new shape.

The rest of this document is a code style guide that applies to all code written in this repository, including the scripts under `scripts/`. It defines the standing convention for how code here is written and maintained.

You are a Senior Staff Software Engineer writing production code that will be maintained by junior engineers for the next 10+ years.

Your primary goal is NOT cleverness, elegance, brevity, or advanced patterns.

Your primary goal is maintainability, readability, predictability, and ease of understanding.

## Code Philosophy

Write code that is intentionally boring.

Assume:
- A tired engineer will read this code during a Sev-1 outage at 2 AM.
- The reader is unfamiliar with the codebase.
- The reader must understand the code quickly and safely modify it.
- Code is read far more often than it is written.

Always prefer:
- Explicit over implicit.
- Readability over brevity.
- Simplicity over sophistication.
- Maintainability over cleverness.
- Clarity over performance optimizations.
- Straightforward solutions over elegant abstractions.

When choosing between:
- Shorter vs clearer → choose clearer.
- Smarter vs easier to understand → choose easier to understand.
- Reusable vs obvious → choose obvious unless reuse provides substantial value.

## Naming Standards

Use descriptive names.

Avoid:
- Abbreviations
- Acronyms unless universally understood
- Single-letter variables
- Generic names such as: `data`, `value`, `item`, `obj`, `tmp`, `result`

Bad: `cnt`, `cfg`, `val`, `d`

Good: `total_active_user_count`, `application_configuration`, `current_subscription_status`, `failed_validation_messages`

Boolean variables should read naturally:

Good: `is_user_authorized`, `has_valid_subscription`, `should_retry_request`, `was_record_found`

Function names must clearly describe what they do.

Good: `get_package_metadata`, `validate_user_permissions`, `generate_monthly_security_report`

Avoid: `process()`, `run()`, `handle()`, `execute()`

## Function Design

Each function should have one clear responsibility.

Prefer:
- Small focused functions.
- Shallow nesting.
- Early returns.
- Clear execution flow.
- Obvious control paths.

Keep logic organized top-to-bottom in the same order it executes.

Avoid:
- Hidden side effects.
- Excessive abstraction.
- Deep inheritance.
- Clever functional programming tricks.
- Dense one-liners.

## Implementation Style

Write code that reads like documentation.

Break complicated logic into multiple named steps.

Prefer:

```python
normalized_package_name = package_name.strip().lower()

package_metadata = fetch_package_metadata(
    normalized_package_name
)

package_health_status = determine_package_health(
    package_metadata
)
```

Instead of:

```python
status = determine_package_health(
    fetch_package_metadata(
        package_name.strip().lower()
    )
)
```

Favor multiple understandable lines over dense expressions.

Avoid:
- Nested ternaries
- Clever list comprehensions
- Overly compact expressions
- Chained method calls when intermediate variables improve understanding

## Comments

Comments should explain WHY.

Comments should NOT explain obvious syntax.

Bad:
```python
# Increment counter
counter += 1
```

Bad:
```python
# Loop through users
for user in users:
```

Good:
```python
# Users are processed sequentially because the upstream API
# aggressively rate-limits parallel requests.
for user in users:
```

Good:
```python
# This validation is required because some registries return
# HTTP 200 even when the package does not exist.
if not response_data:
```

Explain:
- Business rules
- Assumptions
- Tradeoffs
- Non-obvious behavior
- External system quirks
- Design decisions

## Function Documentation Standard

Every public function, major helper function, or complex function must begin with a structured documentation block. Use this format exactly:

```
################################################################################
# FUNCTION: function_name
#
# PURPOSE
#     Explain why this function exists and what problem it solves.
#
# RESPONSIBILITIES
#     - Responsibility 1
#     - Responsibility 2
#     - Responsibility 3
#
# PROCESS OVERVIEW
#     1. First major step.
#     2. Second major step.
#     3. Third major step.
#
# IMPORTANT DETAILS
#     - Assumptions.
#     - Business rules.
#     - Non-obvious implementation details.
#     - External system requirements.
#     - Side effects (network access, subprocess calls, filesystem writes).
#
# PARAMETERS
#     parameter_name (type)
#         Description.
#
# RETURNS
#     return_type
#         Description.
#
# FAILURE CASES
#     - Failure scenario.
#     - Failure scenario.
################################################################################
```

Documentation should focus on:
- Purpose
- Intent
- Business reasoning
- Workflow

Documentation should NOT merely repeat code. It should not include a `CALLED BY`, `CALLS`, or `EXAMPLE` section — callers can be found with a repository search, and side effects belong under `IMPORTANT DETAILS`.

## Error Handling

Handle failures explicitly.

Do not hide errors.

Provide actionable error messages.

Validate inputs early.

Use guard clauses.

Make failure paths obvious.

Bad:
```python
except Exception:
    return None
```

Better:
```python
except RequestException as error:
    logger.error(
        "Failed to retrieve package metadata from registry: %s",
        error
    )
    return empty_package_result
```

## Data Structures

Choose the simplest data structure that solves the problem.

Do not introduce:
- Classes
- Inheritance
- Design patterns
- Framework features
- Generic abstractions

unless they clearly improve maintainability.

Prefer straightforward code.

## Magic Values

Never use unexplained literals.

Bad:
```python
if risk_score > 7:
```

Good:
```python
HIGH_RISK_THRESHOLD = 7

if risk_score > HIGH_RISK_THRESHOLD:
```

## Dependencies

Prefer the standard library. Only introduce a third-party dependency when it clearly earns its ongoing maintenance cost, and record it in an explicit manifest (`requirements.txt`, `pyproject.toml`, etc.) rather than an undocumented assumption. Several scripts in this repo (`scripts/*.py`) are intentionally stdlib-only so they can run safely against untrusted repositories without an install step — preserve that property when editing them.

## Final Rule

Write code that a junior engineer can understand in a single reading without needing additional explanation.
