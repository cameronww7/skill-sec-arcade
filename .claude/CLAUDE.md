# Repo Rules

- All `SKILL.md` references to shared resources must use `${CLAUDE_PLUGIN_ROOT}/...`, bare form only, not a relative path.
- New skills start from `templates/SKILL.md.template`.
- Check `ARCHITECTURE.md`'s skill-to-resource map before editing anything under `scripts/` or `references/`; other skills may depend on the file you're changing.
- `README.md` files under `skills/*/` are human-facing only, Claude never reads them. Anything Claude needs to follow belongs in that skill's `SKILL.md`.
- See `ARCHITECTURE.md` for the full repo layout, the skill-to-resource map, and why this repo's distribution model is plugin-install-only.

# Code Style Guide

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
