# ******************************************************************************
# * TITLE:        Abandoned Package Registry
# * FILE:         abandoned_packages.py
# * PART OF:      dead-weight-detector skill (skill-sec-arcade repo).
# *               Imported by dead_weight_scan.py; not run on its own.
# * PURPOSE:      Hand-maintained lookup table of packages that are known,
# *               by public/community consensus, to be abandoned or
# *               deprecated. It exists because dead_weight_scan.py's
# *               automated health checks (release recency, maintainer
# *               count, download volume, OSV.dev vulnerability data) can
# *               all look "healthy" for a package that is nonetheless a
# *               well-known dead end (steady legacy downloads, no public
# *               CVE, but the maintainers walked away years ago). This
# *               file is the manually-curated safety net for exactly
# *               those cases.
# *
# * HOW IT WORKS: 1) ABANDONED is a nested dict: ecosystem name (e.g.
# *                  "python") -> package name -> {"reason", "replacement"}.
# *               2) The caller (dead_weight_scan.py's run_health()) calls
# *                  lookup(ecosystem, name) for every package it's
# *                  already decided to health-check.
# *               3) lookup() returns the entry dict if found (checking
# *                  the name as given, then lowercased), or None.
# *
# * USAGE:        Not a CLI script. Imported as a module, e.g.:
# *                   import abandoned_packages
# *                   abandoned_packages.lookup("python", "nose")
# * ARGUMENTS:    N/A, no command-line interface.
# * INPUTS:       None beyond the function arguments at call time; all
# *               data lives in the ABANDONED dict below.
# * OUTPUTS:      None (no stdout, no files). Pure return value only.
# * EXIT CODES:   N/A, not a script, has no __main__ entry point.
# * DEPENDENCIES: Python 3 standard library only. No third-party packages.
# * PERMISSIONS:  None. No filesystem or network access of any kind.
# * ASSUMPTIONS:  Caller passes the same lowercase ecosystem key spelling
# *               used elsewhere in this repo (e.g. "python", "javascript",
# *               "go"), matching the keys in ABANDONED below.
# * FAILURE MODES:None. lookup() never raises; an unknown ecosystem or an
# *               unlisted package name both simply return None.
# * SAFE TO RERUN:Yes. Pure, stateless function with no side effects.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-09-15
# ******************************************************************************

"""Curated registry of well-known abandoned/deprecated packages, one small
per-ecosystem dict, hand-maintained and deliberately not exhaustive.

This supplements dead_weight_scan.py's live health signals (recency,
maintainers, downloads, OSV, registry-declared deprecation), it doesn't
replace them: entries here cover cases where a package can still look
healthy by those signals alone (steady downloads from old code, no
widely-known CVE) but is nonetheless a well-known dead end with an
established replacement.

Add an entry when a package meets either condition: no release in
several years with clear community consensus it's abandoned, or a public
maintainer announcement of deprecation/abandonment. Always name a
concrete replacement, "just don't use it" isn't actionable in a report.
"""

# ===== CONFIGURATION =====

# Ecosystem -> package name -> {"reason", "replacement"}. Package names
# are matched case-sensitively first, then lowercased (see lookup()
# below), so entries can be written in whatever casing reads naturally.
ABANDONED = {
    "javascript": {
        "request": {
            "reason": "Deprecated by its maintainers in 2020; unmaintained since.",
            "replacement": "node-fetch, got, or axios",
        },
        "bower": {
            "reason": "Declared end-of-life in 2017 in favor of npm/yarn workflows.",
            "replacement": "npm or yarn (no dedicated frontend package manager needed)",
        },
        "left-pad": {
            "reason": "Single-purpose micro-package; functionality is a one-line call.",
            "replacement": "String.prototype.padStart (built into modern JS)",
        },
    },
    "python": {
        "pycrypto": {
            "reason": "Unmaintained since 2013; has known unpatched vulnerabilities.",
            "replacement": "pycryptodome (drop-in API-compatible fork)",
        },
        "distribute": {
            "reason": "Merged back into setuptools in 2013.",
            "replacement": "setuptools",
        },
        "nose": {
            "reason": "Maintainers declared it dead in 2015; no Python 3.10+ support.",
            "replacement": "pytest",
        },
    },
    "go": {
        "github.com/dgrijalva/jwt-go": {
            "reason": "Unmaintained; carries CVE-2020-26160 with no fix in the original module.",
            "replacement": "github.com/golang-jwt/jwt/v5",
        },
    },
    "ruby": {
        "paperclip": {
            "reason": "Unmaintained since 2018; the Rails team recommends its built-in alternative.",
            "replacement": "ActiveStorage (built into Rails 5.2+)",
        },
        "capybara-webkit": {
            "reason": "Abandoned; the underlying QtWebKit driver is unmaintained.",
            "replacement": "selenium-webdriver, or capybara's built-in rack_test/cuprite drivers",
        },
    },
    "php": {},
    "rust": {},
    "java": {},
    "dotnet": {},
    "dart": {},
    "cpp": {},
}


# ===== MAIN =====

################################################################################
# FUNCTION: lookup
#
# PURPOSE
#     Checks whether a given package, in a given ecosystem, is a known
#     abandoned/deprecated package per the hand-curated ABANDONED table
#     above. dead_weight_scan.py's live registry and OSV checks can miss
#     packages that still look healthy by those signals alone; this gives
#     the scanner one more, human-curated signal to fall back on.
#
# RESPONSIBILITIES
#     - Look up the ecosystem's package table in ABANDONED.
#     - Match the package name against that table, exact case first and
#       then lowercased, so callers don't need to normalize case
#       themselves.
#     - Return the matching entry, or None if there is no match.
#
# PROCESS OVERVIEW
#     1. Look up the ecosystem's package table in ABANDONED.
#     2. If the ecosystem has no table, return None immediately.
#     3. Look for an exact-case match of the package name in that table.
#     4. If no exact match, look for a lowercased match instead.
#     5. Return whichever entry was found, or None if neither matched.
#
# IMPORTANT DETAILS
#     - A None return means "not flagged in this table," not "confirmed
#       healthy." Most real packages simply aren't in this hand-curated
#       table and are expected to return None.
#     - No filesystem or network access of any kind; this is a pure,
#       stateless lookup with no side effects.
#
# PARAMETERS
#     ecosystem (str)
#         Lowercase ecosystem key, e.g. "python" or "go", matching a key
#         in ABANDONED. An ecosystem not present in ABANDONED is not an
#         error; it simply produces a None return.
#     name (str)
#         The package name as declared in the project's manifest.
#
# RETURNS
#     dict or None
#         {"reason": str, "replacement": str} if the package is listed
#         under the given ecosystem; None otherwise.
#
# FAILURE CASES
#     - Unknown ecosystem: returns None.
#     - Package not listed under a known ecosystem: returns None.
################################################################################
def lookup(ecosystem, name):
    """Returns the abandonment entry ({"reason", "replacement"}) for name
    in ecosystem, checking both the name as given and its lowercased
    form, or None if not listed."""
    ecosystem_entries = ABANDONED.get(ecosystem)
    if not ecosystem_entries:
        return None

    exact_case_match = ecosystem_entries.get(name)
    if exact_case_match:
        return exact_case_match

    return ecosystem_entries.get(name.lower())
