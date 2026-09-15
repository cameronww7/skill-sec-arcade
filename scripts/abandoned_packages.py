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

# ------------------------------------------------------------------------
# lookup
#
# WHAT IT DOES:   Checks whether a given package name, in a given
#                 ecosystem, is listed in the curated ABANDONED table
#                 above, and if so returns why it's abandoned and what to
#                 use instead.
# WHY IT EXISTS:  dead_weight_scan.py's live registry/OSV checks can miss
#                 packages that still look healthy by those numbers alone.
#                 This gives the scanner one more, human-curated signal to
#                 fall back on.
#
# INPUTS:
#   ecosystem (str) - lowercase ecosystem key, e.g. "python", "go". If it
#                      isn't a key in ABANDONED, the function returns None
#                      immediately rather than raising KeyError.
#   name (str) - the package name as declared in the project's manifest.
#                Matched exactly first, then against name.lower(), so
#                callers don't need to normalize case themselves.
#
# RETURNS:
#   (dict or None) - {"reason": str, "replacement": str} if name is
#   listed under ecosystem; None if the ecosystem is unknown or the
#   package isn't in the list. None means "not flagged," not "confirmed
#   healthy," most packages simply aren't in this hand-curated table.
#
# RAISES/ERRORS:  None. Every miss (unknown ecosystem, unlisted package)
#                 is reported via a None return, never an exception.
# SIDE EFFECTS:   None.
# CALLED BY:      run_health() in dead_weight_scan.py.
# CALLS:          dict.get() only.
#
# EXAMPLE:
#   lookup("python", "PyCrypto")
#   -> {"reason": "Unmaintained since 2013; has known unpatched
#       vulnerabilities.", "replacement": "pycryptodome (drop-in
#       API-compatible fork)"}
#--------------------------------------------------------------------------
def lookup(ecosystem, name):
    """Returns the abandonment entry ({"reason", "replacement"}) for name
    in ecosystem, checking both the name as given and its lowercased
    form, or None if not listed."""
    ecosystem_entries = ABANDONED.get(ecosystem)
    if not ecosystem_entries:
        return None
    return ecosystem_entries.get(name) or ecosystem_entries.get(name.lower())
