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

ABANDONED = {
    "npm": {
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
}


def lookup(ecosystem, name):
    """Returns the abandonment entry ({"reason", "replacement"}) for name
    in ecosystem, checking both the name as given and its lowercased
    form, or None if not listed."""
    ecosystem_entries = ABANDONED.get(ecosystem)
    if not ecosystem_entries:
        return None
    return ecosystem_entries.get(name) or ecosystem_entries.get(name.lower())
