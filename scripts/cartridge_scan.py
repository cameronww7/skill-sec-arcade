#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Cartridge Scanner
# * FILE:         cartridge_scan.py
# * PART OF:      cartridge-scanner skill (skill-sec-arcade repo). Several
# *               of its helpers (walk, find_files, read_text, read_json,
# *               EXCLUDE_DIRS, install_requires_from_setup_py,
# *               install_requires_from_setup_cfg) are also imported
# *               directly by dead_weight_scan.py, so this file doubles
# *               as a small shared library, not just a standalone script.
# * PURPOSE:      Produces a structured, machine-readable inventory of a
# *               repository: languages and lines of code, every package
# *               manager manifest/lockfile with approximate dependency
# *               counts, any non-default (private/internal) package
# *               registry in use, container files (Dockerfiles/compose),
# *               and Infrastructure-as-Code (IaC, i.e. config that
# *               declares cloud/deployment resources) files. It exists so
# *               the cartridge-scanner skill has hard facts to reason
# *               over instead of re-deriving them from scratch every run.
# *
# * HOW IT WORKS: 1) Counts lines of code per language via the external
# *                  `scc` CLI tool, or a rough manual count if `scc`
# *                  isn't installed.
# *               2) Runs one scan_<ecosystem>() function per package
# *                  manager (JavaScript, Python, Go, Java, Ruby, PHP,
# *                  Rust, .NET, Dart, C/C++), each of which finds that
# *                  ecosystem's manifest/lockfile, counts declared vs.
# *                  resolved dependencies, and flags any registry URL
# *                  that isn't the ecosystem's public default.
# *               3) Finds every Dockerfile (with its FROM base images)
# *                  and docker-compose file.
# *               4) Finds IaC files by filename (Terraform, Helm, Pulumi,
# *                  Serverless, CDK) and, for formats that share plain
# *                  .yml/.yaml/.json extensions with other tools
# *                  (CloudFormation, Kubernetes, Ansible), by sniffing
# *                  file contents for a telltale key.
# *               5) Prints one JSON object with all of the above to
# *                  stdout.
# *
# * USAGE:        python3 cartridge_scan.py [path]
# *               Example: python3 cartridge_scan.py /home/user/my-repo
# * ARGUMENTS:    path (positional, str, optional, default ".") - repo
# *               root to scan.
# * INPUTS:       The filesystem under `path`. Optionally shells out to
# *               the `scc` binary if it's on PATH (see run_scc()).
# * OUTPUTS:      One JSON object printed to stdout. No files are written,
# *               no prose or markdown, the calling skill does all
# *               interpretation of these facts.
# * EXIT CODES:   0 = success. There is no explicit non-zero exit path in
# *               this script; an unhandled exception would still exit
# *               non-zero with a Python traceback on stderr.
# * DEPENDENCIES: Python 3 standard library only (ast, configparser, json,
# *               os, re, subprocess, sys, urllib.parse). The `scc` binary
# *               is optional, used for accurate LOC/language stats when
# *               present; a lower-detail fallback runs without it. The
# *               `syft` binary is optional too, used only for C/C++'s
# *               Conan dependency detection (see run_syft_conan()).
# * PERMISSIONS:  Read-only filesystem access under `path`. No network
# *               access. No write access anywhere.
# * ASSUMPTIONS:  Safe to *read* (never execute) any file under `path`,
# *               including files from an untrusted/third-party repo,
# *               this is why setup.py's install_requires is extracted
# *               with `ast` instead of by actually importing/running it.
# * FAILURE MODES:An unreadable or malformed manifest is silently skipped
# *               (its count stays None) rather than crashing the whole
# *               scan. A missing `scc` binary silently falls back to
# *               fallback_loc_scan(), which has less detail (no
# *               comment/blank/complexity split). A missing `syft` binary
# *               silently falls back to a narrower Conan lockfile parse.
# * SAFE TO RERUN:Yes. Strictly read-only; nothing on disk is created,
# *               modified, or deleted.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-09-15
# ******************************************************************************

"""Cartridge Scanner: repo inventory for cartridge-scanner skill.

Walks a repo, runs `scc` for language/LOC stats (falls back to a rough
manual count if `scc` isn't installed), inventories package manager
manifests/lockfiles with approximate dependency counts, flags any
non-default (private/internal) package registries, and finds
Dockerfiles/compose files and common IaC file types.

Prints one JSON object to stdout. No prose, no markdown: interpretation
is the calling skill's job, not this script's.

`walk`, `find_files`, `read_text`, `read_json`, and `EXCLUDE_DIRS` are
also imported directly by dead_weight_scan.py, keep their names and
signatures stable.
"""

import ast
import configparser
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

# ===== CONFIGURATION =====

# Directories that are never first-party code: dependency caches, build
# output, and VCS metadata. Pruned from every walk below, both for `scc`'s
# fallback LOC count and for manifest/source-file discovery.
EXCLUDE_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env",
    "site-packages", "dist", "build", "target", ".tox",
    ".mypy_cache", "__pycache__", "bower_components", ".terraform",
    ".serverless",
}

# Small, deliberately partial extension map used only when `scc` isn't
# installed. `scc` itself recognizes far more languages; this fallback
# exists to keep the report non-empty, not to replace it.
FALLBACK_EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP",
    ".rs": "Rust", ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++",
    ".hpp": "C++", ".swift": "Swift", ".dart": "Dart",
    ".sh": "Shell", ".yaml": "YAML", ".yml": "YAML", ".tf": "Terraform",
    ".sql": "SQL", ".scala": "Scala", ".m": "Objective-C",
    ".html": "HTML", ".css": "CSS", ".scss": "SCSS",
}

# The public default registry host(s) per ecosystem. Any manifest/config
# pointing somewhere else is flagged as a private/internal registry, see
# add_if_private() below.
DEFAULT_REGISTRY_HOSTS = {
    "javascript": {"registry.npmjs.org"},
    "pip": {"pypi.org", "files.pythonhosted.org"},
    "maven": {"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com"},
    "gem": {"rubygems.org"},
    "composer": {"repo.packagist.org"},
    "cargo": {"crates.io", "static.crates.io"},
    "nuget": {"api.nuget.org", "www.nuget.org"},
}


# ===== HELPERS =====

# ------------------------------------------------------------------------
# read_text
#
# WHAT IT DOES:   Reads a file's full contents as text.
# WHY IT EXISTS:  Every other function in this file needs to read
#                 manifests/lockfiles/source files without crashing the
#                 whole scan over one bad file (missing, permission
#                 denied, binary garbage). Centralizing that tolerance
#                 here means no caller has to wrap every read in its own
#                 try/except.
#
# INPUTS:
#   path (str) - filesystem path to read.
#
# RETURNS:
#   (str) - the file's contents decoded as UTF-8, with undecodable bytes
#   silently dropped (errors="ignore"), so a binary file won't raise a
#   UnicodeDecodeError, it just produces mangled text. "" means either an
#   empty file or a read failure, callers can't tell which from this
#   return value alone.
#
# RAISES/ERRORS:  Never raises; any OSError (missing file, permission
#                 denied, etc.) is caught and turned into "".
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      Nearly every function in this file and in
#                 dead_weight_scan.py.
# CALLS:          open() (builtin).
#
# EXAMPLE:
#   read_text("/repo/package.json") -> '{\n  "name": "app",\n  ...}\n'
#   read_text("/repo/missing.txt")  -> ""
#--------------------------------------------------------------------------
def read_text(path):
    """Reads a file as UTF-8, tolerating decode errors. Returns "" on any
    failure (missing file, permission error, etc.) instead of raising."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


# ------------------------------------------------------------------------
# read_json
#
# WHAT IT DOES:   Reads a file and parses it as JSON.
# WHY IT EXISTS:  Manifest/lockfile parsing throughout this file needs a
#                 "give me the parsed data or nothing" primitive that
#                 never throws, since scanned repos are not trusted to
#                 have well-formed files.
#
# INPUTS:
#   path (str) - filesystem path to a JSON file.
#
# RETURNS:
#   (Any or None) - the parsed JSON value (usually a dict or list) on
#   success. None if the file is missing, unreadable, or not valid JSON.
#   Callers must check for None before indexing into the result.
#
# RAISES/ERRORS:  Never raises; ValueError (bad JSON) and TypeError
#                 (json.loads(None), which can't happen here but is
#                 guarded anyway) are both caught.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      Most scan_* functions when the manifest/lockfile format
#                 is JSON (package.json, composer.json, Pipfile.lock,
#                 etc.).
# CALLS:          read_text(), json.loads().
#
# EXAMPLE:
#   read_json("/repo/package.json") -> {"name": "app", "dependencies": {}}
#   read_json("/repo/not-json.txt") -> None
#--------------------------------------------------------------------------
def read_json(path):
    """Reads and parses a file as JSON. Returns None if it's missing,
    unreadable, or not valid JSON, never raises."""
    try:
        return json.loads(read_text(path))
    except (ValueError, TypeError):
        return None


# ------------------------------------------------------------------------
# walk
#
# WHAT IT DOES:   Walks a directory tree like os.walk(), but skips
#                 dependency/build/VCS directories entirely.
# WHY IT EXISTS:  Without this, every scan would waste time descending
#                 into node_modules, .git, vendor, etc., and could
#                 misreport third-party vendored code as first-party.
#
# INPUTS:
#   root (str) - directory to start walking from.
#
# RETURNS:
#   (generator) - yields (dirpath, dirnames, filenames) tuples, same
#   shape as os.walk(), except dirnames has already had every name in
#   EXCLUDE_DIRS removed before being yielded.
#
# RAISES/ERRORS:  Whatever os.walk() itself can raise (rare; it swallows
#                 most per-directory errors by default).
# SIDE EFFECTS:   None (read-only traversal).
# CALLED BY:      find_files() and every scan_* function that iterates
#                 the tree directly (scan_containers, scan_iac,
#                 fallback_loc_scan).
# CALLS:          os.walk().
#
# EXAMPLE:
#   for dirpath, dirnames, filenames in walk("/repo"): ...
#   # dirnames will never contain "node_modules", ".git", etc.
#--------------------------------------------------------------------------
def walk(root):
    """Drop-in replacement for os.walk(root) that prunes EXCLUDE_DIRS from
    dirnames in place, so nothing under them is ever visited or yielded."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Mutating dirnames *in place* (not reassigning the local name) is
        # what tells os.walk() to skip descending into these directories.
        # Reassigning `dirnames = [...]` here instead would silently do
        # nothing, os.walk() keeps its own reference to the original list.
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        yield dirpath, dirnames, filenames


# ------------------------------------------------------------------------
# find_files
#
# WHAT IT DOES:   Finds every file under a directory whose name either
#                 exactly matches one of a set of names, or ends with one
#                 of a set of suffixes.
# WHY IT EXISTS:  This is the one file-finding primitive every scan_*
#                 function uses instead of hand-rolling its own os.walk()
#                 loop, so EXCLUDE_DIRS pruning is applied consistently
#                 everywhere.
#
# INPUTS:
#   root (str) - directory to search under.
#   names (iterable[str] or None) - exact filenames to match, e.g.
#     {"package.json"}. Defaults to an empty set if None.
#   suffixes (iterable[str] or None) - filename suffixes to match, e.g.
#     (".csproj",) or ("requirements.txt",) to match anything ending in
#     that string, not just a file extension. Defaults to () if None.
#
# RETURNS:
#   (list[str]) - full paths of every matching file, in os.walk()'s
#   natural (unsorted) order. Empty list if nothing matched.
#
# RAISES/ERRORS:  None expected beyond what walk() can raise.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      Nearly every scan_* function in this file and in
#                 dead_weight_scan.py.
# CALLS:          walk().
#
# EXAMPLE:
#   find_files(root, names={"Gemfile"})
#   -> ["/repo/Gemfile"]
#   find_files(root, suffixes=(".csproj",))
#   -> ["/repo/src/App.csproj", "/repo/tests/App.Tests.csproj"]
#--------------------------------------------------------------------------
def find_files(root, names=None, suffixes=None):
    """Finds every file under root (via walk(), so EXCLUDE_DIRS is already
    pruned) whose filename is an exact match in `names` or ends with one
    of `suffixes`. Returns a plain list of full paths, unsorted."""
    names = set(names or [])
    suffixes = tuple(suffixes or ())
    hits = []
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if filename in names or (suffixes and filename.endswith(suffixes)):
                hits.append(os.path.join(dirpath, filename))
    return hits


# --- scc / fallback LOC -----------------------------------------------

# ------------------------------------------------------------------------
# run_scc
#
# WHAT IT DOES:   Shells out to the external `scc` command-line tool to
#                 get accurate lines-of-code and language statistics.
# WHY IT EXISTS:  Writing a correct per-language LOC/comment/complexity
#                 counter from scratch is a large, language-specific
#                 undertaking that `scc` already solves well; this
#                 function just calls it and normalizes its output.
#
# INPUTS:
#   root (str) - directory to scan.
#
# RETURNS:
#   (list[dict] or None) - one dict per language with keys name, files,
#   lines, code, comment, blank, complexity, or None if `scc` isn't
#   installed, times out, exits non-zero, or produces output that isn't
#   valid JSON. Callers must fall back to fallback_loc_scan() when this
#   returns None.
#
# RAISES/ERRORS:  Never raises; OSError (binary not found) and
#                 subprocess.TimeoutExpired are both caught and turned
#                 into a None return.
# SIDE EFFECTS:   Spawns a child process. Reads (but never writes to)
#                 the filesystem under root, via the external tool.
# CALLED BY:      main().
# CALLS:          subprocess.run(["scc", ...]).
#
# EXAMPLE:
#   run_scc("/repo")
#   -> [{"name": "Python", "files": 12, "lines": 900, "code": 700,
#        "comment": 120, "blank": 80, "complexity": 45}, ...]
#--------------------------------------------------------------------------
def run_scc(root):
    """Shells out to the `scc` CLI for language/LOC stats. Returns a list
    of per-language dicts, or None if `scc` isn't installed, times out, or
    exits non-zero, the caller falls back to fallback_loc_scan() in that
    case."""
    try:
        proc = subprocess.run(
            # 180s: `scc` is fast, but a very large monorepo (millions of
            # lines) can still take a while; this caps worst-case scan
            # time instead of hanging the whole cartridge scan forever.
            ["scc", "--format", "json", root],
            capture_output=True, text=True, timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        raw_entries = json.loads(proc.stdout)
    except ValueError:
        return None
    languages = []
    for entry in raw_entries:
        # scc's JSON keys are PascalCase; normalize to our snake_case schema.
        languages.append({
            "name": entry.get("Name"),
            "files": entry.get("Count", 0),
            "lines": entry.get("Lines", 0),
            "code": entry.get("Code", 0),
            "comment": entry.get("Comment", 0),
            "blank": entry.get("Blank", 0),
            "complexity": entry.get("Complexity", 0),
        })
    return languages


# ------------------------------------------------------------------------
# fallback_loc_scan
#
# WHAT IT DOES:   Manually counts files and total lines per language when
#                 the external `scc` tool isn't available.
# WHY IT EXISTS:  So the scan still produces a non-empty, useful language
#                 breakdown even on a machine without `scc` installed,
#                 at the cost of losing the comment/blank/complexity
#                 split (that needs a real per-language tokenizer, which
#                 this deliberately does not attempt to be).
#
# INPUTS:
#   root (str) - directory to scan.
#
# RETURNS:
#   (list[dict]) - one dict per language found (only languages in
#   FALLBACK_EXT_LANG are counted), with keys name, files, lines, and
#   code/comment/blank/complexity always 0. Empty list if no recognized
#   source files exist under root.
#
# RAISES/ERRORS:  None expected; per-file read failures are absorbed by
#                 read_text() returning "".
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      main(), only when run_scc() returns None.
# CALLS:          walk(), read_text().
#
# EXAMPLE:
#   fallback_loc_scan("/repo")
#   -> [{"name": "Python", "files": 12, "lines": 950, "code": 0,
#        "comment": 0, "blank": 0, "complexity": 0}]
#--------------------------------------------------------------------------
def fallback_loc_scan(root):
    """Rough manual LOC count used only when `scc` isn't available: files
    and total line count per language in FALLBACK_EXT_LANG. No
    comment/blank/complexity split, that data needs a real tokenizer."""
    languages_by_name = {}
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            language = FALLBACK_EXT_LANG.get(ext)
            if not language:
                continue
            path = os.path.join(dirpath, filename)
            text = read_text(path)
            if not text and os.path.getsize(path) > 0:
                continue  # unreadable/binary
            entry = languages_by_name.setdefault(language, {
                "name": language, "files": 0, "lines": 0,
                "code": 0, "comment": 0, "blank": 0, "complexity": 0,
            })
            entry["files"] += 1
            # A file with content but no trailing newline still has one
            # more line than the number of "\n" characters in it, this
            # +1 accounts for that final, unterminated line.
            entry["lines"] += text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    return list(languages_by_name.values())


# ------------------------------------------------------------------------
# totals_of
#
# WHAT IT DOES:   Adds up the files/lines/code/comment/blank fields across
#                 every language entry into one overall total.
# WHY IT EXISTS:  The final JSON report includes both a per-language
#                 breakdown and a single repo-wide total; this is the one
#                 place that sums them, so the two can never drift apart.
#
# INPUTS:
#   languages (list[dict]) - output of run_scc() or fallback_loc_scan().
#
# RETURNS:
#   (dict) - {"files", "lines", "code", "comment", "blank"} summed across
#   all entries. All zero if languages is empty.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      main().
# CALLS:          None (pure aggregation).
#
# EXAMPLE:
#   totals_of([{"files": 2, "lines": 10, "code": 8, "comment": 1,
#               "blank": 1}, {"files": 1, "lines": 5, "code": 5,
#               "comment": 0, "blank": 0}])
#   -> {"files": 3, "lines": 15, "code": 13, "comment": 1, "blank": 1}
#--------------------------------------------------------------------------
def totals_of(languages):
    """Sums the files/lines/code/comment/blank fields across every
    language entry (from run_scc() or fallback_loc_scan()) into one dict."""
    totals = {"files": 0, "lines": 0, "code": 0, "comment": 0, "blank": 0}
    for language in languages:
        for key in totals:
            totals[key] += language.get(key, 0)
    return totals


# --- generic helpers for manifest/lockfile parsing ---------------------

# ------------------------------------------------------------------------
# toml_section_lines
#
# WHAT IT DOES:   Pulls out the raw lines that belong to one named TOML
#                 table (a `[section.name]` block), stopping at the next
#                 `[...]` header.
# WHY IT EXISTS:  Several ecosystems (Python's Poetry, Rust's Cargo,
#                 C/C++'s Conan) declare dependencies inside a specific
#                 TOML table. Pulling in the full TOML spec (arrays of
#                 tables, inline tables, multi-line strings, etc.) is
#                 overkill just to hand a table's body to
#                 count_key_value_lines(); this does the one thing those
#                 callers actually need.
#
# INPUTS:
#   text (str) - full file contents of a TOML file.
#   header (str) - the table name to extract, without brackets, e.g.
#     "tool.poetry.dependencies".
#
# RETURNS:
#   (list[str]) - the raw (unstripped) lines inside that table. Empty
#   list if the table doesn't exist in text.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_python(), scan_rust(), scan_cpp() (all via
#                 count_key_value_lines()).
# CALLS:          str.splitlines().
#
# EXAMPLE:
#   text = "[dependencies]\\nserde = \\"1.0\\"\\n\\n[dev-dependencies]\\n..."
#   toml_section_lines(text, "dependencies") -> ['serde = "1.0"']
#--------------------------------------------------------------------------
def toml_section_lines(text, header):
    """Returns the raw lines belonging to a `[header]` TOML table, up to
    (not including) the next `[...]` table header. Not a real TOML parser,
    just enough to hand a table's body to count_key_value_lines()."""
    lines = text.splitlines()
    section_lines = []
    in_section = False
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("["):
            in_section = stripped_line == f"[{header}]"
            continue
        if in_section:
            section_lines.append(line)
    return section_lines


# ------------------------------------------------------------------------
# count_key_value_lines
#
# WHAT IT DOES:   Counts how many `key = value` lines appear in a list of
#                 lines (typically a TOML table's body), skipping blanks,
#                 comments, and specific keys the caller wants excluded.
# WHY IT EXISTS:  This is the shared "how many dependencies are declared
#                 in this table" counter used by every TOML-based
#                 ecosystem (Poetry, Cargo, Conan), so the counting rule
#                 (what counts as a dependency line) only has to be
#                 written once.
#
# INPUTS:
#   lines (list[str]) - lines to scan, as produced by toml_section_lines().
#   exclude_keys (iterable[str]) - key names to not count even though
#     they match the pattern, e.g. {"python"} for Poetry's Python version
#     constraint, which lives in the same table as real dependencies but
#     isn't one.
#
# RETURNS:
#   (int) - number of matching, non-excluded key/value lines.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_python(), scan_rust(), scan_cpp().
# CALLS:          re.match().
#
# EXAMPLE:
#   count_key_value_lines(['python = "^3.10"', 'flask = "2.0"'],
#                          exclude_keys={"python"})
#   -> 1
#--------------------------------------------------------------------------
def count_key_value_lines(lines, exclude_keys=()):
    """Counts `key = value` lines (as produced by toml_section_lines()),
    skipping blanks, comments, and any key named in exclude_keys."""
    count = 0
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        # Matches a bare or quoted key at the start of the line followed
        # by "=", e.g. `serde = "1.0"` or `"my-pkg" = "1.0"`. Does NOT
        # match a continuation line of a multi-line value, or a line that
        # starts with the value instead of a key (this is a heuristic
        # line scanner, not a real TOML parser).
        match = re.match(r'^["\']?([\w.\-/@]+)["\']?\s*=', stripped_line)
        if match and match.group(1) not in exclude_keys:
            count += 1
    return count


# ------------------------------------------------------------------------
# host_of
#
# WHAT IT DOES:   Extracts just the hostname portion out of a URL string.
# WHY IT EXISTS:  Every private-registry check in this file needs to
#                 compare "what host is this URL pointing at" against a
#                 known-good set of default hosts; this is the one place
#                 that does the URL parsing, so a bad/unparseable URL is
#                 handled consistently everywhere.
#
# INPUTS:
#   url (str) - a URL string, e.g. from a manifest's registry field.
#
# RETURNS:
#   (str or None) - the hostname (e.g. "registry.npmjs.org"), or None if
#   url isn't parseable as a URL at all.
#
# RAISES/ERRORS:  Never raises; urlparse's ValueError is caught.
# SIDE EFFECTS:   None.
# CALLED BY:      add_if_private().
# CALLS:          urllib.parse.urlparse().
#
# EXAMPLE:
#   host_of("https://registry.npmjs.org/left-pad") -> "registry.npmjs.org"
#   host_of("not a url")                            -> None
#--------------------------------------------------------------------------
def host_of(url):
    """Extracts the hostname from a URL string. Returns None for anything
    unparseable rather than raising."""
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


# ------------------------------------------------------------------------
# add_if_private
#
# WHAT IT DOES:   Records a "private/internal registry" finding, but only
#                 if the URL's host isn't one of the ecosystem's known
#                 public defaults.
# WHY IT EXISTS:  Every scan_* function needs to make this same decision
#                 (public default vs. private registry) whenever it finds
#                 a registry/source/index URL in a manifest. Routing them
#                 all through one function means the "is this actually
#                 private" logic and the shape of the recorded finding
#                 only exist in one place.
#
# INPUTS:
#   private_registries (list) - the caller's accumulator list; this
#     function appends to it in place (no return value).
#   ecosystem (str) - ecosystem key for the finding, e.g. "javascript".
#   url (str) - the registry/source URL found in a manifest.
#   source_file (str) - path of the manifest the URL came from, for the
#     report to point back to.
#   default_hosts (set[str]) - hosts considered "public default" for this
#     ecosystem, from DEFAULT_REGISTRY_HOSTS (or an empty set() when the
#     caller has no concept of a default, see scan_go()).
#
# RETURNS:
#   (None) - mutates private_registries in place instead.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   Appends to private_registries when url's host is
#                 private. No-op otherwise.
# CALLED BY:      Every scan_* function that checks for private registries
#                 (scan_javascript, scan_python, scan_go, scan_java,
#                 scan_ruby, scan_php, scan_rust, scan_dotnet).
# CALLS:          host_of().
#
# EXAMPLE:
#   add_if_private(private_registries, "pip",
#                   "https://pkgs.mycorp.internal/simple/", "requirements.txt",
#                   {"pypi.org", "files.pythonhosted.org"})
#   # appends {"ecosystem": "pip", "host": "pkgs.mycorp.internal", ...}
#--------------------------------------------------------------------------
def add_if_private(private_registries, ecosystem, url, source_file, default_hosts):
    """Appends a private-registry entry if url's host isn't one of
    default_hosts for this ecosystem. No-op if the host matches a default
    or can't be parsed, this is the single choke point every scan_*
    function routes registry URLs through."""
    host = host_of(url)
    if not host or host in default_hosts:
        return
    private_registries.append({"ecosystem": ecosystem, "host": host, "url": url, "source_file": source_file})


# --- per-ecosystem package manager inventory ----------------------------

# ------------------------------------------------------------------------
# scan_javascript
#
# WHAT IT DOES:   Finds JavaScript/npm-ecosystem manifests and lockfiles,
#                 counts how many dependencies are declared vs. actually
#                 resolved, and flags any non-default registry.
# WHY IT EXISTS:  npm, yarn, and pnpm each use a different lockfile format
#                 with a different way of counting resolved packages;
#                 this function is where that format-specific logic lives
#                 for the JavaScript ecosystem specifically.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator this function appends one entry
#     to (in place) if any npm-family manifest/lockfile exists.
#   private_registries (list) - accumulator passed through to
#     add_if_private().
#
# RETURNS:
#   (None) - results are appended to package_managers/private_registries
#   in place; nothing is returned directly.
#
# RAISES/ERRORS:  None expected; malformed JSON/lockfiles just leave the
#                 corresponding count as None.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_json(), read_text(), add_if_private().
#
# EXAMPLE:
#   scan_javascript("/repo", package_managers, private_registries)
#   # package_managers gains one entry like:
#   # {"ecosystem": "javascript", "manifest_files": [...],
#   #  "lockfile_files": [...], "declared_dependencies": 40,
#   #  "resolved_dependencies": 612}
#--------------------------------------------------------------------------
def scan_javascript(root, package_managers, private_registries):
    """JavaScript, via npm/yarn/pnpm: declared count from package.json,
    resolved count from whichever lockfile is present (format differs by
    tool), plus any non-default registry found in package.json or .npmrc.
    Appends one entry to package_managers if any npm manifest/lockfile
    exists."""
    manifests = find_files(root, names={"package.json"})
    lockfiles = find_files(root, names={"package-lock.json", "yarn.lock", "pnpm-lock.yaml"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for manifest in manifests:
        data = read_json(manifest)
        if not isinstance(data, dict):
            continue
        declared_count = sum(len(data.get(key) or {}) for key in
                              ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"))
        publish_registry = (data.get("publishConfig") or {}).get("registry")
        if publish_registry:
            add_if_private(private_registries, "javascript", publish_registry, manifest,
                            DEFAULT_REGISTRY_HOSTS["javascript"])
        # Only the first package.json's declared count is used (a
        # monorepo with several package.json files would otherwise sum
        # unrelated workspaces together); `break` stops after it.
        break
    resolved_count = None
    for lockfile in lockfiles:
        filename = os.path.basename(lockfile)
        text = read_text(lockfile)
        if filename == "package-lock.json":
            data = read_json(lockfile)
            if isinstance(data, dict) and isinstance(data.get("packages"), dict):
                # v2/v3 lockfile: flat "packages" map, one entry per resolved
                # package plus a "" entry for the root project itself.
                resolved_count = len(data["packages"]) - (1 if "" in data["packages"] else 0)
            elif isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
                # v1 lockfile: nested "dependencies" tree, walk it recursively.
                def count_nested_deps(deps):
                    # ----------------------------------------------------
                    # count_nested_deps
                    # WHAT IT DOES: Recursively counts every package
                    #   entry in an npm v1 lockfile's nested
                    #   "dependencies" tree (each resolved package can
                    #   have its own "dependencies" sub-tree for
                    #   transitive deps that needed a different version).
                    # INPUTS: deps (dict) - a "dependencies" map from the
                    #   lockfile (or a nested sub-map).
                    # RETURNS: (int) - total count of this map's entries
                    #   plus every entry in every nested sub-map.
                    # CALLED BY: scan_javascript(), and itself (recursion).
                    # ----------------------------------------------------
                    count = 0
                    for value in deps.values():
                        count += 1
                        if isinstance(value, dict) and isinstance(value.get("dependencies"), dict):
                            count += count_nested_deps(value["dependencies"])
                    return count
                resolved_count = count_nested_deps(data["dependencies"])
        elif filename == "yarn.lock":
            # yarn.lock entries are blocks whose header line starts at
            # column 0 and ends with ":", one block per resolved package.
            # Matches e.g. `left-pad@^1.0.0:` at line start; does NOT
            # match indented body lines like `  version "1.3.0"`.
            resolved_count = sum(1 for line in text.splitlines()
                                  if line and not line[0].isspace() and line.rstrip().endswith(":")
                                  and not line.startswith("#")) or None
        elif filename == "pnpm-lock.yaml":
            # Matches a 2-space-indented package key ending in ":" with
            # nothing else on the line, e.g. "  /left-pad@1.3.0:". Does
            # NOT match deeper-indented fields inside that package's
            # block (e.g. "    resolution:").
            resolved_count = len(re.findall(r"^\s{2}[^\s#][^:]*:\s*$", text, re.MULTILINE)) or None
        if resolved_count is not None:
            # First lockfile with a usable count wins; a repo shouldn't
            # have more than one npm-family lockfile, but if it does,
            # only one is authoritative for "what's actually installed."
            break
    for npmrc_file in find_files(root, names={".npmrc"}):
        text = read_text(npmrc_file)
        # Matches `registry=URL` or a scoped `@myorg:registry=URL` line.
        for match in re.finditer(r"^(?:@[\w-]+:)?registry\s*=\s*(\S+)", text, re.MULTILINE):
            add_if_private(private_registries, "javascript", match.group(1), npmrc_file,
                            DEFAULT_REGISTRY_HOSTS["javascript"])
    package_managers.append({"ecosystem": "javascript", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# install_requires_from_setup_cfg
#
# WHAT IT DOES:   Reads the install_requires list out of a setup.cfg
#                 file's [options] section.
# WHY IT EXISTS:  setup.cfg is genuine INI-format, so the standard
#                 library's configparser can correctly join a multi-line
#                 install_requires value without any custom parsing code.
#
# INPUTS:
#   path (str) - path to a setup.cfg file.
#
# RETURNS:
#   (list[str] or None) - one requirement-spec string per dependency
#   (version specifier still attached, e.g. "requests>=2.0", the same
#   shape as a requirements.txt line), or None if the file can't be
#   parsed as INI or has no [options] install_requires field.
#
# RAISES/ERRORS:  Never raises; configparser.Error is caught.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      scan_python() (this file), list_python_deps() and
#                 resolve_version_python() (dead_weight_scan.py).
# CALLS:          read_text(), configparser.ConfigParser.
#
# EXAMPLE:
#   # setup.cfg contains:
#   #   [options]
#   #   install_requires =
#   #       requests>=2.0
#   #       flask
#   install_requires_from_setup_cfg("setup.cfg")
#   -> ["requests>=2.0", "flask"]
#--------------------------------------------------------------------------
def install_requires_from_setup_cfg(path):
    """setup.cfg's [options] install_requires field via stdlib configparser
    (setup.cfg is genuine INI, no need for a hand-rolled continuation-line
    parser; configparser already correctly joins the "install_requires =\\n
    pkg1\\n    pkg2" continuation form into one string). Returns a list of
    requirement-spec strings (version specifier still attached, same shape
    as a requirements.txt line), or None if unparseable/absent."""
    parser = configparser.ConfigParser()
    try:
        parser.read_string(read_text(path))
    except configparser.Error:
        return None
    if not parser.has_option("options", "install_requires"):
        return None
    raw = parser.get("options", "install_requires")
    return [line.strip() for line in raw.replace(",", "\n").splitlines() if line.strip()]


# ------------------------------------------------------------------------
# install_requires_from_setup_py
#
# WHAT IT DOES:   Reads the install_requires argument out of a setup.py
#                 file's setup(...) call, without running the file.
# WHY IT EXISTS:  A setup.py is an executable Python script, and this
#                 tool scans untrusted repos, so it must never be
#                 imported or exec'd (that would let a malicious repo run
#                 arbitrary code during a "read-only" scan). Parsing it
#                 with Python's `ast` module and pulling out only a
#                 *literal* list/tuple value keeps the scan safe, at the
#                 cost of skipping setup.py files that compute their
#                 dependency list dynamically (e.g. reading from a
#                 requirements.txt at setup time), those genuinely can't
#                 be resolved without running code.
#
# INPUTS:
#   path (str) - path to a setup.py file.
#
# RETURNS:
#   (list[str] or None) - requirement-spec strings if install_requires is
#   a literal list/tuple of strings; None if the file has a syntax error,
#   has no setup() call, has no install_requires keyword, or
#   install_requires isn't a literal (e.g. it's a variable name or a
#   function call).
#
# RAISES/ERRORS:  Never raises; SyntaxError and literal-eval failures
#                 (ValueError/SyntaxError from ast.literal_eval) are both
#                 caught.
# SIDE EFFECTS:   None. Parses only, never executes the file.
# CALLED BY:      scan_python() (this file), list_python_deps() and
#                 resolve_version_python() (dead_weight_scan.py).
# CALLS:          read_text(), ast.parse(), ast.walk(), ast.literal_eval().
#
# EXAMPLE:
#   # setup.py contains: setup(name="app", install_requires=["flask"])
#   install_requires_from_setup_py("setup.py") -> ["flask"]
#--------------------------------------------------------------------------
def install_requires_from_setup_py(path):
    """setup.py's setup(install_requires=...) argument, extracted via ast
    in parse-only mode. This tool never executes code from a scanned repo,
    a real concern for a security-tooling suite pointed at untrusted repos,
    so only a literal list/tuple of strings is resolved; a computed value
    (a variable, a call to a helper that reads requirements.txt, etc.)
    can't be resolved statically and is honestly skipped, not guessed."""
    try:
        tree = ast.parse(read_text(path))
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setup":
            for keyword in node.keywords:
                if keyword.arg == "install_requires":
                    try:
                        # literal_eval refuses anything that isn't a
                        # literal (numbers, strings, lists, dicts, etc.),
                        # so a call like `install_requires=read_reqs()`
                        # safely fails here instead of being executed.
                        value = ast.literal_eval(keyword.value)
                    except (ValueError, SyntaxError):
                        return None
                    if isinstance(value, (list, tuple)):
                        return [v for v in value if isinstance(v, str)]
    return None


# ------------------------------------------------------------------------
# scan_python
#
# WHAT IT DOES:   Finds Python manifests (requirements*.txt,
#                 pyproject.toml, Pipfile, setup.py, setup.cfg) and
#                 lockfiles (Pipfile.lock, poetry.lock, uv.lock), counts
#                 declared vs. resolved dependencies, and flags any
#                 non-default package index URL.
# WHY IT EXISTS:  Python has more competing dependency-declaration
#                 formats than most ecosystems (pip, Poetry, Pipenv,
#                 setuptools); this function is where all of that
#                 format-specific counting logic lives for Python.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accumulator passed to add_if_private().
#
# RETURNS:
#   (None) - results appended to package_managers/private_registries.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text(), toml_section_lines(),
#                 count_key_value_lines(), install_requires_from_setup_py(),
#                 install_requires_from_setup_cfg(), read_json(),
#                 add_if_private().
#
# EXAMPLE:
#   scan_python("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_python(root, package_managers, private_registries):
    """Python: declared count from requirements*.txt, pyproject.toml
    (PEP 621 and Poetry), Pipfile, setup.py, and setup.cfg; resolved count
    from Pipfile.lock, poetry.lock, and uv.lock; non-default index URLs
    from any of those plus pip.conf/pip.ini."""
    requirements_files = find_files(root, suffixes=("requirements.txt",)) + \
        [f for f in find_files(root, suffixes=(".txt",)) if os.path.basename(f).startswith("requirements")]
    requirements_files = sorted(set(requirements_files))
    pyproject_files = find_files(root, names={"pyproject.toml"})
    pipfiles = find_files(root, names={"Pipfile"})
    setup_pys = find_files(root, names={"setup.py"})
    setup_cfgs = find_files(root, names={"setup.cfg"})
    pipfile_locks = find_files(root, names={"Pipfile.lock"})
    poetry_locks = find_files(root, names={"poetry.lock"})
    uv_locks = find_files(root, names={"uv.lock"})
    manifests = requirements_files + pyproject_files + pipfiles + setup_pys + setup_cfgs
    lockfiles = pipfile_locks + poetry_locks + uv_locks
    if not manifests and not lockfiles:
        return
    declared_count = None
    for requirements_file in requirements_files:
        text = read_text(requirements_file)
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                # An option line, e.g. "-r base.txt" or "--index-url ...",
                # not a package requirement; only --index-url and
                # --extra-index-url are worth inspecting further, for a
                # private registry.
                match = re.match(r"--(?:extra-)?index-url\s+(\S+)", line)
                if match:
                    add_if_private(private_registries, "pip", match.group(1), requirements_file,
                                    DEFAULT_REGISTRY_HOSTS["pip"])
                continue
            count += 1
        declared_count = (declared_count or 0) + count
    for pyproject_file in pyproject_files:
        text = read_text(pyproject_file)
        # PEP 621 (the standardized pyproject.toml format): a
        # dependencies = [...] array at the top level. DOTALL lets "."
        # match across the newlines inside a multi-line array.
        pep621_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
        if pep621_match:
            declared_count = (declared_count or 0) + len(re.findall(r'["\']([^"\']+)["\']', pep621_match.group(1)))
        poetry_dep_lines = toml_section_lines(text, "tool.poetry.dependencies")
        if poetry_dep_lines:
            declared_count = (declared_count or 0) + count_key_value_lines(poetry_dep_lines, exclude_keys={"python"})
        # Poetry can declare custom package sources via one or more
        # [[tool.poetry.source]] array-of-tables entries, each with a url.
        for source_match in re.finditer(
                r'\[\[tool\.poetry\.source\]\].*?url\s*=\s*["\']([^"\']+)["\']', text, re.DOTALL):
            add_if_private(private_registries, "pip", source_match.group(1), pyproject_file,
                            DEFAULT_REGISTRY_HOSTS["pip"])
    for pipfile in pipfiles:
        text = read_text(pipfile)
        for section in ("packages", "dev-packages"):
            section_lines = toml_section_lines(text, section)
            declared_count = (declared_count or 0) + count_key_value_lines(section_lines)
    for setup_py_file in setup_pys:
        requires = install_requires_from_setup_py(setup_py_file)
        if requires:
            declared_count = (declared_count or 0) + len(requires)
    for setup_cfg_file in setup_cfgs:
        requires = install_requires_from_setup_cfg(setup_cfg_file)
        if requires:
            declared_count = (declared_count or 0) + len(requires)
    resolved_count = None
    for lockfile in pipfile_locks:
        data = read_json(lockfile)
        if isinstance(data, dict):
            resolved_count = (resolved_count or 0) + len(data.get("default") or {}) + len(data.get("develop") or {})
    for lockfile in poetry_locks + uv_locks:
        text = read_text(lockfile)
        # poetry.lock and uv.lock both list resolved packages as
        # [[package]] TOML array-of-tables entries; counting the header
        # lines is enough, no need to parse each block's fields.
        block_count = len(re.findall(r"^\[\[package\]\]\s*$", text, re.MULTILINE))
        if block_count:
            resolved_count = (resolved_count or 0) + block_count
    for pip_conf in find_files(root, names={"pip.conf", "pip.ini"}):
        text = read_text(pip_conf)
        match = re.search(r"index-url\s*=\s*(\S+)", text)
        if match:
            add_if_private(private_registries, "pip", match.group(1), pip_conf, DEFAULT_REGISTRY_HOSTS["pip"])
    package_managers.append({"ecosystem": "python", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# scan_go
#
# WHAT IT DOES:   Finds go.mod/go.sum, counts declared vs. resolved
#                 modules, and flags any `replace` directive pointing at
#                 a private host.
# WHY IT EXISTS:  Go's module system has its own require/replace/go.sum
#                 conventions that don't match any other ecosystem here,
#                 so it gets its own dedicated parser.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accumulator passed to add_if_private().
#
# RETURNS:
#   (None) - results appended to package_managers/private_registries.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text(), add_if_private().
#
# EXAMPLE:
#   scan_go("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_go(root, package_managers, private_registries):
    """Go: declared count from go.mod's require directives, resolved
    count from unique modules in go.sum, plus any `replace` directive
    that points at a private host instead of a version."""
    manifests = find_files(root, names={"go.mod"})
    lockfiles = find_files(root, names={"go.sum"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for go_mod_file in manifests:
        text = read_text(go_mod_file)
        count = 0
        in_require_block = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block:
                if stripped_line == ")":
                    in_require_block = False
                    continue
                if stripped_line and not stripped_line.startswith("//"):
                    count += 1
                continue
            if stripped_line.startswith("require ") and "(" not in stripped_line:
                count += 1
        declared_count = (declared_count or 0) + count
        # A `replace old => new` directive can point `new` at either a
        # private module-proxy URL, or a bare host/path like
        # "git.mycorp.internal/team/pkg" with no scheme at all, hence the
        # fallback of prepending "https://" before extracting the host.
        for match in re.finditer(r"^replace\s+\S+\s*=>\s*(\S+)", text, re.MULTILINE):
            target = match.group(1)
            if "://" in target or (re.match(r"^[\w.-]+\.[a-z]{2,}/", target)):
                url = target if "://" in target else f"https://{target}"
                add_if_private(private_registries, "go", url, go_mod_file, set())
    resolved_count = None
    for go_sum_file in lockfiles:
        text = read_text(go_sum_file)
        # Each line is "module version hash"; a module usually appears
        # twice (module hash + go.mod hash), dedupe to unique modules.
        modules = {line.split()[0] for line in text.splitlines() if line.split()}
        if modules:
            resolved_count = (resolved_count or 0) + len(modules)
    package_managers.append({"ecosystem": "go", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# scan_java
#
# WHAT IT DOES:   Finds Maven (pom.xml), Gradle (build.gradle[.kts]), and
#                 Ivy (ivy.xml) manifests, counts declared dependencies,
#                 and flags any custom Maven repository URL.
# WHY IT EXISTS:  Java has three unrelated build-tool conventions in
#                 common use, each with a different dependency-declaration
#                 syntax; this function normalizes all three into one
#                 "java" ecosystem entry.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accumulator passed to add_if_private().
#
# RETURNS:
#   (None) - results appended to package_managers/private_registries.
#   There is deliberately no resolved_dependencies count: none of Maven,
#   Gradle, or Ivy has a default lockfile to count resolved packages from.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text(), add_if_private().
#
# EXAMPLE:
#   scan_java("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_java(root, package_managers, private_registries):
    """Java/Maven/Gradle/Ivy: declared count from <dependency> tags
    (pom.xml), dependency-config calls (build.gradle), or <dependency
    org=.../> tags (ivy.xml), plus any custom Maven repository URL. No
    resolved count, none of the three has a default lockfile. Ivy resolvers
    are conventionally configured in a separate ivysettings.xml, not
    embedded in ivy.xml itself, so private-registry detection isn't
    attempted for Ivy manifests."""
    manifests = find_files(root, names={"pom.xml", "build.gradle", "build.gradle.kts", "ivy.xml"})
    if not manifests:
        return
    declared_count = None
    for manifest in manifests:
        text = read_text(manifest)
        if manifest.endswith("pom.xml"):
            declared_count = (declared_count or 0) + len(re.findall(r"<dependency>", text))
            repositories_block = re.search(r"<repositories>(.*?)</repositories>", text, re.DOTALL)
            if repositories_block:
                for url_match in re.finditer(r"<url>([^<]+)</url>", repositories_block.group(1)):
                    add_if_private(private_registries, "maven", url_match.group(1), manifest,
                                    DEFAULT_REGISTRY_HOSTS["maven"])
        elif manifest.endswith("ivy.xml"):
            # Ivy's <dependency org="..." name="..." rev="..."/> is a
            # self-closing attribute tag, unlike Maven's nested-element
            # <dependency>...</dependency>, so it needs its own count.
            declared_count = (declared_count or 0) + len(re.findall(r"<dependency\b", text))
        else:
            # Gradle: any of these configuration names followed by "(" or
            # a quote marks a dependency declaration, e.g.
            # `implementation("com.foo:bar:1.0")` or
            # `testImplementation 'com.foo:bar:1.0'`.
            declared_count = (declared_count or 0) + len(re.findall(
                r"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*[\(\'\"]",
                text))
            for url_match in re.finditer(r"maven\s*\{\s*url\s*[=]?\s*[\'\"]([^\'\"]+)[\'\"]", text):
                add_if_private(private_registries, "maven", url_match.group(1), manifest,
                                DEFAULT_REGISTRY_HOSTS["maven"])
    package_managers.append({"ecosystem": "java", "manifest_files": manifests, "lockfile_files": [],
                              "declared_dependencies": declared_count, "resolved_dependencies": None})


# ------------------------------------------------------------------------
# scan_ruby
#
# WHAT IT DOES:   Finds Gemfile/Gemfile.lock, counts declared vs.
#                 resolved gems, and flags any non-default gem source.
# WHY IT EXISTS:  Bundler's Gemfile.lock has its own indentation-based
#                 structure (not JSON, not TOML); this is the dedicated
#                 parser for that format.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accumulator passed to add_if_private().
#
# RETURNS:
#   (None) - results appended to package_managers/private_registries.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text(), add_if_private().
#
# EXAMPLE:
#   scan_ruby("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_ruby(root, package_managers, private_registries):
    """Ruby/Bundler: declared count from `gem` lines in the Gemfile,
    resolved count from the GEM specs: block in Gemfile.lock, plus any
    non-default `source` line."""
    manifests = find_files(root, names={"Gemfile"})
    lockfiles = find_files(root, names={"Gemfile.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for gemfile in manifests:
        text = read_text(gemfile)
        declared_count = (declared_count or 0) + len(re.findall(r"^\s*gem\s+['\"]", text, re.MULTILINE))
        for match in re.finditer(r"^\s*source\s+['\"]([^'\"]+)['\"]", text, re.MULTILINE):
            add_if_private(private_registries, "gem", match.group(1), gemfile, DEFAULT_REGISTRY_HOSTS["gem"])
    resolved_count = None
    for lockfile in lockfiles:
        text = read_text(lockfile)
        count = 0
        in_specs_section = False
        for line in text.splitlines():
            if line.strip() == "specs:":
                in_specs_section = True
                continue
            if in_specs_section:
                # Top-level gems are indented 4 spaces; their own
                # dependencies are indented 6, only count the former.
                # BE CAREFUL if editing this: swapping the order of this
                # check with the next `elif` would break the "leaving the
                # specs: block" detection below.
                if line.startswith("    ") and not line.startswith("      "):
                    count += 1
                elif line and not line.startswith(" "):
                    in_specs_section = False
        if count:
            resolved_count = (resolved_count or 0) + count
    package_managers.append({"ecosystem": "ruby", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# scan_php
#
# WHAT IT DOES:   Finds composer.json/composer.lock, counts declared vs.
#                 resolved packages, and flags any custom repository URL.
# WHY IT EXISTS:  Composer's manifest/lockfile are both plain JSON, so
#                 this is the shortest scan_* function, JSON key lookups
#                 are all that's needed.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accumulator passed to add_if_private().
#
# RETURNS:
#   (None) - results appended to package_managers/private_registries.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_json(), add_if_private().
#
# EXAMPLE:
#   scan_php("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_php(root, package_managers, private_registries):
    """PHP/Composer: declared count from require + require-dev in
    composer.json, resolved count from packages + packages-dev arrays in
    composer.lock, plus any custom repository URL."""
    manifests = find_files(root, names={"composer.json"})
    lockfiles = find_files(root, names={"composer.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for composer_json_file in manifests:
        data = read_json(composer_json_file)
        if isinstance(data, dict):
            # "php" itself can appear as a pseudo-dependency (a required
            # PHP version), not a real package, so it's excluded here.
            required = {k: v for k, v in (data.get("require") or {}).items() if k != "php"}
            required_dev = data.get("require-dev") or {}
            declared_count = (declared_count or 0) + len(required) + len(required_dev)
            repositories = data.get("repositories")
            if isinstance(repositories, list):
                for repository in repositories:
                    if isinstance(repository, dict) and repository.get("url"):
                        add_if_private(private_registries, "composer", repository["url"], composer_json_file,
                                        DEFAULT_REGISTRY_HOSTS["composer"])
            elif isinstance(repositories, dict):
                for repository in repositories.values():
                    if isinstance(repository, dict) and repository.get("url"):
                        add_if_private(private_registries, "composer", repository["url"], composer_json_file,
                                        DEFAULT_REGISTRY_HOSTS["composer"])
    resolved_count = None
    for lockfile in lockfiles:
        data = read_json(lockfile)
        if isinstance(data, dict):
            resolved_count = (resolved_count or 0) + len(data.get("packages") or []) + \
                len(data.get("packages-dev") or [])
    package_managers.append({"ecosystem": "php", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# scan_rust
#
# WHAT IT DOES:   Finds Cargo.toml/Cargo.lock, counts declared vs.
#                 resolved crates, and flags any custom registry
#                 configured in .cargo/config.toml.
# WHY IT EXISTS:  Cargo's manifest/lockfile share the same TOML-table
#                 shape as Poetry's, so this reuses toml_section_lines()
#                 and count_key_value_lines() rather than reinventing them.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accumulator passed to add_if_private().
#
# RETURNS:
#   (None) - results appended to package_managers/private_registries.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text(), toml_section_lines(),
#                 count_key_value_lines(), add_if_private().
#
# EXAMPLE:
#   scan_rust("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_rust(root, package_managers, private_registries):
    """Rust/Cargo: declared count from the [dependencies]/[dev-dependencies]/
    [build-dependencies] tables in Cargo.toml, resolved count from
    [[package]] blocks in Cargo.lock, plus any custom registry in a
    repo-local .cargo/config.toml."""
    manifests = find_files(root, names={"Cargo.toml"})
    lockfiles = find_files(root, names={"Cargo.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for cargo_toml_file in manifests:
        text = read_text(cargo_toml_file)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            declared_count = (declared_count or 0) + count_key_value_lines(toml_section_lines(text, section))
    for cargo_config_file in find_files(root, names={"config.toml"}):
        # "config.toml" is a generic filename; only the one that actually
        # lives inside a ".cargo" directory is Cargo's config, so anything
        # else with that name (unrelated to Cargo) is skipped here.
        if os.path.basename(os.path.dirname(cargo_config_file)) != ".cargo":
            continue
        text = read_text(cargo_config_file)
        for match in re.finditer(r"registry\s*=\s*['\"]([^'\"]+)['\"]", text):
            add_if_private(private_registries, "cargo", match.group(1), cargo_config_file,
                            DEFAULT_REGISTRY_HOSTS["cargo"])
    resolved_count = None
    for lockfile in lockfiles:
        text = read_text(lockfile)
        block_count = len(re.findall(r"^\[\[package\]\]\s*$", text, re.MULTILINE))
        if block_count:
            resolved_count = (resolved_count or 0) + block_count
    package_managers.append({"ecosystem": "rust", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# scan_dotnet
#
# WHAT IT DOES:   Finds .csproj/paket.dependencies manifests and
#                 packages.lock.json/paket.lock lockfiles, counts declared
#                 vs. resolved packages, and flags any custom NuGet source.
# WHY IT EXISTS:  .NET has two competing package managers (the built-in
#                 NuGet CLI and the third-party Paket tool) that both
#                 resolve from the same NuGet registry; this function
#                 handles both under one "dotnet" ecosystem entry.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accumulator passed to add_if_private().
#
# RETURNS:
#   (None) - results appended to package_managers/private_registries.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers and private_registries.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text(), read_json(), add_if_private().
#
# EXAMPLE:
#   scan_dotnet("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_dotnet(root, package_managers, private_registries):
    """.NET/NuGet/Paket: declared count from <PackageReference> tags across
    .csproj files plus `nuget` lines in paket.dependencies, resolved count
    from packages.lock.json and/or paket.lock (if present), plus any
    custom source in nuget.config or paket.dependencies. Paket and the
    NuGet CLI both resolve from the same NuGet registry, so they share one
    ecosystem entry here."""
    csproj_files = find_files(root, suffixes=(".csproj",))
    paket_deps_files = find_files(root, names={"paket.dependencies"})
    manifests = csproj_files + paket_deps_files
    packages_lock_files = find_files(root, names={"packages.lock.json"})
    paket_lock_files = find_files(root, names={"paket.lock"})
    lockfiles = packages_lock_files + paket_lock_files
    if not manifests and not lockfiles:
        return
    declared_count = None
    for csproj_file in csproj_files:
        text = read_text(csproj_file)
        declared_count = (declared_count or 0) + len(re.findall(r"<PackageReference\b", text))
    for paket_deps_file in paket_deps_files:
        text = read_text(paket_deps_file)
        declared_count = (declared_count or 0) + len(re.findall(r"^\s*nuget\s+\S+", text, re.MULTILINE | re.IGNORECASE))
        for source_match in re.finditer(r"^\s*source\s+(\S+)", text, re.MULTILINE | re.IGNORECASE):
            add_if_private(private_registries, "nuget", source_match.group(1), paket_deps_file,
                            DEFAULT_REGISTRY_HOSTS["nuget"])
    resolved_count = None
    for lockfile in packages_lock_files:
        data = read_json(lockfile)
        if isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
            # packages.lock.json is keyed by target framework (e.g.
            # "net8.0"), each with its own package map; sum across all of
            # them since the same package can be pinned per-framework.
            total = 0
            for framework_deps in data["dependencies"].values():
                if isinstance(framework_deps, dict):
                    total += len(framework_deps)
            if total:
                resolved_count = (resolved_count or 0) + total
    for paket_lock_file in paket_lock_files:
        text = read_text(paket_lock_file)
        # paket.lock's NUGET block uses the same indentation convention as
        # Gemfile.lock's specs: block, 4-space-indented lines are top-level
        # packages, 6-space-indented lines are their transitive deps.
        count = 0
        in_nuget_section = False
        for line in text.splitlines():
            if line.strip() == "NUGET":
                in_nuget_section = True
                continue
            if in_nuget_section:
                if line.startswith("    ") and not line.startswith("      ") and not line.strip().startswith("remote:"):
                    count += 1
                elif line and not line.startswith(" "):
                    in_nuget_section = False
        if count:
            resolved_count = (resolved_count or 0) + count
    for nuget_config_file in find_files(root, names={"nuget.config", "NuGet.Config"}):
        text = read_text(nuget_config_file)
        for match in re.finditer(r'<add\s+key="[^"]*"\s+value="([^"]+)"', text):
            if match.group(1).startswith("http"):
                add_if_private(private_registries, "nuget", match.group(1), nuget_config_file,
                                DEFAULT_REGISTRY_HOSTS["nuget"])
    package_managers.append({"ecosystem": "dotnet", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# scan_dart
#
# WHAT IT DOES:   Finds pubspec.yaml/pubspec.lock, counts declared vs.
#                 resolved packages.
# WHY IT EXISTS:  Dart/Flutter's pub.dev ecosystem needs the same
#                 declared/resolved counting as every other ecosystem
#                 here, parsed out of YAML by indentation since no YAML
#                 parser dependency is available (stdlib-only tool).
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   _private_registries (list) - accepted only so this function's
#     signature matches every other scan_* function's; pub.dev has no
#     private-registry configuration convention to check, so this
#     parameter is unused (the leading underscore signals that).
#
# RETURNS:
#   (None) - results appended to package_managers.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers.
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   scan_dart("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_dart(root, package_managers, _private_registries):
    """Dart/Flutter: declared count from the dependencies/dev_dependencies
    blocks in pubspec.yaml, resolved count from top-level package entries
    in pubspec.lock. Takes private_registries for signature symmetry with
    the other scan_* functions but pub.dev has no private-registry config
    convention to check."""
    manifests = find_files(root, names={"pubspec.yaml"})
    lockfiles = find_files(root, names={"pubspec.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for pubspec_file in manifests:
        text = read_text(pubspec_file)
        in_deps_section = False
        count = 0
        for line in text.splitlines():
            if re.match(r"^(dependencies|dev_dependencies):\s*$", line):
                in_deps_section = True
                continue
            if in_deps_section:
                # A line with no leading whitespace means we've reached
                # the next top-level YAML key, i.e. left the section.
                if re.match(r"^\S", line):
                    in_deps_section = False
                    continue
                # A 2-space-indented "name:" line is a direct dependency
                # entry; anything indented further is a nested field of
                # that entry (e.g. a git/path source), not a new package.
                if re.match(r"^  \S[^:]*:", line):
                    count += 1
        declared_count = (declared_count or 0) + count
    resolved_count = None
    for lockfile in lockfiles:
        text = read_text(lockfile)
        block_count = len(re.findall(r"^  \S[^:]*:\s*$", text, re.MULTILINE))
        if block_count:
            resolved_count = (resolved_count or 0) + block_count
    package_managers.append({"ecosystem": "dart", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# ------------------------------------------------------------------------
# run_syft_conan
#
# WHAT IT DOES:   Shells out to the external `syft` tool to detect Conan
#                 (a C/C++ package manager) dependencies via its
#                 dedicated Conan and SBOM (Software Bill of Materials, a
#                 formal inventory of a project's components) catalogers.
# WHY IT EXISTS:  Conan's lockfile format changed between v1 and v2, and
#                 `syft` already correctly handles both plus
#                 conaninfo.txt and vendor-supplied SBOM files, none of
#                 which the hand-rolled regex/JSON fallback in scan_cpp()
#                 can match. Using `syft` when available gets a much more
#                 complete answer for comparatively little code.
#
# INPUTS:
#   root (str) - directory to scan.
#
# RETURNS:
#   (list[dict] or None) - {"name", "version"} entries for every detected
#   artifact, or None if `syft` isn't installed, times out, exits
#   non-zero, or its output isn't valid JSON. Callers must fall back to
#   scan_cpp()'s manifest-only parse when this returns None, the same
#   optional-tool contract as run_scc().
#
# RAISES/ERRORS:  Never raises; OSError and subprocess.TimeoutExpired are
#                 both caught.
# SIDE EFFECTS:   Spawns a child process. Read-only otherwise.
# CALLED BY:      scan_cpp().
# CALLS:          subprocess.run(["syft", ...]).
#
# EXAMPLE:
#   run_syft_conan("/repo")
#   -> [{"name": "fmt", "version": "10.1.1"}, ...]
#--------------------------------------------------------------------------
def run_syft_conan(root):
    """Shells out to `syft dir:<root> -o json --select-catalogers conan,sbom`
    for Conan dependency detection: syft's conan-cataloger correctly
    handles both conan.lock v1 and v2 formats plus conaninfo.txt, and its
    sbom-cataloger picks up any vendor-supplied SBOM checked into the repo
    (*.cdx.json, *.spdx.json, *.syft.json), none of which the regex/JSON
    fallback in scan_cpp() can match. Returns a list of {"name", "version"}
    artifact dicts, or None if syft isn't installed, times out, or exits
    non-zero, the caller falls back to the manifest-only parse in that
    case, same optional-tool contract as run_scc()."""
    try:
        proc = subprocess.run(
            ["syft", f"dir:{root}", "-o", "json", "--select-catalogers", "conan,sbom"],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return None
    return [a for a in (data.get("artifacts") or []) if a.get("name") and a.get("version")]


# ------------------------------------------------------------------------
# scan_cpp_structural_signals
#
# WHAT IT DOES:   Looks for CMake find_package()/FetchContent_Declare()
#                 calls and .gitmodules submodule entries, as a weak hint
#                 that a C/C++ dependency exists, even without a real
#                 package-manager manifest.
# WHY IT EXISTS:  Many C/C++ projects don't use Conan or vcpkg at all,
#                 they pull dependencies via CMake or git submodules
#                 instead. This gives at least a "something is here"
#                 signal for those projects, clearly separated from real
#                 manifest-based counts since it's much less reliable
#                 (see the RETURNS note on why it's low-confidence).
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[dict]) - one entry per detected signal, each with at least
#   "name", "source" (one of "find_package", "FetchContent_Declare",
#   "gitmodules"), and "file". FetchContent/gitmodules entries also
#   include "repository" and, for FetchContent, an optional "ref" (which
#   may be a branch name rather than a pinned release, so it isn't a
#   trustworthy version). Empty list if nothing found.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      scan_cpp().
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   scan_cpp_structural_signals("/repo")
#   -> [{"name": "OpenSSL", "source": "find_package",
#        "file": "/repo/CMakeLists.txt"}]
#--------------------------------------------------------------------------
def scan_cpp_structural_signals(root):
    """Best-effort CMakeLists.txt find_package()/FetchContent_Declare()
    calls and .gitmodules submodule entries: a structural hint that a
    C/C++ dependency exists, not a real manifest entry. Most of the time
    there's no pinned version to report, find_package() usually has none
    at all, and a FetchContent GIT_TAG can be a branch name rather than a
    release, so this is deliberately kept out of declared_dependencies/
    resolved_dependencies in scan_cpp(), a lower-confidence signal, not a
    substitute for a real manifest. Mirrors the "structural regex signal,
    not deep analysis" approach already used for Dockerfile FROM scraping
    and IaC content-sniffing elsewhere in this file."""
    signals = []
    for cmake_file in find_files(root, names={"CMakeLists.txt"}):
        text = read_text(cmake_file)
        for match in re.finditer(r"find_package\(\s*([A-Za-z0-9_.-]+)", text):
            signals.append({"name": match.group(1), "source": "find_package", "file": cmake_file})
        for match in re.finditer(
                r"FetchContent_Declare\(\s*([A-Za-z0-9_.-]+)[^)]*?GIT_REPOSITORY\s+(\S+)(?:[^)]*?GIT_TAG\s+(\S+))?",
                text, re.DOTALL):
            signals.append({"name": match.group(1), "source": "FetchContent_Declare", "file": cmake_file,
                             "repository": match.group(2), "ref": match.group(3)})
    for gitmodules_file in find_files(root, names={".gitmodules"}):
        text = read_text(gitmodules_file)
        for match in re.finditer(r'\[submodule\s+"([^"]+)"\][^\[]*?url\s*=\s*(\S+)', text, re.DOTALL):
            signals.append({"name": match.group(1), "source": "gitmodules", "file": gitmodules_file,
                             "repository": match.group(2)})
    return signals


# ------------------------------------------------------------------------
# scan_cpp
#
# WHAT IT DOES:   Finds Conan and vcpkg manifests/lockfiles, counts
#                 declared vs. resolved C/C++ dependencies (using `syft`
#                 for the Conan resolved count when available), and also
#                 reports the weaker CMake/gitmodules structural signals.
# WHY IT EXISTS:  C/C++ has no single dominant package manager the way
#                 npm or pip do; this function covers the two that do
#                 have a real manifest format (Conan, vcpkg) while being
#                 honest that CMake/gitmodules-based dependencies are a
#                 much weaker signal, reported separately rather than
#                 mixed into the same counts.
#
# INPUTS:
#   root (str) - repo root to scan.
#   package_managers (list) - accumulator appended to in place.
#   private_registries (list) - accepted for signature symmetry with the
#     other scan_* functions; unused here (no reliable committed-file
#     convention exists for a custom Conan remote, the same call already
#     made for Ivy and Dart).
#
# RETURNS:
#   (None) - results appended to package_managers. The appended entry has
#   an extra "unversioned_signals" key (from
#   scan_cpp_structural_signals()) that no other ecosystem's entry has.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   Mutates package_managers. May spawn a `syft` subprocess
#                 via run_syft_conan().
# CALLED BY:      scan_package_managers().
# CALLS:          find_files(), read_text(), toml_section_lines(),
#                 read_json(), run_syft_conan(),
#                 scan_cpp_structural_signals().
#
# EXAMPLE:
#   scan_cpp("/repo", package_managers, private_registries)
#--------------------------------------------------------------------------
def scan_cpp(root, package_managers, private_registries):
    """C/C++: Conan (via syft when available, since it handles conan.lock
    v1+v2, conaninfo.txt, and vendor SBOMs, else conanfile.txt/
    conanfile.py + conan.lock v2-shape parsing) and vcpkg (vcpkg.json,
    always hand-rolled, syft has no vcpkg cataloger). CMakeLists.txt/
    .gitmodules structural signals are reported separately, see
    scan_cpp_structural_signals(). No private-registry detection in this
    pass, no reliable committed-file convention for Conan remotes (same
    call already made for Ivy/Dart)."""
    conanfile_txts = find_files(root, names={"conanfile.txt"})
    conanfile_pys = find_files(root, names={"conanfile.py"})
    vcpkg_jsons = find_files(root, names={"vcpkg.json"})
    conan_locks = find_files(root, names={"conan.lock"})
    manifests = conanfile_txts + conanfile_pys + vcpkg_jsons
    lockfiles = conan_locks
    unversioned_signals = scan_cpp_structural_signals(root)
    if not manifests and not lockfiles and not unversioned_signals:
        return

    declared_count = None
    for conanfile_txt in conanfile_txts:
        text = read_text(conanfile_txt)
        count = 0
        for section in ("requires", "build_requires", "tool_requires"):
            for line in toml_section_lines(text, section):
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith("#"):
                    count += 1
        declared_count = (declared_count or 0) + count
    for conanfile_py in conanfile_pys:
        text = read_text(conanfile_py)
        count = len(re.findall(r"self\.(?:requires|build_requires|tool_requires)\(", text))
        declared_count = (declared_count or 0) + count
    for vcpkg_json_file in vcpkg_jsons:
        data = read_json(vcpkg_json_file)
        if isinstance(data, dict):
            deps = data.get("dependencies")
            if isinstance(deps, list):
                declared_count = (declared_count or 0) + len(deps)

    resolved_count = None
    # Only bother invoking syft if there's an actual Conan manifest/lock
    # to resolve, calling out to an external process for a vcpkg-only
    # (or manifest-less) project would just waste a subprocess call.
    syft_packages = run_syft_conan(root) if (conanfile_txts or conanfile_pys or conan_locks) else None
    if syft_packages is not None:
        resolved_count = len(syft_packages) or None
    else:
        for lockfile in conan_locks:
            data = read_json(lockfile)
            if isinstance(data, dict):
                count = 0
                for key in ("requires", "build_requires", "tool_requires", "python_requires"):
                    value = data.get(key)
                    if isinstance(value, list):
                        count += len(value)
                if count:
                    resolved_count = (resolved_count or 0) + count

    package_managers.append({
        "ecosystem": "cpp", "manifest_files": manifests, "lockfile_files": lockfiles,
        "declared_dependencies": declared_count, "resolved_dependencies": resolved_count,
        "unversioned_signals": unversioned_signals,
    })


# ------------------------------------------------------------------------
# scan_package_managers
#
# WHAT IT DOES:   Runs every ecosystem's scan_* function in turn and
#                 collects all of their results.
# WHY IT EXISTS:  Gives main() one call to make instead of ten, and keeps
#                 the list of supported ecosystems in one obvious place.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (tuple[list, list]) - (package_managers, private_registries), the
#   same two lists every scan_* function appended/extended in place while
#   running. Either list can be empty if nothing was found.
#
# RAISES/ERRORS:  None expected beyond whatever an individual scan_*
#                 function could raise (none of them currently do).
# SIDE EFFECTS:   Everything each scan_* function does (subprocess calls
#                 for scan_cpp's syft usage, filesystem reads throughout).
# CALLED BY:      main().
# CALLS:          scan_javascript(), scan_python(), scan_go(), scan_java(),
#                 scan_ruby(), scan_php(), scan_rust(), scan_dotnet(),
#                 scan_dart(), scan_cpp().
#
# EXAMPLE:
#   package_managers, private_registries = scan_package_managers("/repo")
#--------------------------------------------------------------------------
def scan_package_managers(root):
    """Runs every ecosystem's scan_* function and collects their results.
    Returns (package_managers, private_registries), the two lists every
    scan_* function appends/extends in place."""
    package_managers = []
    private_registries = []
    for scan_fn in (scan_javascript, scan_python, scan_go, scan_java, scan_ruby, scan_php, scan_rust, scan_dotnet,
                     scan_dart, scan_cpp):
        scan_fn(root, package_managers, private_registries)
    return package_managers, private_registries


# --- containers ----------------------------------------------------------

# ------------------------------------------------------------------------
# scan_containers
#
# WHAT IT DOES:   Finds every Dockerfile (including suffixed variants
#                 like Dockerfile.dev) along with their FROM base images,
#                 and every docker-compose*.yml/.yaml file.
# WHY IT EXISTS:  Knowing what base images a repo builds from, and
#                 whether it uses Compose, is part of the "what does this
#                 repo actually run on" inventory the calling skill needs.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (dict) - {"dockerfiles": [{"path", "base_images": [...]}], ...],
#   "compose_files": [...]}, both lists sorted, both possibly empty.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      main().
# CALLS:          find_files(), walk(), read_text().
#
# EXAMPLE:
#   scan_containers("/repo")
#   -> {"dockerfiles": [{"path": "/repo/Dockerfile",
#                         "base_images": ["python:3.12-slim"]}],
#       "compose_files": ["/repo/docker-compose.yml"]}
#--------------------------------------------------------------------------
def scan_containers(root):
    """Finds every Dockerfile (including suffixed variants like
    Dockerfile.dev) with its FROM base images, and every
    docker-compose*.yml/.yaml file."""
    dockerfile_paths = list(find_files(root, names={"Dockerfile"}))
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if filename.startswith("Dockerfile") and filename != "Dockerfile":
                dockerfile_paths.append(os.path.join(dirpath, filename))
    dockerfiles = []
    for path in sorted(set(dockerfile_paths)):
        text = read_text(path)
        # Matches a FROM line's image reference at the start of a line,
        # e.g. "FROM python:3.12-slim" or "FROM python:3.12 AS builder"
        # (the trailing "AS builder" alias is not captured, only the
        # image reference itself).
        base_images = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
        dockerfiles.append({"path": path, "base_images": base_images})
    compose_files = []
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if re.match(r"^docker-compose.*\.ya?ml$", filename):
                compose_files.append(os.path.join(dirpath, filename))
    return {"dockerfiles": dockerfiles, "compose_files": sorted(compose_files)}


# --- IaC -------------------------------------------------------------------

# ------------------------------------------------------------------------
# scan_iac
#
# WHAT IT DOES:   Finds Infrastructure-as-Code (IaC, configuration files
#                 that declare cloud or deployment resources instead of
#                 provisioning them by hand) files, split by tool:
#                 Terraform, CloudFormation, Kubernetes, Helm, Ansible,
#                 Pulumi, Serverless Framework, and AWS CDK.
# WHY IT EXISTS:  Several of these tools (CloudFormation, Kubernetes,
#                 Ansible) all use plain .yml/.yaml/.json files with no
#                 distinguishing filename, so telling them apart requires
#                 looking at file contents, not just names, this is the
#                 one place that does that classification.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (dict) - keys "terraform", "cloudformation", "kubernetes", "helm",
#   "ansible", "pulumi", "serverless", "cdk", each a sorted, de-duplicated
#   list of file paths (possibly empty).
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      main().
# CALLS:          find_files(), walk(), read_text().
#
# EXAMPLE:
#   scan_iac("/repo")
#   -> {"terraform": ["/repo/main.tf"], "cloudformation": [],
#       "kubernetes": ["/repo/k8s/deployment.yaml"], "helm": [],
#       "ansible": [], "pulumi": [], "serverless": [], "cdk": []}
#--------------------------------------------------------------------------
def scan_iac(root):
    """Finds Infrastructure-as-Code files by a mix of filename (Terraform,
    Helm, Pulumi, Serverless, CDK) and content sniffing (CloudFormation,
    Kubernetes, Ansible, which all use plain .yml/.yaml/.json)."""
    result = {"terraform": [], "cloudformation": [], "kubernetes": [], "helm": [],
              "ansible": [], "pulumi": [], "serverless": [], "cdk": []}
    result["terraform"] = sorted(find_files(root, suffixes=(".tf", ".tfvars")))
    result["helm"] = sorted(find_files(root, names={"Chart.yaml"}))
    result["pulumi"] = sorted(find_files(root, names={"Pulumi.yaml"}))
    result["serverless"] = sorted(find_files(root, names={"serverless.yml", "serverless.yaml"}))
    result["cdk"] = sorted(find_files(root, names={"cdk.json"}))

    # These three overlap in file extension (.yml/.yaml/.json), so content
    # sniffing decides which bucket a file lands in. Checked in this order
    # since a CloudFormation template could technically also contain the
    # substring "kind:" in a resource property, but not the reverse.
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if not filename.endswith((".yml", ".yaml", ".json")):
                continue
            path = os.path.join(dirpath, filename)
            text = read_text(path)
            if not text:
                continue
            if "AWSTemplateFormatVersion" in text or re.search(r"Type:\s*['\"]?AWS::", text):
                result["cloudformation"].append(path)
                continue
            if filename.endswith((".yml", ".yaml")) and "apiVersion:" in text and "kind:" in text:
                result["kubernetes"].append(path)
                continue
            if filename.endswith((".yml", ".yaml")) and "hosts:" in text and "tasks:" in text:
                result["ansible"].append(path)

    for key in result:
        result[key] = sorted(set(result[key]))
    return result


# ===== MAIN =====

# ------------------------------------------------------------------------
# main
#
# WHAT IT DOES:   CLI entry point. Runs every scan (languages, package
#                 managers, containers, IaC) and prints one combined JSON
#                 report to stdout.
# WHY IT EXISTS:  This is what actually gets invoked when the script is
#                 run from the command line or by the cartridge-scanner
#                 skill.
#
# INPUTS:
#   None directly (reads sys.argv): sys.argv[1], if present, is the repo
#   path to scan; defaults to "." (current directory) otherwise.
#
# RETURNS:
#   (None) - prints JSON to stdout as its output instead of returning a
#   value.
#
# RAISES/ERRORS:  An unhandled exception from any called function would
#                 propagate here and crash with a non-zero exit and a
#                 traceback, none of the scan functions are expected to
#                 raise under normal use.
# SIDE EFFECTS:   Prints to stdout. May spawn `scc` and/or `syft`
#                 subprocesses (via run_scc()/run_syft_conan()). Reads the
#                 filesystem under the target path. Writes nothing.
# CALLED BY:      The `if __name__ == "__main__":` guard at the bottom of
#                 this file.
# CALLS:          run_scc(), fallback_loc_scan(), scan_package_managers(),
#                 scan_containers(), scan_iac(), totals_of().
#
# EXAMPLE:
#   $ python3 cartridge_scan.py /home/user/my-repo
#   {"scc_available": true, "languages": [...], "totals": {...}, ...}
#--------------------------------------------------------------------------
def main():
    """CLI entry point: `cartridge_scan.py [path]` (defaults to `.`).
    Runs every scan and prints one JSON object to stdout."""
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    root = os.path.abspath(root)

    languages = run_scc(root)
    scc_available = languages is not None
    if languages is None:
        languages = fallback_loc_scan(root)

    package_managers, private_registries = scan_package_managers(root)
    containers = scan_containers(root)
    iac = scan_iac(root)

    output = {
        "scc_available": scc_available,
        "languages": languages,
        "totals": totals_of(languages),
        "package_managers": package_managers,
        "private_registries": private_registries,
        "containers": containers,
        "iac": iac,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
