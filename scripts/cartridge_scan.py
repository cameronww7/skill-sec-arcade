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

################################################################################
# FUNCTION: read_text
#
# PURPOSE
#     Reads a file's full contents as text without ever raising, so a
#     single unreadable or malformed file can't crash an entire scan of
#     an untrusted repository.
#
# RESPONSIBILITIES
#     - Open and read the file as UTF-8.
#     - Tolerate any read failure by returning an empty string instead of
#       raising.
#
# PROCESS OVERVIEW
#     1. Open the file at the given path in UTF-8 text mode.
#     2. Read and return its full contents.
#     3. If opening or reading fails for any filesystem reason, return an
#        empty string instead.
#
# IMPORTANT DETAILS
#     - Undecodable bytes are silently dropped (errors="ignore"), so a
#       binary file will not raise a UnicodeDecodeError; it will simply
#       produce mangled text.
#     - An empty string return is ambiguous: it means either the file was
#       genuinely empty, or the read failed. Callers cannot distinguish
#       the two from the return value alone.
#     - This function is called by nearly every other function in this
#       file and in dead_weight_scan.py, so centralizing this tolerance
#       here means no caller has to wrap every read in its own
#       try/except.
#
# PARAMETERS
#     path (str)
#         Filesystem path to read.
#
# RETURNS
#     str
#         The file's UTF-8 decoded contents, or "" if the file could not
#         be read.
#
# FAILURE CASES
#     - Missing file, permission denied, or any other OSError: returns ""
#       instead of raising.
################################################################################
def read_text(path):
    """Reads a file as UTF-8, tolerating decode errors. Returns "" on any
    failure (missing file, permission error, etc.) instead of raising."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


################################################################################
# FUNCTION: read_json
#
# PURPOSE
#     Gives every JSON-format manifest/lockfile reader in this file a
#     single "give me the parsed data or nothing" primitive that never
#     raises, since scanned repositories are not trusted to contain
#     well-formed files.
#
# RESPONSIBILITIES
#     - Read the file's contents via read_text().
#     - Parse those contents as JSON.
#     - Tolerate any parse failure by returning None instead of raising.
#
# PROCESS OVERVIEW
#     1. Read the file's contents as text via read_text().
#     2. Parse the text as JSON.
#     3. If parsing fails, return None instead.
#
# IMPORTANT DETAILS
#     - Callers must check for None before indexing into the result;
#       read_text() already returns "" on a read failure, and "" is not
#       valid JSON, so a missing or unreadable file and a malformed JSON
#       file both end up here as None.
#
# PARAMETERS
#     path (str)
#         Filesystem path to a JSON file.
#
# RETURNS
#     Any or None
#         The parsed JSON value (usually a dict or list) on success, or
#         None if the file is missing, unreadable, or not valid JSON.
#
# FAILURE CASES
#     - File missing, unreadable, or not valid JSON: returns None instead
#       of raising.
################################################################################
def read_json(path):
    """Reads and parses a file as JSON. Returns None if it's missing,
    unreadable, or not valid JSON, never raises."""
    try:
        return json.loads(read_text(path))
    except (ValueError, TypeError):
        return None


################################################################################
# FUNCTION: walk
#
# PURPOSE
#     Provides a drop-in replacement for os.walk() that never descends
#     into dependency/build/VCS directories, so every caller gets that
#     pruning for free instead of reimplementing it.
#
# RESPONSIBILITIES
#     - Walk the directory tree starting at root, same as os.walk().
#     - Remove every directory name listed in EXCLUDE_DIRS from each
#       yielded dirnames list before os.walk() descends further.
#
# PROCESS OVERVIEW
#     1. Start an os.walk() traversal from root.
#     2. For each (dirpath, dirnames, filenames) tuple os.walk() produces,
#        remove any name in EXCLUDE_DIRS from dirnames.
#     3. Yield the same tuple, now with dirnames pruned.
#
# IMPORTANT DETAILS
#     - Without this pruning, a scan would waste time descending into
#       node_modules, .git, vendor, and similar directories, and could
#       misreport third-party vendored code as first-party.
#     - dirnames must be mutated in place (dirnames[:] = ...), not
#       reassigned (dirnames = ...). os.walk() keeps its own reference to
#       the original list object and only skips descending into names
#       that are removed from that same object; reassigning the local
#       name would silently have no effect on traversal.
#
# PARAMETERS
#     root (str)
#         Directory to start walking from.
#
# RETURNS
#     generator
#         Yields (dirpath, dirnames, filenames) tuples, the same shape as
#         os.walk(), except dirnames has already had every name in
#         EXCLUDE_DIRS removed.
#
# FAILURE CASES
#     - None expected beyond whatever os.walk() itself can raise, which
#       is rare since it swallows most per-directory errors by default.
################################################################################
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


################################################################################
# FUNCTION: find_files
#
# PURPOSE
#     Gives every scan_* function in this file and in dead_weight_scan.py
#     one shared file-finding primitive, so EXCLUDE_DIRS pruning is
#     applied consistently everywhere instead of each function
#     hand-rolling its own os.walk() loop.
#
# RESPONSIBILITIES
#     - Normalize the names/suffixes filter arguments.
#     - Walk the tree under root via walk(), which already prunes
#       EXCLUDE_DIRS.
#     - Collect the full path of every file whose name is an exact match
#       in names, or whose name ends with one of suffixes.
#
# PROCESS OVERVIEW
#     1. Normalize names to a set (empty if None) and suffixes to a tuple
#        (empty if None).
#     2. Walk the tree under root via walk().
#     3. For each file encountered, check whether its filename is an
#        exact match in names, or ends with one of suffixes.
#     4. Collect the full path of every match into a list.
#     5. Return the collected list.
#
# IMPORTANT DETAILS
#     - A suffix match uses str.endswith(), so a suffix like
#       "requirements.txt" matches "requirements.txt" but also
#       "dev-requirements.txt", not only a true file extension.
#     - Results are returned in os.walk()'s natural (unsorted) order.
#
# PARAMETERS
#     root (str)
#         Directory to search under.
#     names (iterable[str] or None)
#         Exact filenames to match, e.g. {"package.json"}. Treated as an
#         empty set if None.
#     suffixes (iterable[str] or None)
#         Filename suffixes to match, e.g. (".csproj",) or
#         ("requirements.txt",). Treated as an empty tuple if None.
#
# RETURNS
#     list[str]
#         Full paths of every matching file. Empty list if nothing
#         matched.
#
# FAILURE CASES
#     - None expected beyond whatever walk() can raise.
################################################################################
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

# `scc` itself is fast, but a very large monorepo (millions of lines) can
# still take a while to scan. This caps the worst case instead of letting
# one slow `scc` invocation hang the entire cartridge scan forever.
SCC_TIMEOUT_SECONDS = 180

################################################################################
# FUNCTION: run_scc
#
# PURPOSE
#     Gets accurate lines-of-code and language statistics by shelling out
#     to the external `scc` command-line tool, instead of reimplementing
#     a per-language LOC/comment/complexity counter from scratch.
#
# RESPONSIBILITIES
#     - Run the `scc` binary against the given directory.
#     - Parse its JSON output.
#     - Normalize its PascalCase keys into this project's snake_case
#       schema.
#
# PROCESS OVERVIEW
#     1. Run `scc --format json <root>` as a subprocess, capturing its
#        output and bounding its run time.
#     2. If the binary is missing or the run times out, return None.
#     3. If the process exits non-zero, return None.
#     4. Parse its stdout as JSON.
#     5. If that JSON is invalid, return None.
#     6. Convert each entry's PascalCase fields (Name, Count, Lines,
#        Code, Comment, Blank, Complexity) into this project's
#        snake_case schema.
#     7. Return the list of normalized per-language entries.
#
# IMPORTANT DETAILS
#     - Spawns a child process (`scc`) and, through it, reads the
#       filesystem under root; it never writes anything.
#     - Callers must fall back to fallback_loc_scan() whenever this
#       function returns None, since that is the only signal that `scc`
#       wasn't usable.
#
# PARAMETERS
#     root (str)
#         Directory to scan.
#
# RETURNS
#     list[dict] or None
#         One dict per language with keys name, files, lines, code,
#         comment, blank, complexity. None if `scc` isn't installed,
#         times out, exits non-zero, or produces output that isn't valid
#         JSON.
#
# FAILURE CASES
#     - `scc` binary not found: returns None.
#     - `scc` run exceeds SCC_TIMEOUT_SECONDS: returns None.
#     - `scc` exits non-zero: returns None.
#     - `scc`'s stdout isn't valid JSON: returns None.
################################################################################
def run_scc(root):
    """Shells out to the `scc` CLI for language/LOC stats. Returns a list
    of per-language dicts, or None if `scc` isn't installed, times out, or
    exits non-zero, the caller falls back to fallback_loc_scan() in that
    case."""
    try:
        scc_process = subprocess.run(
            ["scc", "--format", "json", root],
            capture_output=True, text=True, timeout=SCC_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if scc_process.returncode != 0:
        return None

    try:
        raw_language_entries = json.loads(scc_process.stdout)
    except ValueError:
        return None

    normalized_language_entries = []
    for raw_entry in raw_language_entries:
        # scc's JSON keys are PascalCase; normalize to our snake_case schema.
        normalized_language_entries.append({
            "name": raw_entry.get("Name"),
            "files": raw_entry.get("Count", 0),
            "lines": raw_entry.get("Lines", 0),
            "code": raw_entry.get("Code", 0),
            "comment": raw_entry.get("Comment", 0),
            "blank": raw_entry.get("Blank", 0),
            "complexity": raw_entry.get("Complexity", 0),
        })
    return normalized_language_entries


################################################################################
# FUNCTION: fallback_loc_scan
#
# PURPOSE
#     Produces a non-empty, useful language breakdown even on a machine
#     without the external `scc` tool installed, by manually counting
#     files and lines per language.
#
# RESPONSIBILITIES
#     - Walk the tree under root.
#     - Recognize each file's language from its extension, via
#       FALLBACK_EXT_LANG.
#     - Count files and total lines per recognized language.
#
# PROCESS OVERVIEW
#     1. Walk the tree under root.
#     2. For each file, look up its language by extension in
#        FALLBACK_EXT_LANG; skip the file if its extension isn't
#        recognized.
#     3. Read the file's text.
#     4. Skip the file if it has non-empty size but produced no readable
#        text (unreadable or binary).
#     5. Increment that language's file count.
#     6. Count the file's lines and add them to that language's line
#        count.
#     7. Return one entry per language encountered.
#
# IMPORTANT DETAILS
#     - This is a deliberately rough count: it loses the
#       comment/blank/complexity split that `scc` provides, since a
#       correct version of that split needs a real per-language
#       tokenizer, which this function does not attempt to be.
#     - A file with content but no trailing newline still has one more
#       line than the number of "\n" characters in it; the line count
#       accounts for that final, unterminated line explicitly.
#
# PARAMETERS
#     root (str)
#         Directory to scan.
#
# RETURNS
#     list[dict]
#         One dict per language found (only languages in
#         FALLBACK_EXT_LANG are counted), with keys name, files, lines,
#         and code/comment/blank/complexity always 0. Empty list if no
#         recognized source files exist under root.
#
# FAILURE CASES
#     - None expected; per-file read failures are absorbed by
#       read_text() returning "".
################################################################################
def fallback_loc_scan(root):
    """Rough manual LOC count used only when `scc` isn't available: files
    and total line count per language in FALLBACK_EXT_LANG. No
    comment/blank/complexity split, that data needs a real tokenizer."""
    languages_by_name = {}
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            file_extension = os.path.splitext(filename)[1].lower()
            language = FALLBACK_EXT_LANG.get(file_extension)
            if not language:
                continue

            file_path = os.path.join(dirpath, filename)
            file_text = read_text(file_path)
            if not file_text and os.path.getsize(file_path) > 0:
                continue  # unreadable/binary

            language_entry = languages_by_name.setdefault(language, {
                "name": language, "files": 0, "lines": 0,
                "code": 0, "comment": 0, "blank": 0, "complexity": 0,
            })
            language_entry["files"] += 1

            line_count = file_text.count("\n")
            file_has_unterminated_final_line = file_text and not file_text.endswith("\n")
            if file_has_unterminated_final_line:
                line_count += 1
            language_entry["lines"] += line_count
    return list(languages_by_name.values())


################################################################################
# FUNCTION: totals_of
#
# PURPOSE
#     Provides the single place that sums per-language stats into one
#     repo-wide total, so the per-language breakdown and the total in the
#     final report can never drift apart from being computed twice.
#
# RESPONSIBILITIES
#     - Add up the files, lines, code, comment, and blank fields across
#       every language entry.
#
# PROCESS OVERVIEW
#     1. Start a totals dict with each field at zero.
#     2. For each language entry, add its value for each field into the
#        running totals.
#     3. Return the totals dict.
#
# IMPORTANT DETAILS
#     - Pure aggregation; does not read the "complexity" field, since
#       that is not summed anywhere in the final report.
#
# PARAMETERS
#     languages (list[dict])
#         Output of run_scc() or fallback_loc_scan().
#
# RETURNS
#     dict
#         {"files", "lines", "code", "comment", "blank"} summed across
#         all entries. All zero if languages is empty.
#
# FAILURE CASES
#     - None.
################################################################################
def totals_of(languages):
    """Sums the files/lines/code/comment/blank fields across every
    language entry (from run_scc() or fallback_loc_scan()) into one dict."""
    totals = {"files": 0, "lines": 0, "code": 0, "comment": 0, "blank": 0}
    for language in languages:
        for key in totals:
            totals[key] += language.get(key, 0)
    return totals


# --- generic helpers for manifest/lockfile parsing ---------------------

################################################################################
# FUNCTION: toml_section_lines
#
# PURPOSE
#     Gives every TOML-based ecosystem (Python's Poetry, Rust's Cargo,
#     C/C++'s Conan) a shared way to pull out one table's body, without
#     needing a full TOML parser just to hand that body to
#     count_key_value_lines().
#
# RESPONSIBILITIES
#     - Split the file's text into lines.
#     - Track which named table the current line belongs to.
#     - Collect every line that belongs to the requested table.
#
# PROCESS OVERVIEW
#     1. Split text into individual lines.
#     2. For each line, check whether it is a `[...]` table header.
#     3. If it is a header, note whether it matches the requested
#        header, and move to the next line without collecting the header
#        line itself.
#     4. If it is not a header and the current table is the requested
#        one, collect the line as-is.
#     5. Return the collected lines.
#
# IMPORTANT DETAILS
#     - This is a heuristic line scanner, not a real TOML parser: it does
#       not understand arrays of tables, inline tables, or multi-line
#       strings. It is deliberately narrow, built only to extract a
#       table's body for count_key_value_lines().
#     - Lines are returned unstripped (leading/trailing whitespace kept
#       as-is); trimming, if needed, is the caller's job.
#
# PARAMETERS
#     text (str)
#         Full file contents of a TOML file.
#     header (str)
#         The table name to extract, without brackets, e.g.
#         "tool.poetry.dependencies".
#
# RETURNS
#     list[str]
#         The raw (unstripped) lines inside that table. Empty list if the
#         table doesn't exist in text.
#
# FAILURE CASES
#     - None.
################################################################################
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


################################################################################
# FUNCTION: count_key_value_lines
#
# PURPOSE
#     Provides the one shared "how many dependencies are declared in this
#     table" counter used by every TOML-based ecosystem (Poetry, Cargo,
#     Conan), so the rule for what counts as a dependency line only has
#     to be written once.
#
# RESPONSIBILITIES
#     - Recognize which lines look like a `key = value` declaration.
#     - Skip blank lines and comment lines.
#     - Skip any key explicitly named in exclude_keys.
#     - Count everything else.
#
# PROCESS OVERVIEW
#     1. For each line, skip it if it is blank or starts with "#".
#     2. Check whether the line matches a bare or quoted key followed by
#        "=".
#     3. If it matches and the key isn't in exclude_keys, count it.
#     4. Return the total count.
#
# IMPORTANT DETAILS
#     - This is a heuristic line scanner, not a real TOML parser: it does
#       not match a continuation line of a multi-line value, or a line
#       that starts with the value instead of a key.
#     - exclude_keys exists because a table can hold one non-dependency
#       key alongside real dependencies, e.g. Poetry's Python version
#       constraint (`python = "^3.10"`) lives in the same table as its
#       real dependencies but isn't one.
#
# PARAMETERS
#     lines (list[str])
#         Lines to scan, as produced by toml_section_lines().
#     exclude_keys (iterable[str])
#         Key names to not count even though they match the pattern.
#
# RETURNS
#     int
#         Number of matching, non-excluded key/value lines.
#
# FAILURE CASES
#     - None.
################################################################################
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


################################################################################
# FUNCTION: host_of
#
# PURPOSE
#     Gives every private-registry check in this file a single place
#     that extracts a URL's hostname, so a bad or unparseable URL is
#     handled the same way everywhere instead of once per caller.
#
# RESPONSIBILITIES
#     - Parse the given string as a URL.
#     - Return just its hostname.
#
# PROCESS OVERVIEW
#     1. Parse url with urlparse().
#     2. Return its hostname attribute.
#     3. If parsing raises, return None instead.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     url (str)
#         A URL string, e.g. from a manifest's registry field.
#
# RETURNS
#     str or None
#         The hostname (e.g. "registry.npmjs.org"), or None if url isn't
#         parseable as a URL at all.
#
# FAILURE CASES
#     - url isn't parseable as a URL: returns None instead of raising.
################################################################################
def host_of(url):
    """Extracts the hostname from a URL string. Returns None for anything
    unparseable rather than raising."""
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


################################################################################
# FUNCTION: add_if_private
#
# PURPOSE
#     Gives every scan_* function the same single decision point for
#     "is this registry URL actually private," so that logic and the
#     shape of the recorded finding only exist in one place.
#
# RESPONSIBILITIES
#     - Extract the URL's host.
#     - Compare it against the ecosystem's known public default hosts.
#     - Record a finding in the caller's accumulator list only when the
#       host is not a known default.
#
# PROCESS OVERVIEW
#     1. Extract the host from url via host_of().
#     2. If the host couldn't be parsed, or matches one of
#        default_hosts, do nothing.
#     3. Otherwise, append a finding describing the ecosystem, host, url,
#        and source_file to private_registries.
#
# IMPORTANT DETAILS
#     - private_registries is mutated in place; this function has no
#       return value, since the accumulator itself is the output.
#     - default_hosts can be an empty set for an ecosystem with no
#       concept of a single public default host (see scan_go()), in
#       which case every parseable host is treated as private.
#
# PARAMETERS
#     private_registries (list)
#         The caller's accumulator list; appended to in place.
#     ecosystem (str)
#         Ecosystem key for the finding, e.g. "javascript".
#     url (str)
#         The registry/source URL found in a manifest.
#     source_file (str)
#         Path of the manifest the URL came from, for the report to
#         point back to.
#     default_hosts (set[str])
#         Hosts considered "public default" for this ecosystem, from
#         DEFAULT_REGISTRY_HOSTS (or an empty set when the caller has no
#         concept of a default).
#
# RETURNS
#     None
#         Mutates private_registries in place instead of returning.
#
# FAILURE CASES
#     - url's host can't be parsed: no finding is recorded.
#     - url's host matches a known default: no finding is recorded.
################################################################################
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

################################################################################
# FUNCTION: count_nested_lockfile_dependencies
#
# PURPOSE
#     Counts every package entry in an npm v1 lockfile's nested
#     "dependencies" tree, where a resolved package can have its own
#     nested "dependencies" sub-tree for transitive dependencies that
#     needed a different version than the top-level resolution.
#
# RESPONSIBILITIES
#     - Count every direct entry in the given dependencies map.
#     - Recurse into each entry's own nested "dependencies" sub-map, if
#       it has one, and add that count too.
#
# PROCESS OVERVIEW
#     1. Start a running count at zero.
#     2. For each entry in the dependencies map, add one to the count.
#     3. If that entry itself has a nested "dependencies" sub-map,
#        recursively count it and add that to the running count.
#     4. Return the running count.
#
# IMPORTANT DETAILS
#     - This mirrors the nested shape of an npm v1 package-lock.json:
#       each resolved package's entry can itself contain a
#       "dependencies" key holding transitive dependencies that were
#       resolved to a different version and therefore needed their own
#       nested copy.
#
# PARAMETERS
#     dependencies_map (dict)
#         A "dependencies" map from an npm v1 lockfile, or a nested
#         sub-map of the same shape.
#
# RETURNS
#     int
#         Total count of this map's entries plus every entry in every
#         nested sub-map.
#
# FAILURE CASES
#     - None expected; called only with dict values already confirmed by
#       the caller.
################################################################################
def count_nested_lockfile_dependencies(dependencies_map):
    nested_dependency_count = 0
    for dependency_entry in dependencies_map.values():
        nested_dependency_count += 1
        entry_has_nested_dependencies = (
            isinstance(dependency_entry, dict)
            and isinstance(dependency_entry.get("dependencies"), dict)
        )
        if entry_has_nested_dependencies:
            nested_dependency_count += count_nested_lockfile_dependencies(dependency_entry["dependencies"])
    return nested_dependency_count


################################################################################
# FUNCTION: scan_javascript
#
# PURPOSE
#     Inventories the JavaScript/npm ecosystem's dependencies: how many
#     are declared vs. actually resolved, and whether any non-default
#     registry is in use. npm, yarn, and pnpm each use a different
#     lockfile format with a different way of counting resolved
#     packages, so this function is where that format-specific logic
#     lives for the JavaScript ecosystem specifically.
#
# RESPONSIBILITIES
#     - Find package.json manifests and package-lock.json/yarn.lock/
#       pnpm-lock.yaml lockfiles.
#     - Count declared dependencies from the first package.json found.
#     - Count resolved dependencies from whichever lockfile format is
#       present.
#     - Flag any non-default registry found in package.json or .npmrc.
#     - Append one summary entry to package_managers if any npm-family
#       manifest or lockfile exists.
#
# PROCESS OVERVIEW
#     1. Find all package.json manifests and all npm-family lockfiles.
#     2. If neither exists, return without recording anything.
#     3. From the first package.json, sum the dependencies,
#        devDependencies, peerDependencies, and optionalDependencies
#        entries into a declared count, and check its publishConfig
#        registry for a private registry.
#     4. For each lockfile found, count resolved dependencies using the
#        counting rule for that specific lockfile format, stopping at
#        the first lockfile that produces a usable count.
#     5. Check every .npmrc file for a registry line pointing at a
#        private registry.
#     6. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - Only the first package.json's declared count is used. A monorepo
#       with several package.json files would otherwise have their
#       dependency counts summed together, mixing unrelated workspaces.
#     - package-lock.json v2/v3 format uses a flat "packages" map with
#       one entry per resolved package, plus one entry keyed "" for the
#       root project itself, which must be excluded from the count.
#     - package-lock.json v1 format uses a nested "dependencies" tree
#       instead, counted recursively via
#       count_nested_lockfile_dependencies().
#     - yarn.lock has no JSON/YAML structure of its own; each resolved
#       package is a block whose header line starts at column 0 and
#       ends with ":". A matching header line looks like
#       "left-pad@^1.0.0:"; an indented body line like '  version
#       "1.3.0"' does not match.
#     - pnpm-lock.yaml is real YAML, but this function does not parse it
#       as YAML; it matches a 2-space-indented package key ending in ":"
#       with nothing else on the line, e.g. "  /left-pad@1.3.0:", while
#       deeper-indented fields inside that package's block (e.g.
#       "    resolution:") do not match.
#     - If more than one npm-family lockfile is present (unusual, but
#       possible), only the first one with a usable count is treated as
#       authoritative for "what's actually installed."
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator this function appends one entry to, in place, if
#         any npm-family manifest/lockfile exists.
#     private_registries (list)
#         Accumulator passed through to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place; nothing is returned directly.
#
# FAILURE CASES
#     - No package.json and no npm-family lockfile found: returns without
#       recording anything.
#     - A manifest or lockfile that can't be parsed as expected simply
#       leaves the corresponding count as None; it does not raise.
################################################################################
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
        package_json_contents = read_json(manifest)
        if not isinstance(package_json_contents, dict):
            continue
        declared_count = sum(len(package_json_contents.get(key) or {}) for key in
                              ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"))
        publish_registry = (package_json_contents.get("publishConfig") or {}).get("registry")
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
        lockfile_text = read_text(lockfile)

        if filename == "package-lock.json":
            package_lock_json_contents = read_json(lockfile)
            has_v2_or_v3_packages_map = (
                isinstance(package_lock_json_contents, dict)
                and isinstance(package_lock_json_contents.get("packages"), dict)
            )
            has_v1_dependencies_tree = (
                isinstance(package_lock_json_contents, dict)
                and isinstance(package_lock_json_contents.get("dependencies"), dict)
            )
            if has_v2_or_v3_packages_map:
                # v2/v3 lockfile: flat "packages" map, one entry per resolved
                # package plus a "" entry for the root project itself.
                resolved_packages = package_lock_json_contents["packages"]
                root_project_entry_is_present = "" in resolved_packages
                resolved_count = len(resolved_packages)
                if root_project_entry_is_present:
                    resolved_count -= 1
            elif has_v1_dependencies_tree:
                # v1 lockfile: nested "dependencies" tree, walk it recursively.
                resolved_count = count_nested_lockfile_dependencies(
                    package_lock_json_contents["dependencies"])

        elif filename == "yarn.lock":
            # yarn.lock entries are blocks whose header line starts at
            # column 0 and ends with ":", one block per resolved package.
            # Matches e.g. `left-pad@^1.0.0:` at line start; does NOT
            # match indented body lines like `  version "1.3.0"`.
            resolved_package_count = 0
            for line in lockfile_text.splitlines():
                line_is_unindented = bool(line) and not line[0].isspace()
                line_looks_like_package_header = (
                    line_is_unindented
                    and line.rstrip().endswith(":")
                    and not line.startswith("#")
                )
                if line_looks_like_package_header:
                    resolved_package_count += 1
            resolved_count = resolved_package_count or None

        elif filename == "pnpm-lock.yaml":
            # Matches a 2-space-indented package key ending in ":" with
            # nothing else on the line, e.g. "  /left-pad@1.3.0:". Does
            # NOT match deeper-indented fields inside that package's
            # block (e.g. "    resolution:").
            resolved_count = len(re.findall(
                r"^\s{2}[^\s#][^:]*:\s*$", lockfile_text, re.MULTILINE)) or None

        if resolved_count is not None:
            # First lockfile with a usable count wins; a repo shouldn't
            # have more than one npm-family lockfile, but if it does,
            # only one is authoritative for "what's actually installed."
            break

    for npmrc_file in find_files(root, names={".npmrc"}):
        npmrc_text = read_text(npmrc_file)
        # Matches `registry=URL` or a scoped `@myorg:registry=URL` line.
        for match in re.finditer(r"^(?:@[\w-]+:)?registry\s*=\s*(\S+)", npmrc_text, re.MULTILINE):
            add_if_private(private_registries, "javascript", match.group(1), npmrc_file,
                            DEFAULT_REGISTRY_HOSTS["javascript"])

    package_managers.append({"ecosystem": "javascript", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


################################################################################
# FUNCTION: install_requires_from_setup_cfg
#
# PURPOSE
#     Reads the install_requires dependency list out of a setup.cfg
#     file's [options] section, one of several places a Python project
#     can declare its dependencies.
#
# RESPONSIBILITIES
#     - Parse the file as INI format.
#     - Read the install_requires value out of the [options] section.
#     - Split that value into individual requirement-spec strings.
#
# PROCESS OVERVIEW
#     1. Read the file's text and parse it as INI via configparser.
#     2. If parsing fails, return None.
#     3. If the [options] section has no install_requires field, return
#        None.
#     4. Split the install_requires value on commas and newlines into
#        individual lines.
#     5. Strip whitespace from each line and drop any empty lines.
#     6. Return the resulting list of requirement-spec strings.
#
# IMPORTANT DETAILS
#     - setup.cfg is genuine INI format, so configparser correctly joins
#       a multi-line install_requires value (the
#       "install_requires =\n    pkg1\n    pkg2" continuation form) into
#       one string without any custom continuation-line parsing.
#     - Each returned string keeps its version specifier attached (e.g.
#       "requests>=2.0"), the same shape as a requirements.txt line.
#
# PARAMETERS
#     path (str)
#         Path to a setup.cfg file.
#
# RETURNS
#     list[str] or None
#         One requirement-spec string per dependency, or None if the file
#         can't be parsed as INI or has no [options] install_requires
#         field.
#
# FAILURE CASES
#     - File isn't valid INI: returns None.
#     - File has no [options] install_requires field: returns None.
################################################################################
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
    raw_install_requires = parser.get("options", "install_requires")
    normalized_lines = raw_install_requires.replace(",", "\n").splitlines()
    requirement_specs = []
    for line in normalized_lines:
        stripped_line = line.strip()
        if stripped_line:
            requirement_specs.append(stripped_line)
    return requirement_specs


################################################################################
# FUNCTION: install_requires_from_setup_py
#
# PURPOSE
#     Reads the install_requires argument out of a setup.py file's
#     setup(...) call, without ever running the file.
#
# RESPONSIBILITIES
#     - Parse the file's source into an abstract syntax tree (AST),
#       never import or execute it.
#     - Find a call to a function named setup() in that tree.
#     - Extract the install_requires keyword argument's value, only if it
#       is a literal list or tuple of strings.
#
# PROCESS OVERVIEW
#     1. Parse the file's text into an AST via ast.parse().
#     2. If the file has a syntax error, return None.
#     3. Walk the AST looking for a call to a function named setup().
#     4. Within that call's keyword arguments, find install_requires.
#     5. Evaluate its value with ast.literal_eval(), which only succeeds
#        for literal values (strings, numbers, lists, dicts, etc.).
#     6. If that value is a list or tuple, keep only the string entries
#        and return them.
#     7. If no setup() call, no install_requires keyword, or a
#        non-literal value is found, return None.
#
# IMPORTANT DETAILS
#     - setup.py is an executable Python script, and this tool scans
#       untrusted repositories, so it must never be imported or exec'd;
#       doing so would let a malicious repo run arbitrary code during
#       what is supposed to be a read-only scan. Parsing it with the
#       ast module and evaluating only literal values keeps the scan
#       safe.
#     - ast.literal_eval() refuses anything that isn't a literal, so a
#       call like install_requires=read_reqs() safely fails to evaluate
#       here instead of being executed.
#     - This means setup.py files that compute their dependency list
#       dynamically (e.g. reading from a requirements.txt file at setup
#       time) are skipped rather than guessed at; that dependency list
#       genuinely cannot be resolved without running code.
#
# PARAMETERS
#     path (str)
#         Path to a setup.py file.
#
# RETURNS
#     list[str] or None
#         Requirement-spec strings if install_requires is a literal
#         list/tuple of strings; None otherwise.
#
# FAILURE CASES
#     - File has a syntax error: returns None.
#     - No setup() call found: returns None.
#     - No install_requires keyword argument: returns None.
#     - install_requires isn't a literal (e.g. a variable name or a
#       function call): returns None.
################################################################################
def install_requires_from_setup_py(path):
    """setup.py's setup(install_requires=...) argument, extracted via ast
    in parse-only mode. This tool never executes code from a scanned repo,
    a real concern for a security-tooling suite pointed at untrusted repos,
    so only a literal list/tuple of strings is resolved; a computed value
    (a variable, a call to a helper that reads requirements.txt, etc.)
    can't be resolved statically and is honestly skipped, not guessed."""
    try:
        syntax_tree = ast.parse(read_text(path))
    except SyntaxError:
        return None

    for node in ast.walk(syntax_tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "setup":
            continue

        for keyword in node.keywords:
            if keyword.arg != "install_requires":
                continue

            try:
                install_requires_value = ast.literal_eval(keyword.value)
            except (ValueError, SyntaxError):
                return None

            # A non-list/tuple literal (e.g. install_requires was a
            # string) is not treated as a hard failure here: the search
            # keeps going in case a later setup() call in the same file
            # has a usable value, matching the original parser's
            # behavior before this rewrite.
            if isinstance(install_requires_value, (list, tuple)):
                requirement_specs = []
                for entry in install_requires_value:
                    if isinstance(entry, str):
                        requirement_specs.append(entry)
                return requirement_specs

    return None


################################################################################
# FUNCTION: scan_python
#
# PURPOSE
#     Inventories the Python ecosystem's dependencies. Python has more
#     competing dependency-declaration formats than most ecosystems (pip,
#     Poetry, Pipenv, setuptools), so this function is where all of that
#     format-specific counting logic lives.
#
# RESPONSIBILITIES
#     - Find every Python manifest format (requirements*.txt,
#       pyproject.toml, Pipfile, setup.py, setup.cfg) and lockfile format
#       (Pipfile.lock, poetry.lock, uv.lock).
#     - Count declared dependencies across all manifest formats found.
#     - Count resolved dependencies across all lockfile formats found.
#     - Flag any non-default package index URL found in any of those
#       files, or in pip.conf/pip.ini.
#     - Append one summary entry to package_managers if any manifest or
#       lockfile exists.
#
# PROCESS OVERVIEW
#     1. Find all files for every Python manifest and lockfile format.
#     2. If none exist, return without recording anything.
#     3. Count declared dependencies from requirements*.txt files, while
#        also checking their --index-url/--extra-index-url option lines
#        for a private registry.
#     4. Count declared dependencies from pyproject.toml's PEP 621
#        dependencies array and Poetry's tool.poetry.dependencies table,
#        while checking Poetry's [[tool.poetry.source]] entries for a
#        private registry.
#     5. Count declared dependencies from Pipfile's packages and
#        dev-packages tables.
#     6. Count declared dependencies from setup.py and setup.cfg via
#        install_requires_from_setup_py()/install_requires_from_setup_cfg().
#     7. Count resolved dependencies from Pipfile.lock's default and
#        develop sections.
#     8. Count resolved dependencies from poetry.lock/uv.lock by counting
#        their [[package]] block headers.
#     9. Check any pip.conf/pip.ini file's index-url for a private
#        registry.
#     10. Append one summary entry describing all of the above to
#         package_managers.
#
# IMPORTANT DETAILS
#     - requirements*.txt option lines (starting with "-", e.g. "-r
#       base.txt" or "--index-url ...") are not package requirements and
#       are not counted; only --index-url and --extra-index-url are
#       inspected further, for a private registry.
#     - The PEP 621 dependencies array is matched with a DOTALL regex so
#       "." can match across the newlines inside a multi-line array.
#     - poetry.lock and uv.lock both list resolved packages as
#       [[package]] TOML array-of-tables entries; counting the header
#       lines is enough, there is no need to parse each block's fields.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accumulator passed to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place.
#
# FAILURE CASES
#     - No Python manifest or lockfile found: returns without recording
#       anything.
#     - A manifest or lockfile that can't be parsed as expected simply
#       leaves the corresponding count unaffected; it does not raise.
################################################################################
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
        declared_count_for_requirements_file = 0
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
            declared_count_for_requirements_file += 1
        declared_count = (declared_count or 0) + declared_count_for_requirements_file

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
        setup_py_requirement_specs = install_requires_from_setup_py(setup_py_file)
        if setup_py_requirement_specs:
            declared_count = (declared_count or 0) + len(setup_py_requirement_specs)

    for setup_cfg_file in setup_cfgs:
        setup_cfg_requirement_specs = install_requires_from_setup_cfg(setup_cfg_file)
        if setup_cfg_requirement_specs:
            declared_count = (declared_count or 0) + len(setup_cfg_requirement_specs)

    resolved_count = None
    for lockfile in pipfile_locks:
        pipfile_lock_contents = read_json(lockfile)
        if isinstance(pipfile_lock_contents, dict):
            default_package_count = len(pipfile_lock_contents.get("default") or {})
            develop_package_count = len(pipfile_lock_contents.get("develop") or {})
            resolved_count = (resolved_count or 0) + default_package_count + develop_package_count

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


################################################################################
# FUNCTION: scan_go
#
# PURPOSE
#     Inventories the Go ecosystem's dependencies. Go's module system has
#     its own require/replace/go.sum conventions that don't match any
#     other ecosystem here, so it gets its own dedicated parser.
#
# RESPONSIBILITIES
#     - Find go.mod manifests and go.sum lockfiles.
#     - Count declared modules from go.mod's require directives.
#     - Count resolved modules from unique module names in go.sum.
#     - Flag any `replace` directive that points at a private host.
#     - Append one summary entry to package_managers if either file
#       exists.
#
# PROCESS OVERVIEW
#     1. Find all go.mod and go.sum files.
#     2. If neither exists, return without recording anything.
#     3. For each go.mod, count require directives, both the
#        parenthesized require ( ... ) block form and the single-line
#        require form.
#     4. For each go.mod, check every `replace` directive's target for a
#        private host.
#     5. For each go.sum, count the unique module names listed.
#     6. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - A `replace old => new` directive can point `new` at either a
#       private module-proxy URL, or a bare host/path like
#       "git.mycorp.internal/team/pkg" with no scheme at all. When there
#       is no "://" in the target, "https://" is prepended before
#       extracting the host, so the bare-host form is still recognized.
#     - Each go.sum line is "module version hash"; a module usually
#       appears twice (once for the module hash, once for the go.mod
#       hash), so module names are deduplicated before counting.
#     - Go has no single well-known public default registry host the
#       way npm or PyPI do, so add_if_private() is called with an empty
#       default-hosts set: any parseable replace target is treated as
#       private.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accumulator passed to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place.
#
# FAILURE CASES
#     - No go.mod and no go.sum found: returns without recording
#       anything.
################################################################################
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
        declared_count_for_go_mod_file = 0
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
                    declared_count_for_go_mod_file += 1
                continue
            if stripped_line.startswith("require ") and "(" not in stripped_line:
                declared_count_for_go_mod_file += 1
        declared_count = (declared_count or 0) + declared_count_for_go_mod_file

        # A `replace old => new` directive can point `new` at either a
        # private module-proxy URL, or a bare host/path like
        # "git.mycorp.internal/team/pkg" with no scheme at all, hence the
        # fallback of prepending "https://" before extracting the host.
        for match in re.finditer(r"^replace\s+\S+\s*=>\s*(\S+)", text, re.MULTILINE):
            replace_target = match.group(1)
            replace_target_has_scheme = "://" in replace_target
            replace_target_looks_like_bare_host = bool(re.match(r"^[\w.-]+\.[a-z]{2,}/", replace_target))
            if replace_target_has_scheme or replace_target_looks_like_bare_host:
                if replace_target_has_scheme:
                    replace_target_url = replace_target
                else:
                    replace_target_url = f"https://{replace_target}"
                add_if_private(private_registries, "go", replace_target_url, go_mod_file, set())

    resolved_count = None
    for go_sum_file in lockfiles:
        text = read_text(go_sum_file)
        # Each line is "module version hash"; a module usually appears
        # twice (module hash + go.mod hash), dedupe to unique modules.
        unique_module_names = set()
        for line in text.splitlines():
            line_fields = line.split()
            if line_fields:
                unique_module_names.add(line_fields[0])
        if unique_module_names:
            resolved_count = (resolved_count or 0) + len(unique_module_names)

    package_managers.append({"ecosystem": "go", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


################################################################################
# FUNCTION: scan_java
#
# PURPOSE
#     Inventories the Java ecosystem's dependencies. Java has three
#     unrelated build-tool conventions in common use (Maven, Gradle,
#     Ivy), each with a different dependency-declaration syntax; this
#     function normalizes all three into one "java" ecosystem entry.
#
# RESPONSIBILITIES
#     - Find pom.xml, build.gradle, build.gradle.kts, and ivy.xml
#       manifests.
#     - Count declared dependencies using the syntax specific to whichever
#       build tool produced the manifest.
#     - Flag any custom Maven repository URL.
#     - Append one summary entry to package_managers if any manifest
#       exists.
#
# PROCESS OVERVIEW
#     1. Find all Maven, Gradle, and Ivy manifest files.
#     2. If none exist, return without recording anything.
#     3. For a pom.xml, count <dependency> tags and check its
#        <repositories> block for custom repository URLs.
#     4. For an ivy.xml, count self-closing <dependency .../> tags.
#     5. For a build.gradle or build.gradle.kts, count dependency
#        configuration calls and check for maven { url ... } blocks
#        pointing at a custom repository.
#     6. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - There is deliberately no resolved_dependencies count: none of
#       Maven, Gradle, or Ivy has a default lockfile to count resolved
#       packages from.
#     - Ivy's <dependency org="..." name="..." rev="..."/> is a
#       self-closing attribute tag, unlike Maven's nested-element
#       <dependency>...</dependency>, so it needs its own counting
#       pattern rather than reusing Maven's.
#     - Ivy resolvers are conventionally configured in a separate
#       ivysettings.xml file, not embedded in ivy.xml itself, so
#       private-registry detection is not attempted for Ivy manifests.
#     - Gradle dependency declarations are recognized by configuration
#       name (implementation, api, compileOnly, runtimeOnly,
#       testImplementation, testRuntimeOnly) followed by "(" or a quote,
#       e.g. implementation("com.foo:bar:1.0") or testImplementation
#       'com.foo:bar:1.0'.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accumulator passed to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place.
#
# FAILURE CASES
#     - No Maven, Gradle, or Ivy manifest found: returns without
#       recording anything.
################################################################################
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


################################################################################
# FUNCTION: scan_ruby
#
# PURPOSE
#     Inventories the Ruby/Bundler ecosystem's dependencies.
#     Gemfile.lock has its own indentation-based structure (not JSON, not
#     TOML), so this is the dedicated parser for that format.
#
# RESPONSIBILITIES
#     - Find Gemfile manifests and Gemfile.lock lockfiles.
#     - Count declared gems from `gem` lines in the Gemfile.
#     - Count resolved gems from the top-level entries in Gemfile.lock's
#       specs: block.
#     - Flag any non-default `source` line in the Gemfile.
#     - Append one summary entry to package_managers if either file
#       exists.
#
# PROCESS OVERVIEW
#     1. Find all Gemfile and Gemfile.lock files.
#     2. If neither exists, return without recording anything.
#     3. For each Gemfile, count `gem` declaration lines and check each
#        `source` line for a private registry.
#     4. For each Gemfile.lock, count the top-level gem entries in its
#        specs: block.
#     5. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - Inside the specs: block, top-level gems are indented 4 spaces;
#       their own transitive dependencies are indented 6 spaces. Only
#       the 4-space-indented lines are counted.
#     - The check for a 4-space-indented line must come before the check
#       for "left the specs: block" (a line with no leading whitespace);
#       swapping that order would break the "leaving the specs: block"
#       detection.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accumulator passed to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place.
#
# FAILURE CASES
#     - No Gemfile and no Gemfile.lock found: returns without recording
#       anything.
################################################################################
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
        top_level_gem_count = 0
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
                    top_level_gem_count += 1
                elif line and not line.startswith(" "):
                    in_specs_section = False
        if top_level_gem_count:
            resolved_count = (resolved_count or 0) + top_level_gem_count

    package_managers.append({"ecosystem": "ruby", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


################################################################################
# FUNCTION: scan_php
#
# PURPOSE
#     Inventories the PHP/Composer ecosystem's dependencies. Composer's
#     manifest and lockfile are both plain JSON, so this is the simplest
#     scan_* function: JSON key lookups are all that's needed.
#
# RESPONSIBILITIES
#     - Find composer.json manifests and composer.lock lockfiles.
#     - Count declared packages from composer.json's require and
#       require-dev sections.
#     - Count resolved packages from composer.lock's packages and
#       packages-dev arrays.
#     - Flag any custom repository URL declared in composer.json.
#     - Append one summary entry to package_managers if either file
#       exists.
#
# PROCESS OVERVIEW
#     1. Find all composer.json and composer.lock files.
#     2. If neither exists, return without recording anything.
#     3. For each composer.json, count require entries (excluding the
#        "php" pseudo-dependency) plus require-dev entries.
#     4. Check composer.json's repositories field, which can be either a
#        list or a dict depending on Composer version, for any custom
#        repository URL.
#     5. For each composer.lock, count its packages and packages-dev
#        array entries.
#     6. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - "php" itself can appear as a pseudo-dependency in the require
#       section (a required PHP version constraint), not a real
#       package, so it is excluded from the declared count.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accumulator passed to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place.
#
# FAILURE CASES
#     - No composer.json and no composer.lock found: returns without
#       recording anything.
################################################################################
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
        composer_json_contents = read_json(composer_json_file)
        if isinstance(composer_json_contents, dict):
            # "php" itself can appear as a pseudo-dependency (a required
            # PHP version), not a real package, so it's excluded here.
            required_packages = {}
            for package_name, package_constraint in (composer_json_contents.get("require") or {}).items():
                if package_name != "php":
                    required_packages[package_name] = package_constraint
            required_dev_packages = composer_json_contents.get("require-dev") or {}
            declared_count = (declared_count or 0) + len(required_packages) + len(required_dev_packages)

            repositories = composer_json_contents.get("repositories")
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
        composer_lock_contents = read_json(lockfile)
        if isinstance(composer_lock_contents, dict):
            resolved_package_count = len(composer_lock_contents.get("packages") or [])
            resolved_dev_package_count = len(composer_lock_contents.get("packages-dev") or [])
            resolved_count = (resolved_count or 0) + resolved_package_count + resolved_dev_package_count

    package_managers.append({"ecosystem": "php", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


################################################################################
# FUNCTION: scan_rust
#
# PURPOSE
#     Inventories the Rust/Cargo ecosystem's dependencies. Cargo's
#     manifest and lockfile share the same TOML-table shape as Poetry's,
#     so this reuses toml_section_lines() and count_key_value_lines()
#     rather than reinventing that parsing.
#
# RESPONSIBILITIES
#     - Find Cargo.toml manifests and Cargo.lock lockfiles.
#     - Count declared crates from Cargo.toml's dependencies,
#       dev-dependencies, and build-dependencies tables.
#     - Count resolved crates from Cargo.lock's [[package]] block
#       headers.
#     - Flag any custom registry configured in a repo-local
#       .cargo/config.toml.
#     - Append one summary entry to package_managers if either file
#       exists.
#
# PROCESS OVERVIEW
#     1. Find all Cargo.toml and Cargo.lock files.
#     2. If neither exists, return without recording anything.
#     3. For each Cargo.toml, count key/value lines in its dependencies,
#        dev-dependencies, and build-dependencies tables.
#     4. For each config.toml file found, skip it unless it lives inside
#        a ".cargo" directory, then check its registry line for a
#        private registry.
#     5. For each Cargo.lock, count its [[package]] block headers.
#     6. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - "config.toml" is a generic filename used by other tools too;
#       only the one that actually lives inside a ".cargo" directory is
#       Cargo's own config, so anything else with that name is skipped.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accumulator passed to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place.
#
# FAILURE CASES
#     - No Cargo.toml and no Cargo.lock found: returns without recording
#       anything.
################################################################################
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


################################################################################
# FUNCTION: scan_dotnet
#
# PURPOSE
#     Inventories the .NET ecosystem's dependencies. .NET has two
#     competing package managers, the built-in NuGet CLI and the
#     third-party Paket tool, that both resolve from the same NuGet
#     registry; this function handles both under one "dotnet" ecosystem
#     entry.
#
# RESPONSIBILITIES
#     - Find .csproj and paket.dependencies manifests, and
#       packages.lock.json and paket.lock lockfiles.
#     - Count declared packages from <PackageReference> tags and
#       `nuget` lines.
#     - Count resolved packages from packages.lock.json and/or
#       paket.lock.
#     - Flag any custom source in paket.dependencies or nuget.config.
#     - Append one summary entry to package_managers if any manifest or
#       lockfile exists.
#
# PROCESS OVERVIEW
#     1. Find all .csproj, paket.dependencies, packages.lock.json, and
#        paket.lock files.
#     2. If no manifest and no lockfile exist, return without recording
#        anything.
#     3. For each .csproj, count <PackageReference> tags.
#     4. For each paket.dependencies, count `nuget` lines and check each
#        `source` line for a private registry.
#     5. For each packages.lock.json, sum package counts across every
#        target framework section.
#     6. For each paket.lock, count the top-level package entries in its
#        NUGET block.
#     7. For each nuget.config/NuGet.Config, check its <add key value>
#        entries whose value looks like a URL for a private registry.
#     8. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - packages.lock.json is keyed by target framework (e.g. "net8.0"),
#       each with its own package map; counts are summed across all
#       frameworks, since the same package can be pinned per-framework.
#     - paket.lock's NUGET block uses the same indentation convention as
#       Gemfile.lock's specs: block: 4-space-indented lines are
#       top-level packages, 6-space-indented lines are their transitive
#       dependencies. A 4-space-indented "remote:" line is metadata, not
#       a package, and is excluded from the count.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accumulator passed to add_if_private().
#
# RETURNS
#     None
#         Results are appended to package_managers/private_registries in
#         place.
#
# FAILURE CASES
#     - No .csproj, paket.dependencies, packages.lock.json, or
#       paket.lock found: returns without recording anything.
################################################################################
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
        packages_lock_json_contents = read_json(lockfile)
        has_dependencies_by_framework = (
            isinstance(packages_lock_json_contents, dict)
            and isinstance(packages_lock_json_contents.get("dependencies"), dict)
        )
        if has_dependencies_by_framework:
            # packages.lock.json is keyed by target framework (e.g.
            # "net8.0"), each with its own package map; sum across all of
            # them since the same package can be pinned per-framework.
            resolved_count_across_frameworks = 0
            for framework_package_map in packages_lock_json_contents["dependencies"].values():
                if isinstance(framework_package_map, dict):
                    resolved_count_across_frameworks += len(framework_package_map)
            if resolved_count_across_frameworks:
                resolved_count = (resolved_count or 0) + resolved_count_across_frameworks

    for paket_lock_file in paket_lock_files:
        text = read_text(paket_lock_file)
        # paket.lock's NUGET block uses the same indentation convention as
        # Gemfile.lock's specs: block, 4-space-indented lines are top-level
        # packages, 6-space-indented lines are their transitive deps.
        top_level_package_count = 0
        in_nuget_section = False
        for line in text.splitlines():
            if line.strip() == "NUGET":
                in_nuget_section = True
                continue
            if in_nuget_section:
                if line.startswith("    ") and not line.startswith("      ") and not line.strip().startswith("remote:"):
                    top_level_package_count += 1
                elif line and not line.startswith(" "):
                    in_nuget_section = False
        if top_level_package_count:
            resolved_count = (resolved_count or 0) + top_level_package_count

    for nuget_config_file in find_files(root, names={"nuget.config", "NuGet.Config"}):
        text = read_text(nuget_config_file)
        for match in re.finditer(r'<add\s+key="[^"]*"\s+value="([^"]+)"', text):
            if match.group(1).startswith("http"):
                add_if_private(private_registries, "nuget", match.group(1), nuget_config_file,
                                DEFAULT_REGISTRY_HOSTS["nuget"])

    package_managers.append({"ecosystem": "dotnet", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


################################################################################
# FUNCTION: scan_dart
#
# PURPOSE
#     Inventories the Dart/Flutter (pub.dev) ecosystem's dependencies,
#     parsed out of YAML by indentation since this project is
#     stdlib-only and has no YAML parser available.
#
# RESPONSIBILITIES
#     - Find pubspec.yaml manifests and pubspec.lock lockfiles.
#     - Count declared packages from pubspec.yaml's dependencies and
#       dev_dependencies blocks.
#     - Count resolved packages from pubspec.lock's top-level package
#       entries.
#     - Append one summary entry to package_managers if either file
#       exists.
#
# PROCESS OVERVIEW
#     1. Find all pubspec.yaml and pubspec.lock files.
#     2. If neither exists, return without recording anything.
#     3. For each pubspec.yaml, track whether the current line is inside
#        a dependencies or dev_dependencies block, and count each
#        2-space-indented package name line within it.
#     4. For each pubspec.lock, count its 2-space-indented top-level
#        package entries.
#     5. Append one summary entry describing all of the above to
#        package_managers.
#
# IMPORTANT DETAILS
#     - pub.dev has no private-registry configuration convention to
#       check, so this function takes a private_registries parameter
#       only for signature symmetry with the other scan_* functions; it
#       is unused, which the leading underscore in its name signals.
#     - A line with no leading whitespace means the next top-level YAML
#       key has been reached, i.e. the dependencies/dev_dependencies
#       block has ended.
#     - A 2-space-indented "name:" line is a direct dependency entry;
#       anything indented further is a nested field of that entry (e.g.
#       a git/path source), not a new package.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     _private_registries (list)
#         Unused; present only for signature symmetry with the other
#         scan_* functions.
#
# RETURNS
#     None
#         Results are appended to package_managers in place.
#
# FAILURE CASES
#     - No pubspec.yaml and no pubspec.lock found: returns without
#       recording anything.
################################################################################
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
        declared_count_for_pubspec_file = 0
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
                    declared_count_for_pubspec_file += 1
        declared_count = (declared_count or 0) + declared_count_for_pubspec_file

    resolved_count = None
    for lockfile in lockfiles:
        text = read_text(lockfile)
        block_count = len(re.findall(r"^  \S[^:]*:\s*$", text, re.MULTILINE))
        if block_count:
            resolved_count = (resolved_count or 0) + block_count

    package_managers.append({"ecosystem": "dart", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


# `syft` is used only for Conan detection, a narrower job than `scc`'s
# full-repo LOC scan, so it gets a shorter timeout than SCC_TIMEOUT_SECONDS.
SYFT_TIMEOUT_SECONDS = 120

################################################################################
# FUNCTION: run_syft_conan
#
# PURPOSE
#     Detects Conan (a C/C++ package manager) dependencies by shelling
#     out to the external `syft` tool's dedicated Conan and SBOM
#     (Software Bill of Materials, a formal inventory of a project's
#     components) catalogers, since Conan's lockfile format changed
#     between v1 and v2 and `syft` already handles both correctly.
#
# RESPONSIBILITIES
#     - Run the `syft` binary against the given directory, selecting
#       only its Conan and SBOM catalogers.
#     - Parse its JSON output.
#     - Keep only the artifacts that have both a name and a version.
#
# PROCESS OVERVIEW
#     1. Run `syft dir:<root> -o json --select-catalogers conan,sbom` as
#        a subprocess, capturing its output and bounding its run time.
#     2. If the binary is missing or the run times out, return None.
#     3. If the process exits non-zero, return None.
#     4. Parse its stdout as JSON.
#     5. If that JSON is invalid, return None.
#     6. Keep only the artifacts that have both a "name" and a
#        "version" field.
#     7. Return the kept artifacts.
#
# IMPORTANT DETAILS
#     - `syft`'s conan-cataloger correctly handles both conan.lock v1
#       and v2 formats plus conaninfo.txt, and its sbom-cataloger picks
#       up any vendor-supplied SBOM checked into the repo (*.cdx.json,
#       *.spdx.json, *.syft.json). None of that is something the
#       hand-rolled regex/JSON fallback in scan_cpp() can match; using
#       `syft` when available gets a much more complete answer for
#       comparatively little code here.
#     - Spawns a child process (`syft`); read-only otherwise.
#     - Callers must fall back to scan_cpp()'s manifest-only parse
#       whenever this function returns None, the same optional-tool
#       contract as run_scc().
#
# PARAMETERS
#     root (str)
#         Directory to scan.
#
# RETURNS
#     list[dict] or None
#         {"name", "version"} entries for every detected artifact, or
#         None if `syft` isn't installed, times out, exits non-zero, or
#         its output isn't valid JSON.
#
# FAILURE CASES
#     - `syft` binary not found: returns None.
#     - `syft` run exceeds SYFT_TIMEOUT_SECONDS: returns None.
#     - `syft` exits non-zero: returns None.
#     - `syft`'s stdout isn't valid JSON: returns None.
################################################################################
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
        syft_process = subprocess.run(
            ["syft", f"dir:{root}", "-o", "json", "--select-catalogers", "conan,sbom"],
            capture_output=True, text=True, timeout=SYFT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if syft_process.returncode != 0:
        return None

    try:
        syft_output = json.loads(syft_process.stdout)
    except ValueError:
        return None

    detected_artifacts = []
    for artifact in (syft_output.get("artifacts") or []):
        if artifact.get("name") and artifact.get("version"):
            detected_artifacts.append(artifact)
    return detected_artifacts


################################################################################
# FUNCTION: scan_cpp_structural_signals
#
# PURPOSE
#     Gives at least a "something is here" signal for C/C++ projects
#     that don't use Conan or vcpkg at all, but instead pull
#     dependencies via CMake calls or git submodules.
#
# RESPONSIBILITIES
#     - Find CMake find_package() and FetchContent_Declare() calls in
#       every CMakeLists.txt.
#     - Find submodule entries in every .gitmodules file.
#     - Report both as a list of signals, clearly separate from real
#       manifest-based dependency counts.
#
# PROCESS OVERVIEW
#     1. Find all CMakeLists.txt files.
#     2. For each one, collect every find_package() call's argument as
#        a signal.
#     3. For each one, collect every FetchContent_Declare() call's name,
#        GIT_REPOSITORY, and optional GIT_TAG as a signal.
#     4. Find all .gitmodules files.
#     5. For each one, collect every [submodule "name"] entry's name
#        and url as a signal.
#     6. Return all collected signals.
#
# IMPORTANT DETAILS
#     - This is a much lower-confidence signal than a real
#       manifest-based dependency count, and is deliberately kept out
#       of declared_dependencies/resolved_dependencies in scan_cpp():
#       find_package() usually has no version at all, and a
#       FetchContent GIT_TAG can be a branch name rather than a pinned
#       release, so neither is a trustworthy version.
#     - This mirrors the "structural regex signal, not deep analysis"
#       approach already used for Dockerfile FROM scraping and IaC
#       content-sniffing elsewhere in this file.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         One entry per detected signal, each with at least "name",
#         "source" (one of "find_package", "FetchContent_Declare",
#         "gitmodules"), and "file". FetchContent/gitmodules entries
#         also include "repository" and, for FetchContent, an optional
#         "ref". Empty list if nothing found.
#
# FAILURE CASES
#     - None expected.
################################################################################
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


################################################################################
# FUNCTION: scan_cpp
#
# PURPOSE
#     Inventories the C/C++ ecosystem's dependencies. C/C++ has no
#     single dominant package manager the way npm or pip do; this
#     function covers the two that do have a real manifest format
#     (Conan, vcpkg), while being honest that CMake/gitmodules-based
#     dependencies are a much weaker signal, reported separately rather
#     than mixed into the same counts.
#
# RESPONSIBILITIES
#     - Find Conan (conanfile.txt, conanfile.py, conan.lock) and vcpkg
#       (vcpkg.json) manifests/lockfiles.
#     - Count declared dependencies from Conan and vcpkg manifests.
#     - Count resolved Conan dependencies, preferring `syft` when it's
#       usable and falling back to a hand-rolled conan.lock parse
#       otherwise.
#     - Also collect the weaker CMake/gitmodules structural signals via
#       scan_cpp_structural_signals().
#     - Append one summary entry to package_managers if any manifest,
#       lockfile, or structural signal exists.
#
# PROCESS OVERVIEW
#     1. Find all conanfile.txt, conanfile.py, vcpkg.json, and
#        conan.lock files, and collect CMake/gitmodules structural
#        signals.
#     2. If nothing was found in any of those, return without recording
#        anything.
#     3. For each conanfile.txt, count non-comment lines in its
#        requires, build_requires, and tool_requires sections.
#     4. For each conanfile.py, count self.requires()/
#        self.build_requires()/self.tool_requires() calls.
#     5. For each vcpkg.json, count its dependencies array entries.
#     6. If any Conan manifest or lockfile exists, try `syft` for the
#        resolved Conan dependency count.
#     7. If `syft` wasn't usable, fall back to counting entries across
#        conan.lock's requires/build_requires/tool_requires/
#        python_requires arrays.
#     8. Append one summary entry describing all of the above, plus the
#        structural signals, to package_managers.
#
# IMPORTANT DETAILS
#     - `syft` is only invoked when there's an actual Conan
#        manifest/lock to resolve; calling out to an external process
#        for a vcpkg-only (or manifest-less) project would just waste a
#        subprocess call.
#     - No private-registry detection is attempted in this function:
#       there's no reliable committed-file convention for a custom
#       Conan remote, the same call already made for Ivy and Dart.
#     - The appended entry has an extra "unversioned_signals" key (from
#       scan_cpp_structural_signals()) that no other ecosystem's entry
#       has.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     package_managers (list)
#         Accumulator appended to in place.
#     private_registries (list)
#         Accepted for signature symmetry with the other scan_*
#         functions; unused here.
#
# RETURNS
#     None
#         Results are appended to package_managers in place.
#
# FAILURE CASES
#     - No Conan/vcpkg manifest, no conan.lock, and no structural signal
#       found: returns without recording anything.
################################################################################
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
        declared_count_for_conanfile_txt = 0
        for section in ("requires", "build_requires", "tool_requires"):
            for line in toml_section_lines(text, section):
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith("#"):
                    declared_count_for_conanfile_txt += 1
        declared_count = (declared_count or 0) + declared_count_for_conanfile_txt
    for conanfile_py in conanfile_pys:
        text = read_text(conanfile_py)
        declared_count_for_conanfile_py = len(
            re.findall(r"self\.(?:requires|build_requires|tool_requires)\(", text))
        declared_count = (declared_count or 0) + declared_count_for_conanfile_py
    for vcpkg_json_file in vcpkg_jsons:
        vcpkg_json_contents = read_json(vcpkg_json_file)
        if isinstance(vcpkg_json_contents, dict):
            vcpkg_dependencies = vcpkg_json_contents.get("dependencies")
            if isinstance(vcpkg_dependencies, list):
                declared_count = (declared_count or 0) + len(vcpkg_dependencies)

    resolved_count = None
    # Only bother invoking syft if there's an actual Conan manifest/lock
    # to resolve, calling out to an external process for a vcpkg-only
    # (or manifest-less) project would just waste a subprocess call.
    any_conan_manifest_or_lock_exists = bool(conanfile_txts or conanfile_pys or conan_locks)
    if any_conan_manifest_or_lock_exists:
        syft_packages = run_syft_conan(root)
    else:
        syft_packages = None

    if syft_packages is not None:
        resolved_count = len(syft_packages) or None
    else:
        for lockfile in conan_locks:
            conan_lock_contents = read_json(lockfile)
            if isinstance(conan_lock_contents, dict):
                resolved_count_for_conan_lock = 0
                for key in ("requires", "build_requires", "tool_requires", "python_requires"):
                    requires_list = conan_lock_contents.get(key)
                    if isinstance(requires_list, list):
                        resolved_count_for_conan_lock += len(requires_list)
                if resolved_count_for_conan_lock:
                    resolved_count = (resolved_count or 0) + resolved_count_for_conan_lock

    package_managers.append({
        "ecosystem": "cpp", "manifest_files": manifests, "lockfile_files": lockfiles,
        "declared_dependencies": declared_count, "resolved_dependencies": resolved_count,
        "unversioned_signals": unversioned_signals,
    })


################################################################################
# FUNCTION: scan_package_managers
#
# PURPOSE
#     Gives main() one call to make instead of ten, and keeps the list
#     of supported ecosystems in one obvious place.
#
# RESPONSIBILITIES
#     - Run every ecosystem's scan_* function against the same root,
#       package_managers list, and private_registries list.
#     - Return the two accumulator lists once every ecosystem has run.
#
# PROCESS OVERVIEW
#     1. Start empty package_managers and private_registries lists.
#     2. Run each ecosystem's scan_* function in turn, passing it root
#        and both accumulator lists.
#     3. Return the two accumulator lists.
#
# IMPORTANT DETAILS
#     - Every scan_* function mutates package_managers and
#       private_registries in place; this function does not build the
#       result itself, it only sequences the calls and returns the
#       lists they filled in.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     tuple[list, list]
#         (package_managers, private_registries), the same two lists
#         every scan_* function appended/extended in place while
#         running. Either list can be empty if nothing was found.
#
# FAILURE CASES
#     - None expected beyond whatever an individual scan_* function
#       could raise (none of them currently do).
################################################################################
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

################################################################################
# FUNCTION: scan_containers
#
# PURPOSE
#     Inventories a repo's container tooling: every Dockerfile with its
#     FROM base images, and every docker-compose file. Knowing what base
#     images a repo builds from, and whether it uses Compose, is part of
#     the "what does this repo actually run on" inventory the calling
#     skill needs.
#
# RESPONSIBILITIES
#     - Find every Dockerfile, including suffixed variants like
#       Dockerfile.dev.
#     - Extract each Dockerfile's FROM base image references.
#     - Find every docker-compose*.yml/.yaml file.
#
# PROCESS OVERVIEW
#     1. Find every file named exactly "Dockerfile".
#     2. Also find every file whose name starts with "Dockerfile" but
#        isn't exactly "Dockerfile" (suffixed variants).
#     3. For each Dockerfile found, extract its FROM line image
#        references.
#     4. Find every file matching the docker-compose*.yml/.yaml naming
#        pattern.
#     5. Return both collections.
#
# IMPORTANT DETAILS
#     - A FROM line's image reference is matched at the start of a
#       line, e.g. "FROM python:3.12-slim" or "FROM python:3.12 AS
#       builder"; the trailing "AS builder" alias is not captured, only
#       the image reference itself.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     dict
#         {"dockerfiles": [{"path", "base_images": [...]}, ...],
#         "compose_files": [...]}, both lists sorted, both possibly
#         empty.
#
# FAILURE CASES
#     - None expected.
################################################################################
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
    for dockerfile_path in sorted(set(dockerfile_paths)):
        text = read_text(dockerfile_path)
        # Matches a FROM line's image reference at the start of a line,
        # e.g. "FROM python:3.12-slim" or "FROM python:3.12 AS builder"
        # (the trailing "AS builder" alias is not captured, only the
        # image reference itself).
        base_images = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
        dockerfiles.append({"path": dockerfile_path, "base_images": base_images})

    compose_files = []
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if re.match(r"^docker-compose.*\.ya?ml$", filename):
                compose_files.append(os.path.join(dirpath, filename))

    return {"dockerfiles": dockerfiles, "compose_files": sorted(compose_files)}


# --- IaC -------------------------------------------------------------------

################################################################################
# FUNCTION: scan_iac
#
# PURPOSE
#     Finds Infrastructure-as-Code (IaC, configuration files that
#     declare cloud or deployment resources instead of provisioning
#     them by hand) files, split by tool: Terraform, CloudFormation,
#     Kubernetes, Helm, Ansible, Pulumi, Serverless Framework, and AWS
#     CDK.
#
# RESPONSIBILITIES
#     - Find IaC files that are identifiable by filename alone
#       (Terraform, Helm, Pulumi, Serverless, CDK).
#     - Find IaC files that share a plain .yml/.yaml/.json extension
#       with other tools (CloudFormation, Kubernetes, Ansible) by
#       sniffing file contents for a telltale key.
#     - Return one sorted, de-duplicated list of file paths per tool.
#
# PROCESS OVERVIEW
#     1. Find Terraform, Helm, Pulumi, Serverless, and CDK files by
#        filename/suffix.
#     2. Walk every other .yml/.yaml/.json file and read its contents.
#     3. If it contains an AWSTemplateFormatVersion key or a
#        Type: "AWS::..." resource declaration, classify it as
#        CloudFormation.
#     4. Otherwise, if it is a .yml/.yaml file containing both
#        "apiVersion:" and "kind:", classify it as Kubernetes.
#     5. Otherwise, if it is a .yml/.yaml file containing both
#        "hosts:" and "tasks:", classify it as Ansible.
#     6. Sort and de-duplicate every tool's file list.
#     7. Return the dict of per-tool file lists.
#
# IMPORTANT DETAILS
#     - CloudFormation, Kubernetes, and Ansible files all use plain
#       .yml/.yaml/.json extensions with no distinguishing filename, so
#       telling them apart requires looking at file contents, not just
#       names.
#     - The three content-sniffing checks are ordered CloudFormation,
#       then Kubernetes, then Ansible, since a CloudFormation template
#       could technically also contain the substring "kind:" in a
#       resource property, but not the reverse; checking CloudFormation
#       first avoids that ambiguity.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     dict
#         Keys "terraform", "cloudformation", "kubernetes", "helm",
#         "ansible", "pulumi", "serverless", "cdk", each a sorted,
#         de-duplicated list of file paths (possibly empty).
#
# FAILURE CASES
#     - None expected.
################################################################################
def scan_iac(root):
    """Finds Infrastructure-as-Code files by a mix of filename (Terraform,
    Helm, Pulumi, Serverless, CDK) and content sniffing (CloudFormation,
    Kubernetes, Ansible, which all use plain .yml/.yaml/.json)."""
    iac_findings_by_tool = {"terraform": [], "cloudformation": [], "kubernetes": [], "helm": [],
                             "ansible": [], "pulumi": [], "serverless": [], "cdk": []}
    iac_findings_by_tool["terraform"] = sorted(find_files(root, suffixes=(".tf", ".tfvars")))
    iac_findings_by_tool["helm"] = sorted(find_files(root, names={"Chart.yaml"}))
    iac_findings_by_tool["pulumi"] = sorted(find_files(root, names={"Pulumi.yaml"}))
    iac_findings_by_tool["serverless"] = sorted(find_files(root, names={"serverless.yml", "serverless.yaml"}))
    iac_findings_by_tool["cdk"] = sorted(find_files(root, names={"cdk.json"}))

    # These three overlap in file extension (.yml/.yaml/.json), so content
    # sniffing decides which bucket a file lands in. Checked in this order
    # since a CloudFormation template could technically also contain the
    # substring "kind:" in a resource property, but not the reverse.
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if not filename.endswith((".yml", ".yaml", ".json")):
                continue
            candidate_path = os.path.join(dirpath, filename)
            text = read_text(candidate_path)
            if not text:
                continue
            if "AWSTemplateFormatVersion" in text or re.search(r"Type:\s*['\"]?AWS::", text):
                iac_findings_by_tool["cloudformation"].append(candidate_path)
                continue
            if filename.endswith((".yml", ".yaml")) and "apiVersion:" in text and "kind:" in text:
                iac_findings_by_tool["kubernetes"].append(candidate_path)
                continue
            if filename.endswith((".yml", ".yaml")) and "hosts:" in text and "tasks:" in text:
                iac_findings_by_tool["ansible"].append(candidate_path)

    for tool_name in iac_findings_by_tool:
        iac_findings_by_tool[tool_name] = sorted(set(iac_findings_by_tool[tool_name]))
    return iac_findings_by_tool


# ===== MAIN =====

################################################################################
# FUNCTION: main
#
# PURPOSE
#     Serves as the CLI entry point: runs every scan (languages,
#     package managers, containers, IaC) and prints one combined JSON
#     report to stdout. This is what actually gets invoked when the
#     script is run from the command line or by the cartridge-scanner
#     skill.
#
# RESPONSIBILITIES
#     - Determine which repo path to scan from the command line.
#     - Run the language/LOC scan, preferring `scc` and falling back to
#       fallback_loc_scan().
#     - Run the package manager, container, and IaC scans.
#     - Assemble every scan's results into one JSON object and print it
#       to stdout.
#
# PROCESS OVERVIEW
#     1. Read the repo path from sys.argv[1], defaulting to "." if not
#        given, and resolve it to an absolute path.
#     2. Run run_scc(); if it returns None, run fallback_loc_scan()
#        instead.
#     3. Run scan_package_managers(), scan_containers(), and
#        scan_iac().
#     4. Assemble all results, plus totals_of()'s summary, into one
#        dict.
#     5. Print that dict as indented JSON to stdout.
#
# IMPORTANT DETAILS
#     - "scc_available" in the output records whether run_scc()
#       succeeded, so the calling skill can tell a real per-language
#       LOC/comment/complexity breakdown from the coarser
#       fallback_loc_scan() result.
#
# PARAMETERS
#     None
#         Reads sys.argv directly: sys.argv[1], if present, is the repo
#         path to scan; defaults to "." otherwise.
#
# RETURNS
#     None
#         Prints JSON to stdout as its output instead of returning a
#         value.
#
# FAILURE CASES
#     - An unhandled exception from any called function would
#       propagate here and crash with a non-zero exit and a traceback;
#       none of the scan functions are expected to raise under normal
#       use.
################################################################################
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
